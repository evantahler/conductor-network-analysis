#!/usr/bin/env python3
"""Comprehensive pcap network trace analyzer with color-coded terminal output."""

import sys
import struct
import socket
import dpkt
from collections import defaultdict, Counter
from datetime import datetime, timezone


# ── ANSI Colors ──────────────────────────────────────────────────────────────

BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"


def bold(s):
    return f"{BOLD}{s}{RESET}"


def red(s):
    return f"{RED}{s}{RESET}"


def green(s):
    return f"{GREEN}{s}{RESET}"


def yellow(s):
    return f"{YELLOW}{s}{RESET}"


def cyan(s):
    return f"{CYAN}{s}{RESET}"


def dim(s):
    return f"{DIM}{s}{RESET}"


# ── Helpers ──────────────────────────────────────────────────────────────────

def fmt_bytes(n):
    """Human-readable byte count."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def ip_str(packed):
    """Convert packed IP bytes to string."""
    if len(packed) == 4:
        return socket.inet_ntop(socket.AF_INET, packed)
    elif len(packed) == 16:
        return socket.inet_ntop(socket.AF_INET6, packed)
    return packed.hex()


def identify_ip(ip):
    """Identify an IP by known ranges, rDNS, or ASN hints."""
    if not hasattr(identify_ip, "_cache"):
        identify_ip._cache = {}
    if ip in identify_ip._cache:
        return identify_ip._cache[ip]

    # Little Snitch synthetic local addresses
    if ip.startswith("0.1.") or ip.startswith("::0.1."):
        identify_ip._cache[ip] = "Local"
        return "Local"

    # Known IP range mappings (prefix → org)
    # Cross-referenced with Little Snitch UI for this capture
    known = [
        # Conductor app (conductor.build)
        ("2607:6bc0:", "conductor.build"),
        ("160.79.104.", "conductor.build"),

        # Conductor backend on Fly.io (conductor-cloud-prototype.fly.dev)
        ("2a09:8280:", "Fly.io (conductor-cloud-prototype)"),

        # GitHub (git ops via gh, ssh, and HTTPS)
        ("140.82.112.", "GitHub"),
        ("140.82.113.", "GitHub"),
        ("140.82.114.", "GitHub"),
        ("140.82.116.", "GitHub"),
        ("140.82.118.", "GitHub"),
        ("140.82.121.", "GitHub"),
        ("20.200.", "GitHub"),
        ("2606:50c0:", "GitHub"),

        # Cloudflare-fronted services (arcade.dev, posthog, incident.io, chorus.sh, etc.)
        ("2606:4700:", "Cloudflare CDN"),
        ("172.66.", "Cloudflare CDN"),
        ("104.16.", "Cloudflare CDN"),
        ("104.17.", "Cloudflare CDN"),
        ("104.18.", "Cloudflare CDN"),

        # Anthropic API (hosted on GCP)
        ("2600:1901:", "GCP (likely api.anthropic.com)"),
        ("34.149.", "GCP (likely api.anthropic.com)"),

        # Datadog / PostHog (AWS-hosted)
        ("2600:1f18:", "AWS (likely datadoghq.com)"),
        ("2600:1f1c:", "AWS"),

        # Vercel
        ("76.76.21.", "Vercel"),
        ("76.223.", "Vercel"),

        # Other
        ("2a00:1450:", "Google"),
        ("142.250.", "Google"),
        ("2620:1ec:", "Akamai"),
        ("66.33.60.", "crabnebula.app"),
    ]

    for prefix, org in known:
        if ip.startswith(prefix):
            identify_ip._cache[ip] = org
            return org

    # Try rDNS
    try:
        host = socket.gethostbyaddr(ip)[0]
        identify_ip._cache[ip] = host
        return host
    except (socket.herror, socket.gaierror, OSError):
        pass

    identify_ip._cache[ip] = None
    return None


def ascii_table(headers, rows, col_align=None):
    """Render a simple ASCII table."""
    if not rows:
        return "  (no data)\n"
    widths = [len(h) for h in headers]
    str_rows = []
    for row in rows:
        sr = [str(c) for c in row]
        str_rows.append(sr)
        for i, c in enumerate(sr):
            # strip ANSI for width calc
            plain = c
            for code in (BOLD, RED, GREEN, YELLOW, CYAN, DIM, RESET):
                plain = plain.replace(code, "")
            widths[i] = max(widths[i], len(plain))

    if col_align is None:
        col_align = ["l"] * len(headers)

    def fmt_cell(val, width, align):
        plain = val
        for code in (BOLD, RED, GREEN, YELLOW, CYAN, DIM, RESET):
            plain = plain.replace(code, "")
        pad = width - len(plain)
        if align == "r":
            return " " * pad + val
        return val + " " * pad

    sep = "  "
    hdr = sep.join(fmt_cell(bold(h), widths[i], col_align[i]) for i, h in enumerate(headers))
    divider = sep.join("─" * w for w in widths)
    lines = ["  " + hdr, "  " + divider]
    for sr in str_rows:
        line = sep.join(fmt_cell(sr[i], widths[i], col_align[i]) for i in range(len(headers)))
        lines.append("  " + line)
    return "\n".join(lines) + "\n"


def section(title):
    width = 72
    print()
    print(f"{CYAN}{'━' * width}{RESET}")
    print(f"{CYAN}┃{RESET} {bold(title)}")
    print(f"{CYAN}{'━' * width}{RESET}")


# ── Parsing ──────────────────────────────────────────────────────────────────

def parse_pcap(path):
    """Parse pcap file and return structured data."""
    packets = []
    dns_queries = []
    dns_responses = defaultdict(set)  # query_name -> set of IPs
    ip_to_hostnames = defaultdict(set)  # IP -> set of hostnames
    flows = defaultdict(lambda: {"bytes": 0, "packets": 0, "proto": "", "flags": set()})
    proto_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
    ip_src_bytes = Counter()
    ip_dst_bytes = Counter()

    with open(path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            # Try pcapng
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        for ts, buf in pcap:
            pkt_len = len(buf)
            packets.append((ts, pkt_len))

            # Parse ethernet frame, but fix Little Snitch's mislabeled ethertypes.
            # Little Snitch writes all packets with ethertype 0x0800 (IPv4) even
            # when the payload is IPv6. Check the actual version nibble to dispatch.
            if len(buf) < 15:
                proto_stats["Other"]["packets"] += 1
                proto_stats["Other"]["bytes"] += pkt_len
                continue

            try:
                ip_version = (buf[14] >> 4)
                if ip_version == 4:
                    ip = dpkt.ip.IP(buf[14:])
                elif ip_version == 6:
                    ip = dpkt.ip6.IP6(buf[14:])
                else:
                    proto_stats["Other"]["packets"] += 1
                    proto_stats["Other"]["bytes"] += pkt_len
                    continue
            except (dpkt.UnpackError, struct.error):
                proto_stats["Other"]["packets"] += 1
                proto_stats["Other"]["bytes"] += pkt_len
                continue
            src = ip_str(ip.src)
            dst = ip_str(ip.dst)
            ip_src_bytes[src] += pkt_len
            ip_dst_bytes[dst] += pkt_len

            # Protocol
            if isinstance(ip, dpkt.ip.IP):
                proto_num = ip.p
            else:
                proto_num = ip.nxt

            if proto_num == dpkt.ip.IP_PROTO_TCP:
                proto_name = "TCP"
                tcp = ip.data
                if isinstance(tcp, dpkt.tcp.TCP):
                    sport, dport = tcp.sport, tcp.dport
                    flow_key = (src, sport, dst, dport, "TCP")
                    flows[flow_key]["bytes"] += pkt_len
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["proto"] = "TCP"
                    # Track TCP flags
                    if tcp.flags & dpkt.tcp.TH_SYN:
                        flows[flow_key]["flags"].add("SYN")
                    if tcp.flags & dpkt.tcp.TH_FIN:
                        flows[flow_key]["flags"].add("FIN")
                    if tcp.flags & dpkt.tcp.TH_RST:
                        flows[flow_key]["flags"].add("RST")

                    # Check for DNS over TCP or HTTP
                    if dport == 53 or sport == 53:
                        _try_parse_dns(tcp.data, dns_queries, dns_responses, ip_to_hostnames, ts)
                else:
                    sport = dport = 0
                    flow_key = (src, 0, dst, 0, "TCP")
                    flows[flow_key]["bytes"] += pkt_len
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["proto"] = "TCP"

            elif proto_num == dpkt.ip.IP_PROTO_UDP:
                proto_name = "UDP"
                udp = ip.data
                if isinstance(udp, dpkt.udp.UDP):
                    sport, dport = udp.sport, udp.dport
                    flow_key = (src, sport, dst, dport, "UDP")
                    flows[flow_key]["bytes"] += pkt_len
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["proto"] = "UDP"

                    # DNS
                    if dport == 53 or sport == 53:
                        _try_parse_dns(udp.data, dns_queries, dns_responses, ip_to_hostnames, ts)
                else:
                    flow_key = (src, 0, dst, 0, "UDP")
                    flows[flow_key]["bytes"] += pkt_len
                    flows[flow_key]["packets"] += 1
                    flows[flow_key]["proto"] = "UDP"

            elif proto_num == dpkt.ip.IP_PROTO_ICMP or proto_num == dpkt.ip.IP_PROTO_ICMP6:
                proto_name = "ICMP"
                flow_key = (src, 0, dst, 0, "ICMP")
                flows[flow_key]["bytes"] += pkt_len
                flows[flow_key]["packets"] += 1
                flows[flow_key]["proto"] = "ICMP"
            else:
                proto_name = f"Proto-{proto_num}"

            proto_stats[proto_name]["packets"] += 1
            proto_stats[proto_name]["bytes"] += pkt_len

    return {
        "packets": packets,
        "proto_stats": proto_stats,
        "ip_src_bytes": ip_src_bytes,
        "ip_dst_bytes": ip_dst_bytes,
        "dns_queries": dns_queries,
        "dns_responses": dns_responses,
        "ip_to_hostnames": ip_to_hostnames,
        "flows": flows,
    }


def _try_parse_dns(data, dns_queries, dns_responses, ip_to_hostnames, ts):
    """Attempt to parse DNS from payload bytes."""
    if not data or len(data) < 12:
        return
    try:
        dns = dpkt.dns.DNS(data)
    except (dpkt.UnpackError, struct.error, IndexError):
        return

    # Queries
    for q in dns.qd:
        qname = q.name
        dns_queries.append((ts, qname, q.type))

    # Answers
    for rr in dns.an:
        name = rr.name
        if rr.type == dpkt.dns.DNS_A:
            try:
                ip_addr = socket.inet_ntoa(rr.rdata)
                dns_responses[name].add(ip_addr)
                ip_to_hostnames[ip_addr].add(name)
            except (struct.error, OSError):
                pass
        elif rr.type == dpkt.dns.DNS_AAAA:
            try:
                ip_addr = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                dns_responses[name].add(ip_addr)
                ip_to_hostnames[ip_addr].add(name)
            except (struct.error, OSError):
                pass
        elif rr.type == dpkt.dns.DNS_CNAME:
            try:
                dns_responses[name].add(f"CNAME → {rr.cname}")
            except AttributeError:
                pass


# ── Report Sections ──────────────────────────────────────────────────────────

def print_capture_summary(data):
    section("1. Capture Summary")
    pkts = data["packets"]
    if not pkts:
        print("  No packets found.")
        return
    ts_start = pkts[0][0]
    ts_end = pkts[-1][0]
    total_bytes = sum(p[1] for p in pkts)
    duration = ts_end - ts_start

    dt_start = datetime.fromtimestamp(ts_start, tz=timezone.utc)
    dt_end = datetime.fromtimestamp(ts_end, tz=timezone.utc)

    print(f"  {bold('Start:')}    {green(dt_start.strftime('%Y-%m-%d %H:%M:%S UTC'))}")
    print(f"  {bold('End:')}      {green(dt_end.strftime('%Y-%m-%d %H:%M:%S UTC'))}")
    print(f"  {bold('Duration:')} {green(f'{duration:.1f}s')} ({duration/60:.1f} min)")
    print(f"  {bold('Packets:')}  {green(f'{len(pkts):,}')}")
    print(f"  {bold('Bytes:')}    {green(fmt_bytes(total_bytes))}")
    if duration > 0:
        print(f"  {bold('Rate:')}     {green(f'{len(pkts)/duration:.1f} pkt/s')}, {green(f'{fmt_bytes(total_bytes/duration)}/s')}")


def print_protocol_breakdown(data):
    section("2. Protocol Breakdown")
    stats = data["proto_stats"]
    total_pkts = sum(v["packets"] for v in stats.values())
    total_bytes = sum(v["bytes"] for v in stats.values())

    rows = []
    for proto in sorted(stats, key=lambda p: stats[p]["bytes"], reverse=True):
        s = stats[proto]
        pkt_pct = s["packets"] / total_pkts * 100 if total_pkts else 0
        byte_pct = s["bytes"] / total_bytes * 100 if total_bytes else 0
        rows.append([
            bold(proto),
            f"{s['packets']:,}",
            f"{pkt_pct:.1f}%",
            fmt_bytes(s["bytes"]),
            f"{byte_pct:.1f}%",
        ])

    print(ascii_table(
        ["Protocol", "Packets", "Pkt %", "Bytes", "Byte %"],
        rows,
        col_align=["l", "r", "r", "r", "r"],
    ))


def print_top_talkers(data):
    section("3. Top Talkers (Remote Hosts)")

    # Merge src + dst, but skip local/synthetic IPs
    all_ips = Counter()
    for ip, b in data["ip_src_bytes"].items():
        if not _is_local(ip):
            all_ips[ip] += b
    for ip, b in data["ip_dst_bytes"].items():
        if not _is_local(ip):
            all_ips[ip] += b

    hostnames = data["ip_to_hostnames"]

    print(f"  {bold('By total bytes (src + dst):')}\n")
    rows = []
    for ip, total in all_ips.most_common(15):
        sent = data["ip_src_bytes"].get(ip, 0)
        recv = data["ip_dst_bytes"].get(ip, 0)
        names = hostnames.get(ip, set())
        display_name = ", ".join(sorted(names)[:2]) if names else (identify_ip(ip) or dim("—"))
        rows.append([ip, fmt_bytes(sent), fmt_bytes(recv), fmt_bytes(total), display_name])

    print(ascii_table(
        ["IP Address", "Sent", "Received", "Total", "Hostname"],
        rows,
        col_align=["l", "r", "r", "r", "l"],
    ))


def print_service_breakdown(data):
    section("4. Service Breakdown")
    flows = data["flows"]

    # Aggregate bytes by identified service
    service_bytes = Counter()
    service_conns = Counter()
    for (src, sport, dst, dport, proto), info in flows.items():
        # Identify remote endpoint
        remote = dst if _is_local(src) or (not _is_local(dst)) else src
        svc = identify_ip(remote) or "Unknown"
        if svc == "Local":
            continue
        service_bytes[svc] += info["bytes"]
        service_conns[svc] += 1

    total = sum(service_bytes.values())
    rows = []
    for svc, b in service_bytes.most_common(15):
        pct = b / total * 100 if total else 0
        rows.append([bold(svc), f"{service_conns[svc]:,}", fmt_bytes(b), f"{pct:.1f}%"])

    print(ascii_table(
        ["Service", "Flows", "Bytes", "%"],
        rows,
        col_align=["l", "r", "r", "r"],
    ))


def print_dns_analysis(data):
    section("5. DNS Analysis")
    queries = data["dns_queries"]
    responses = data["dns_responses"]

    print(f"  {bold('Total DNS queries:')} {green(str(len(queries)))}")
    print(f"  {bold('Unique names queried:')} {green(str(len(set(q[1] for q in queries))))}")
    print(f"  {bold('Names with responses:')} {green(str(len(responses)))}")

    # Deduplicated query names by frequency
    qname_counts = Counter(q[1] for q in queries)
    print(f"\n  {bold('Top queried names:')}\n")
    rows = []
    for name, count in qname_counts.most_common(25):
        ips = responses.get(name, set())
        ip_str_val = ", ".join(sorted(ips)[:3]) if ips else dim("no response")
        rows.append([name, str(count), ip_str_val])

    print(ascii_table(
        ["Domain", "Queries", "Resolved IPs"],
        rows,
        col_align=["l", "r", "l"],
    ))


def print_connection_map(data):
    section("6. Connection Map (Top 30 Flows)")
    flows = data["flows"]
    hostnames = data["ip_to_hostnames"]

    sorted_flows = sorted(flows.items(), key=lambda x: x[1]["bytes"], reverse=True)[:30]

    rows = []
    for (src, sport, dst, dport, proto), info in sorted_flows:
        dst_names = hostnames.get(dst, set())
        src_names = hostnames.get(src, set())
        host = (", ".join(sorted(dst_names)[:1]) or ", ".join(sorted(src_names)[:1])
                or identify_ip(dst) or identify_ip(src) or "")

        flags = ",".join(sorted(info["flags"])) if info["flags"] else ""

        src_str = f"{src}:{sport}" if sport else src
        dst_str = f"{dst}:{dport}" if dport else dst

        rows.append([
            f"{src_str}",
            "→",
            f"{dst_str}",
            proto,
            f"{info['packets']:,}",
            fmt_bytes(info["bytes"]),
            flags,
            dim(host) if host else "",
        ])

    print(ascii_table(
        ["Source", "", "Destination", "Proto", "Pkts", "Bytes", "Flags", "Hostname"],
        rows,
        col_align=["l", "l", "l", "l", "r", "r", "l", "l"],
    ))


def _is_local(ip):
    """Check if IP is a local/synthetic Little Snitch address."""
    return ip.startswith(("0.1.", "::0.1.", "10.", "172.16.", "192.168.", "127.",
                          "::1", "fe80:", "224.", "239.", "255.", "ff"))


def print_security_flags(data):
    section("7. Security Flags")
    flows = data["flows"]
    hostnames = data["ip_to_hostnames"]
    findings = []

    well_known_ports = {80, 443, 53, 22, 993, 995, 587, 465, 123, 5353, 5228, 5229, 5230}

    for (src, sport, dst, dport, proto), info in flows.items():
        # Plaintext HTTP to remote servers
        if dport == 80 and proto == "TCP" and info["bytes"] > 0 and not _is_local(dst):
            host = identify_ip(dst) or dst
            findings.append((red("PLAINTEXT HTTP"), f"→ {host}:{dport}", fmt_bytes(info["bytes"])))

        # Non-standard destination ports (only flag actual server ports, not ephemeral client ports)
        if (proto == "TCP" and dport not in well_known_ports and dport > 0
                and dport < 1024 and info["bytes"] > 5000 and not _is_local(dst)):
            host = identify_ip(dst) or dst
            findings.append((yellow("NON-STD PORT"), f"→ {host}:{dport}", fmt_bytes(info["bytes"])))

        # RST flags (connection resets)
        if "RST" in info.get("flags", set()) and info["packets"] > 5:
            remote = dst if not _is_local(dst) else src
            host = identify_ip(remote) or remote
            findings.append((yellow("CONN RESETS"), f"↔ {host} ({info['packets']} pkts)", ""))

    if not findings:
        print(f"  {green('No significant security flags detected.')}")
        return

    # Deduplicate and limit
    seen = set()
    unique = []
    for f in findings:
        key = (f[0], f[1])
        plain_key = key[1]
        if plain_key not in seen:
            seen.add(plain_key)
            unique.append(f)

    print(ascii_table(
        ["Flag", "Detail", "Volume"],
        unique[:40],
        col_align=["l", "l", "r"],
    ))


def print_timeline(data):
    section("8. Traffic Timeline")
    pkts = data["packets"]
    if not pkts:
        return

    ts_start = pkts[0][0]
    ts_end = pkts[-1][0]
    duration = ts_end - ts_start

    if duration == 0:
        print("  Capture too short for timeline.")
        return

    # Choose bucket size: aim for ~40 buckets
    bucket_secs = max(1, int(duration / 40))
    buckets = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for ts, pkt_len in pkts:
        bucket = int((ts - ts_start) / bucket_secs)
        buckets[bucket]["packets"] += 1
        buckets[bucket]["bytes"] += pkt_len

    max_bytes = max(b["bytes"] for b in buckets.values()) if buckets else 1
    bar_width = 50

    print(f"  {bold(f'Bucket size: {bucket_secs}s')}\n")
    print(f"  {'Time':>8}  {'Packets':>8}  {'Bytes':>10}  Bar")
    print(f"  {'─' * 8}  {'─' * 8}  {'─' * 10}  {'─' * bar_width}")

    max_bucket = max(buckets.keys()) if buckets else 0
    for i in range(max_bucket + 1):
        b = buckets.get(i, {"packets": 0, "bytes": 0})
        offset = i * bucket_secs
        bar_len = int(b["bytes"] / max_bytes * bar_width) if max_bytes else 0
        bar = green("█" * bar_len) + dim("░" * (bar_width - bar_len))

        if offset < 60:
            time_label = f"{offset:>5.0f}s"
        else:
            time_label = f"{offset/60:>5.1f}m"

        print(f"  {time_label:>8}  {b['packets']:>8,}  {fmt_bytes(b['bytes']):>10}  {bar}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    path = sys.argv[1]
    print(f"\n{bold(cyan('  ╔══════════════════════════════════════════════════════╗'))}")
    print(f"{bold(cyan('  ║'))}{bold('   Network Trace Analysis                             ')}{bold(cyan('║'))}")
    print(f"{bold(cyan('  ║'))}{dim(f'   File: {path:<47s}')}{bold(cyan('║'))}")
    print(f"{bold(cyan('  ╚══════════════════════════════════════════════════════╝'))}")

    print(f"\n  {dim('Parsing pcap...')}", end="", flush=True)
    data = parse_pcap(path)
    print(f"\r  {green('Parsing complete.')}   ")

    print_capture_summary(data)
    print_protocol_breakdown(data)
    print_top_talkers(data)
    print_service_breakdown(data)
    print_dns_analysis(data)
    print_connection_map(data)
    print_security_flags(data)
    print_timeline(data)

    print(f"\n{dim('  Analysis complete.')}\n")


if __name__ == "__main__":
    main()
