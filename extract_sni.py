#!/usr/bin/env python3
"""Extract TLS SNI and outbound payload info from a Little Snitch pcap."""

import sys
import struct
import socket
import dpkt


def ip_str(packed):
    if len(packed) == 4:
        return socket.inet_ntop(socket.AF_INET, packed)
    elif len(packed) == 16:
        return socket.inet_ntop(socket.AF_INET6, packed)
    return packed.hex()


def is_local(ip):
    return ip.startswith(("0.1.", "::0.1."))


def parse_tls_sni(data):
    """Extract SNI from TLS ClientHello."""
    try:
        if len(data) < 5 or data[0] != 0x16:  # TLS handshake
            return None
        pos = 5
        if data[pos] != 0x01:  # ClientHello
            return None
        pos += 4  # handshake header
        pos += 2  # client version
        pos += 32  # random
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2 + cs_len
        comp_len = data[pos]
        pos += 1 + comp_len
        ext_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_len
        while pos < end:
            ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
            ext_data_len = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
            pos += 4
            if ext_type == 0x0000:  # SNI
                name_len = struct.unpack("!H", data[pos + 3 : pos + 5])[0]
                return data[pos + 5 : pos + 5 + name_len].decode(
                    "ascii", errors="replace"
                )
            pos += ext_data_len
    except (IndexError, struct.error):
        pass
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/conductor.pcap"

    sni_map = {}  # dst_ip -> SNI
    outbound_bytes = {}  # dst_ip -> total bytes sent
    plaintext_payloads = []

    with open(path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            if len(buf) < 15:
                continue
            ver = buf[14] >> 4
            try:
                if ver == 4:
                    ip = dpkt.ip.IP(buf[14:])
                elif ver == 6:
                    ip = dpkt.ip6.IP6(buf[14:])
                else:
                    continue
            except (dpkt.UnpackError, struct.error):
                continue

            src = ip_str(ip.src)
            dst = ip_str(ip.dst)

            if not is_local(src) or is_local(dst):
                continue

            proto_num = ip.p if ver == 4 else ip.nxt
            if proto_num != 6:
                continue

            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            payload = bytes(tcp.data)
            if not payload:
                continue

            outbound_bytes[dst] = outbound_bytes.get(dst, 0) + len(payload)

            sni = parse_tls_sni(payload)
            if sni:
                sni_map[dst] = sni

            # Check for plaintext HTTP
            if payload[0:1] not in (b"\x16", b"\x17", b"\x15", b"\x14"):
                if payload[:4] in (
                    b"GET ",
                    b"POST",
                    b"PUT ",
                    b"HEAD",
                    b"DELE",
                    b"PATC",
                    b"HTTP",
                ):
                    preview = payload[:200].decode("ascii", errors="replace")
                    plaintext_payloads.append((src, dst, tcp.dport, preview))

    print("=" * 70)
    print("TLS SNI (Server Name Indication) from ClientHello messages")
    print("=" * 70)
    for dst_ip, sni in sorted(sni_map.items(), key=lambda x: x[1]):
        sent = outbound_bytes.get(dst_ip, 0)
        print(f"  {sni:<50s}  {sent:>10,} bytes out  ({dst_ip})")

    print()
    print("=" * 70)
    print("Outbound bytes by destination (excluding Anthropic)")
    print("=" * 70)
    for dst, total in sorted(outbound_bytes.items(), key=lambda x: -x[1])[:20]:
        sni = sni_map.get(dst, "(no SNI)")
        print(f"  {dst:<50s}  {total:>10,} bytes  SNI: {sni}")

    print()
    print("=" * 70)
    print("Plaintext HTTP payloads")
    print("=" * 70)
    if plaintext_payloads:
        for src, dst, port, preview in plaintext_payloads:
            print(f"  {src} -> {dst}:{port}")
            print(f"    {preview[:150]}")
            print()
    else:
        print("  None detected (all traffic encrypted)")


if __name__ == "__main__":
    main()
