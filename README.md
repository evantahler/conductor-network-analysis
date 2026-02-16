# Network Trace Analysis

A network capture and analysis of [Conductor](https://conductor.build) and [Claude Code](https://claude.ai/claude-code) working together to produce [this diff](https://github.com/ArcadeAI/docs/compare/evantahler/landing-ascii-logo?expand=1) on the ArcadeAI docs repo. The pcap was captured via [Little Snitch](https://www.obdev.at/products/littlesnitch/) during a ~2.6 minute session.

![Little Snitch showing Conductor's network connections](images/little-snitch-conductor.png)

The screenshot above shows Little Snitch's view of the Conductor app's network activity during the capture — connections to fly.dev, PostHog, Anthropic, Datadog, Arcade, GitHub (via `gh` and `ssh`), npmjs.org, incident.io, chorus.sh, conductor.build, and crabnebula.app.

## Analyzer

`analyze.py` is a Python script that parses Little Snitch pcap files and prints a color-coded terminal report with service identification, connection mapping, security flags, and traffic timeline.

## Setup

```bash
uv init
uv add dpkt
```

## Usage

```bash
uv run python analyze.py data/conductor.pcap
```

## Report Sections

1. **Capture Summary** — time range, total packets/bytes, duration, rate
2. **Protocol Breakdown** — TCP/UDP/ICMP/other counts, bytes, percentages
3. **Top Talkers** — top 15 remote IPs by bytes, with SNI-based service identification
4. **Service Breakdown** — traffic aggregated by identified service (GitHub, Anthropic, etc.)
5. **Outbound Data Analysis** — per-destination deep dive: protocol (h2/TLS/SSH), directional bytes, traffic classification (LLM API, telemetry, git ops, package registry, etc.)
6. **DNS Analysis** — queries + response mappings (when DNS traffic is present in capture)
7. **Connection Map** — top 30 flows by bytes, enriched with hostnames and TCP flags
8. **Security Flags** — plaintext HTTP, non-standard ports, connection resets
9. **Traffic Timeline** — ASCII bar chart of traffic volume over time

## Notes

- Handles Little Snitch's non-standard pcap format (all packets written with IPv4 ethertype regardless of actual protocol)
- **TLS SNI extraction** — parses ClientHello messages to identify destinations by hostname (preferred over IP-range heuristics)
- **ALPN protocol detection** — extracts negotiated protocol (h2, http/1.1) from TLS handshake
- **SSH banner extraction** — captures SSH version strings on port 22 connections
- IP-range heuristics used as fallback when no SNI is observed (e.g., SSH connections)
- Local addresses (`0.1.x.x`, `::0.1.x.x`) are Little Snitch synthetic source IPs
- DNS traffic is typically not captured by Little Snitch, so the DNS section may be empty

## IP Identification

Since Little Snitch doesn't include DNS in its pcap exports, IP addresses are identified primarily via **TLS SNI** (Server Name Indication) extracted from ClientHello messages. IP-range heuristics are used as fallback for non-TLS connections (e.g., SSH).

| IP / Range | Identified As | Method |
|---|---|---|
| `2607:6bc0::10`, `160.79.104.10` | **api.anthropic.com** | TLS SNI |
| `140.82.116.6` | **api.github.com** | TLS SNI |
| `140.82.116.4` | **GitHub** (SSH git operations) | IP range (port 22, no TLS) |
| `2606:4700::6810:122` | **registry.npmjs.org** | TLS SNI |
| `2606:4700:10::ac42:9478`, `172.66.148.120`, `2606:4700:10::6814:1bcc` | **api.arcade.dev** | TLS SNI |
| `2606:4700:10::6814:11a7` | **us-assets.i.posthog.com** | TLS SNI |
| `2600:1f18:*` | **us.i.posthog.com** | TLS SNI |
| `2600:1901:0:3084::`, `34.149.*` | **http-intake.logs.us5.datadoghq.com** | TLS SNI |
| `2a09:8280:1::*` | **conductor-cloud-prototype.fly.dev** | TLS SNI |
| `76.76.21.22`, `66.33.60.35` | **statuspage.incident.io** | TLS SNI |

SNI-based identification resolves the ambiguity of Cloudflare CDN IPs — each is now mapped to its actual service (arcade.dev, posthog, npmjs, etc.).

## Example Output

Full plain-text report: [`report.txt`](report.txt)

Analysis of `conductor.pcap` — a 2.6 minute Little Snitch capture:

```
  ╔══════════════════════════════════════════════════════╗
  ║   Network Trace Analysis                             ║
  ║   File: data/conductor.pcap                            ║
  ╚══════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 1. Capture Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Start:    2026-02-16 18:42:45 UTC
  End:      2026-02-16 18:45:23 UTC
  Duration: 158.2s (2.6 min)
  Packets:  15,315
  Bytes:    12.5 MB
  Rate:     96.8 pkt/s, 80.7 KB/s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 2. Protocol Breakdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Protocol  Packets   Pkt %    Bytes  Byte %
  ────────  ───────  ──────  ───────  ──────
  TCP        15,315  100.0%  12.5 MB  100.0%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 3. Top Talkers (Remote Hosts)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  By total bytes (src + dst):

  IP Address                                   Sent  Received     Total  Hostname
  ───────────────────────────────────────  ────────  ────────  ────────  ──────────────────────────────────
  2607:6bc0::10                              1.6 MB    8.1 MB    9.7 MB  api.anthropic.com
  160.79.104.10                            714.2 KB  734.8 KB    1.4 MB  api.anthropic.com
  140.82.116.6                             375.9 KB   55.8 KB  431.6 KB  api.github.com
  2606:4700::6810:122                      363.1 KB   16.8 KB  379.9 KB  registry.npmjs.org
  2600:1901:0:3084::                        12.9 KB  122.5 KB  135.4 KB  http-intake.logs.us5.datadoghq.com
  140.82.116.4                              92.3 KB   15.1 KB  107.5 KB  GitHub
  2606:4700:10::ac42:9478                   59.2 KB   21.0 KB   80.1 KB  api.arcade.dev
  2606:4700:10::6814:11a7                   44.4 KB    3.0 KB   47.4 KB  us-assets.i.posthog.com
  2600:1f18:4c12:9a02:c6c7:fc08:82f6:ce27   12.8 KB   24.4 KB   37.2 KB  us.i.posthog.com
  172.66.148.120                            20.1 KB    3.8 KB   23.9 KB  api.arcade.dev
  76.76.21.22                               18.7 KB    2.4 KB   21.1 KB  statuspage.incident.io
  2606:4700:10::6814:1bcc                   10.8 KB    8.8 KB   19.6 KB  api.arcade.dev
  2a09:8280:1::c6:3c04:0                     8.0 KB    6.9 KB   15.0 KB  conductor-cloud-prototype.fly.dev
  66.33.60.35                                9.4 KB    1.2 KB   10.5 KB  statuspage.incident.io
  34.149.66.137                              4.9 KB    3.4 KB    8.2 KB  http-intake.logs.us5.datadoghq.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 4. Service Breakdown
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Service                             Flows     Bytes      %
  ──────────────────────────────────  ─────  ────────  ─────
  api.anthropic.com                   1,636   11.1 MB  89.5%
  api.github.com                         32  431.6 KB   3.4%
  registry.npmjs.org                     10  379.9 KB   3.0%
  http-intake.logs.us5.datadoghq.com     12  143.7 KB   1.1%
  api.arcade.dev                         48  123.6 KB   1.0%
  GitHub                                  6  107.5 KB   0.8%
  us-assets.i.posthog.com                 2   47.4 KB   0.4%
  us.i.posthog.com                        2   37.2 KB   0.3%
  statuspage.incident.io                  6   31.6 KB   0.2%
  conductor-cloud-prototype.fly.dev       4   15.0 KB   0.1%
  app.chorus.sh                           2    7.4 KB   0.1%
  app.conductor.build                     2    6.5 KB   0.1%
  cdn.crabnebula.app                      2    5.8 KB   0.0%
  Unknown                                16    2.5 KB   0.0%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 5. Outbound Data Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Destination                         Protocol      Out Bytes  In Bytes  Type                  Detail
  ──────────────────────────────────  ────────────  ─────────  ────────  ────────────────────  ────────────────────────────────────
  api.anthropic.com                   http/1.1/TLS     8.3 MB    1.9 MB  LLM API calls         Prompts + code context → completions
  api.github.com                      h2/TLS          41.9 KB  363.5 KB  API calls (download)  Receiving data / responses
  registry.npmjs.org                  TLS              9.9 KB  357.0 KB  Package registry      npm registry queries
  http-intake.logs.us5.datadoghq.com  http/1.1/TLS   122.1 KB   14.8 KB  Telemetry             Event/metric telemetry
  api.arcade.dev                      http/1.1/TLS    23.3 KB   82.8 KB  API calls (download)  Receiving data / responses
  GitHub:22                           SSH              9.7 KB   87.2 KB  Git pull/fetch        Inbound objects via SSH
  us-assets.i.posthog.com             h2/TLS           2.2 KB   43.6 KB  Telemetry             Event/metric telemetry
  us.i.posthog.com                    h2/TLS          21.2 KB    9.6 KB  Telemetry             Event/metric telemetry
  statuspage.incident.io              TLS              1.5 KB   26.4 KB  API calls (download)  Receiving data / responses
  conductor-cloud-prototype.fly.dev   http/1.1/TLS     4.8 KB    6.1 KB  REST API              Bidirectional API traffic
  app.chorus.sh                       TLS              1.2 KB    4.1 KB  Web traffic           HTTPS session
  app.conductor.build                 TLS            561.0 B     4.2 KB  Status check          Health ping / keep-alive
  cdn.crabnebula.app                  TLS            518.0 B     3.5 KB  App update            Update check / binary download

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 6. DNS Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total DNS queries: 0
  Unique names queried: 0
  Names with responses: 0

  Top queried names:

  (no data)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 7. Connection Map (Top 30 Flows)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Source                          Destination                                  Proto   Pkts     Bytes  Flags    Hostname
  ───────────────────────────  ─  ───────────────────────────────────────────  ─────  ─────  ────────  ───────  ──────────────────────────────────
  ::0.1.31.140:2960            →  2607:6bc0::10:443                            TCP    1,056    3.4 MB  FIN,SYN  api.anthropic.com
  ::0.1.31.140:2958            →  2607:6bc0::10:443                            TCP      687    2.5 MB  FIN,SYN  api.anthropic.com
  ::0.1.31.140:2956            →  2607:6bc0::10:443                            TCP      165  662.3 KB  FIN,SYN  api.anthropic.com
  ::0.1.31.140:3167            →  2607:6bc0::10:443                            TCP      104  440.1 KB  FIN,SYN  api.anthropic.com
  2607:6bc0::10:443            →  ::0.1.31.140:2960                            TCP    1,054  223.5 KB  FIN,SYN  api.anthropic.com
  ::0.1.36.38:3416             →  2607:6bc0::10:443                            TCP       35  199.8 KB  FIN,SYN  api.anthropic.com
  140.82.116.6:443             →  0.1.29.67:2756                               TCP       25  146.4 KB  FIN,SYN  api.github.com
  2606:4700::6810:122:443      →  ::0.1.40.14:3832                             TCP       33  146.0 KB  FIN,SYN  registry.npmjs.org
  140.82.116.6:443             →  0.1.29.67:3924                               TCP       20  145.4 KB  FIN,SYN  api.github.com
  2607:6bc0::10:443            →  ::0.1.31.140:2958                            TCP      685  128.0 KB  FIN,SYN  api.anthropic.com
  ::0.1.31.140:3222            →  2600:1901:0:3084:::443                       TCP       25  119.0 KB  FIN,SYN  http-intake.logs.us5.datadoghq.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 8. Security Flags
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  No significant security flags detected.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ 9. Traffic Timeline
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  (traffic timeline chart)
```

