# DNS Watchdog (Windows)

A single-file PowerShell script that watches a Windows machine's own network traffic for signs of **DNS poisoning / spoofing**, using `pktmon` — the packet-capture tool built into Windows 10 (1809+), Windows 11, and Windows Server 2019+. No third-party capture tool (Wireshark, Npcap, tcpdump) is required.

It captures DNS traffic (UDP/TCP port 53) at the OS networking stack, which covers both LAN and WAN traffic on a typical machine, then parses the raw packets itself — pcapng binary format, Ethernet/IP/UDP/TCP headers, and the DNS message format, including name-compression pointers — entirely in native PowerShell.

A companion [bash/tcpdump version](../bash) covers macOS and Linux.

## What it detects

| Signal | Why it matters |
|---|---|
| **Conflicting answers to the same DNS query** | The textbook signature of a poisoning attempt: an attacker races a forged answer against the real one, hoping the forged reply arrives first and gets cached. |
| **Responses from a DNS server you never configured** | Compared against `Get-DnsClientServerAddress`. A reply from an unrecognized server can indicate an off-path attacker injecting answers. |
| **Responses with no matching outstanding query** | An answer for a question the monitor never saw asked — a possible sign of injected/spoofed traffic (with a startup grace period to avoid false positives). |
| **Default gateway MAC address changes mid-session** | Polled via `Get-NetNeighbor` each capture cycle. ARP spoofing is the usual first step attackers take to position themselves for on-LAN DNS tampering. |

Every alert prints two parts:

- **`[TECHNICAL]`** — raw packet detail, for anyone investigating further
- **`[WHAT THIS MEANS]`** — a plain-language explanation of why it matters

All output is also written to a timestamped log file.

## Requirements

- Windows 10 (1809+), Windows 11, or Windows Server 2019+, with `pktmon.exe` available (in-box on all of these)
- A reasonably current build — `pktmon pcapng` (used to convert captures for analysis) was added after initial 1809 release; if it's missing, update Windows
- PowerShell running **as Administrator** (packet capture requires it)

## Installation

```powershell
git clone https://github.com/microlaser/dns-watchdog.git
cd dns-watchdog\windows
```

No modules or external dependencies to install — just the script itself.

## Usage

From an **elevated (Administrator)** PowerShell:

```powershell
.\dns_watchdog.ps1
```

By default the script auto-detects your default gateway and configured DNS servers, and captures across all network adapters (pktmon operates at the OS networking stack, so this naturally covers both LAN and WAN traffic without picking a specific adapter). Stop monitoring with `Ctrl+C`; a session summary prints on exit.

### Parameters

```powershell
.\dns_watchdog.ps1 [-LogFile <path>] [-CaptureIntervalSeconds <n>] [-GraceResponses <n>] [-KeepCaptures]
```

| Parameter | Description |
|---|---|
| `-LogFile` | Path to the session log (default: `.\dns_watchdog_<timestamp>.log`) |
| `-CaptureIntervalSeconds` | Length of each capture window before it's converted and analyzed. Lower = less detection latency, more overhead. Default: `5` |
| `-GraceResponses` | Number of responses to observe before "no matching query" alerts activate, to avoid startup noise. Default: `10` |
| `-KeepCaptures` | Keep each window's `.etl`/`.pcapng` files on disk instead of deleting them after analysis |

### Example session

```
=========================================================================
 DNS Watchdog (Windows) - DNS poisoning / spoofing monitor
=========================================================================
Capturing on:      all network adapters (pktmon captures at the OS networking stack,
                   which covers this host's LAN and WAN traffic together)
Default gateway:   192.168.1.1  (MAC baseline: 60-95-F8-2B-5E-78)
Configured DNS:    192.168.0.1, 192.168.1.1
Log file:          .\dns_watchdog_20260918_204725.log
...

[20:47:44.872] [ALERT] Conflicting DNS responses for the same query
  [TECHNICAL] txn=64878  query=example.com (type 28)  first_response=[AAAA:2607:f8b0:...]  conflicting_response(src=10.0.0.9)=[AAAA:dead:beef::1]
  [WHAT THIS MEANS] This machine's DNS question got two DIFFERENT answers back. Legitimate DNS servers don't normally do this. This is the textbook signature of a DNS poisoning attempt, where an attacker races a forged answer against the real one, hoping the forged one arrives first and gets cached.
```

## How it works

Windows has no direct analog to piping `tcpdump` into a text parser — `pktmon`'s live console output is raw bytes, not decoded lines. So this script instead:

1. Runs `pktmon` in short rotating windows (5 seconds by default), capturing to `.etl`
2. Converts each window to `.pcapng` (`pktmon pcapng`)
3. Parses the pcapng binary format directly — reading Enhanced Packet Blocks, then walking each frame's IP → UDP/TCP → DNS message headers, including DNS name-compression pointer decoding — with no external libraries
4. Tracks DNS transaction IDs across capture windows using native PowerShell hashtables that persist for the life of the process, flagging conflicts and anomalies as they're seen
5. Separately polls the gateway's ARP entry each cycle to catch MAC address changes

**A quirk worth knowing:** Windows frequently captures locally-generated (outbound) packets *before* the Ethernet header is added at some stack checkpoints, so outbound DNS queries can arrive as bare IP packets with no link-layer framing at all, while inbound responses arrive fully Ethernet-framed off the wire. The parser detects and handles both. `pktmon` also tends to report the same physical packet more than once (captured at multiple points in the network stack); the script deduplicates byte-identical repeats within each capture window so one real packet isn't alerted on multiple times — a genuinely conflicting/poisoned response has different content, so it's never affected by this dedup.

## Limitations

- This is a **heuristic monitor**, not a guarantee. A single isolated alert can be a false positive (e.g. a VPN switching resolvers mid-session, or a CDN returning multiple valid IPs). Repeated or clustered alerts are far more meaningful than a one-off.
- There's a small gap between capture windows (stop → convert → restart) rather than truly continuous capture.
- DNS-over-TCP responses spanning multiple TCP segments aren't reassembled — fine for ordinary lookups, a real limitation for large zone-transfer-style responses.
- `pktmon pcapng` conversion requires a reasonably current Windows build; very old 1809-era systems may need to fall back to `pktmon etl2txt` instead (not implemented here).
- It observes traffic on the host it runs on; it cannot see poisoning that occurs purely within a remote resolver's cache before an answer ever reaches this machine.

## License

MIT (or update to match your preference).
