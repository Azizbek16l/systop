# systop — technical overview

> Written in English on purpose: this is the document to hand to a reviewer,
> a client, or a new engineer. The code itself is commented in Uzbek, which is
> the working language of the team that runs it.

**Version:** 0.10.0 · **Language:** Python 3.11+ · **Size:** ~12,800 LOC · **Tests:** 817 (all offline)
**Commands:** 23 · **Platforms:** Linux, Windows, macOS · **Privileges:** none — never requires root/admin
**Install:** one-line installer, or a single self-contained binary (no Python needed)

---

## What it is

A network toolkit for sysadmins and netadmins that answers **"what is broken?"**,
not just "here are some numbers". It ships as one CLI plus a full-screen TUI
dashboard, and covers 22 commands that would otherwise be `ping`, `mtr`,
`traceroute`, `dig`, `nmap`, `ncat`, `openssl s_client`, `arp`, `netstat`,
`ip route`, `ntpdate`, `dhcping`, `iftop` and a browser speed-test tab.

The design bet: **breadth in one no-root binary**, with a diagnostic layer on
top that converts measurements into ranked findings with a suggested fix.

## Why it exists

It is built and used against real multi-site corporate networks. Every feature
traces to an incident that was hard to diagnose with existing
single-purpose tools — the driving observation being that the expensive part of
network troubleshooting is rarely collecting data, it is **knowing which number
is the anomaly**.

---

## Command surface

| Group | Commands |
|---|---|
| Reachability | `ping` (v4/v6, `--watch` live), `trace`, `mtr` |
| Discovery | `lan` (v4 sweep + v6 via NDP), `web` (admin-panel fingerprinting), `info` |
| Ports | `scan` (single host, CIDR, range, `--top N`, `--banner`, `--lan`, `--lan6`), `nc` (raw TCP/TLS) |
| Naming | `dns` (resolver comparison + real AAAA) |
| Transport | `tls`, `http`, `mtu` |
| Infrastructure | `route`, `dhcp`, `arpwatch`, `ntp`, `bw`, `conn` |
| Wireless | `wifi` (RSSI/SNR, channel, PHY, neighbour APs, 2.4 GHz overlap) |
| Synthesis | **`doctor`** — 15 checks, severity-ranked findings |
| Misc | `speed` (`--local` compares an IX endpoint against international), `config`, `dashboard` (TUI) |

Every command supports `--json` / `--format csv` with clean stdout and
meaningful exit codes (`0` ok, `1` error, `2` unreachable/expired/down), so it
drops into cron and monitoring without wrappers.

---

## Architecture

```
src/systop/
  cli.py            argparse entry; JSON/CSV serialisation layer; exit codes
  app.py            Textual TUI (status bar + speed + ping + 6-tab diagnostics)
  core/             network logic — async, UI-independent, individually usable
    ping speed topology ports webscan netcat dns tls bandwidth
    connections netinfo routes mtu dhcp ntp arpwatch oui config _platform
    diagnose.py     ← the "doctor" layer
  widgets/          Textual panels; each calls the same core/* functions
```

Two rules hold the design together:

1. **`core/` returns dataclasses, never UI objects.** The CLI, the TUI and the
   tests all call the same async functions.
2. **Network I/O is separated from judgement.** Every check is split into a
   pure `evaluate_*` / `parse_*` function and a thin async wrapper. That is why
   817 tests run fully offline in ~7 s — the parsing, scoring and classification
   logic is directly testable without a network.

### The diagnostic layer

`core/diagnose.py` holds a severity model (`critical` → `info`), a `Thresholds`
dataclass so limits are tunable per network type, and one pure `evaluate_*` per
check. `run_diagnostics()` orchestrates them with **every stage independently
guarded** — one failing check records itself in `report.skipped` instead of
aborting the report, because a diagnostic tool that crashes is worthless.

Current checks: interface errors/APIPA, gateway and internet loss/RTT/jitter,
DNS health and latency, risky listening services, LAN anomalies, IPv6 state,
insecure HTTP admin panels, TLS expiry, IPv6 port exposure, clock skew, routing,
path MTU, DHCP, ARP drift.

---

## Design decisions worth challenging

These are the choices I would most like an outside opinion on.

**1. No root, ever.** ICMP uses unprivileged datagram sockets; port scanning is
TCP connect (`-sT`), not SYN. This rules out SYN/stealth scan, OS fingerprinting,
reliable UDP scanning and packet capture. Traceroute needs a raw socket for TTL,
so it falls back to the setuid system `traceroute` binary. *Is "no root" worth
those losses, or should there be an opt-in privileged mode?*

**2. Uzbek-language UI, English identifiers.** All user-facing strings, table
headers, error messages and code comments are Uzbek. *This is deliberate for the
target users but obviously caps external contribution — worth revisiting?*

**3. Breadth over depth.** systop does not beat `nmap` at scanning, `mtr` at
path analysis or `dog` at DNS. It aims to be the tool you reach for first,
before knowing which specialist you need. *Is that a coherent product, or an
argument for a smaller sharper tool?*

**4. Batteries-included fingerprinting.** ~33 product fingerprints (Kerio,
Hikvision, Dahua, UniFi, MikroTik, Proxmox, Grafana, …) and a ~100-entry OUI
table are compiled in, so admin-panel detection and vendor lookup work offline.
The full IEEE OUI database (~30k) is deliberately excluded for file size.
*Right tradeoff, or should it fetch/cache the real database?*

**5. Deliberately slow scanning.** `web`/`doctor` default to concurrency 16
with an optional `--polite` mode (4 concurrent, 300 ms delay). Fast wide scans
trip IPS/anti-scan protection and get the scanning host temporarily blocked —
the symptom is badly misleading (ICMP fine, existing connections fine, every
*new* TCP connection refused). *Is defaulting to slow the right call?*

---

## Bugs found in production that shaped the code

Useful signal about the class of problem this domain generates:

- **MAC addresses rendered wrong on screen.** Rich treats `:ab:` as the emoji
  shortcode for 🆎, so `62:46:3c:ab:d1:1a` displayed as `62:46:3c🆎d1:1a`. Ten
  shortcodes are hex-only and reachable from address text (`:a:` `:b:` `:ab:`
  `:cd:` `:abc:` `:abcd:` `:bed:` `:bee:` `:100:` `:1234:`) — IPv6 is affected
  more than MAC. Fixed by wrapping all data cells in `rich.text.Text`; a test
  asserts the shortcode set so a future Rich release fails loudly.
- **The whole MAC/vendor column was empty.** `arp -a` does reverse DNS per entry
  and took 5.2 s on a /23, exceeding a 3 s subprocess timeout; the parser then
  silently returned nothing. `arp -an` does the same in 9 ms. Separately, macOS
  emits unpadded octets (`0:15:5d:…`) which never match the OUI table.
- **`getaddrinfo` hides AAAA records** when the host has no global IPv6 route
  (RFC 6724), returning IPv4-mapped `::ffff:` forms. A diagnostic tool must
  report what DNS *says*, so AAAA is now queried directly via dig.
- **Banner grabbing silently returned nothing** because `host.encode("idna",
  "ignore")` raises — the `idna` codec rejects an `errors` argument — and a
  broad `except` swallowed it.
- **False positives are the main quality risk.** Two were caught pre-release:
  a default nginx page classified as an "admin panel", and every dual-stack
  device flagged as a duplicate MAC (34 false alarms) because IPv4 and IPv6
  entries were compared together. Related: the project's own monitoring probe
  once reported three healthy systems as down simultaneously — the probe host
  had lost its network, so the correct fix was a self-health gate, not target
  checks.

---

## Known limitations

- No SYN scan, OS fingerprinting, UDP scanning, NSE-style scripting (all need root).
- No listen/server mode in `nc` — client only.
- IPv6 subnets cannot be swept (2^64 addresses); discovery uses `ff02::1`
  multicast plus the OS neighbour table, and `scan --lan6` scans exactly those.
- Rogue-DHCP detection via broadcast is best-effort: binding port 68 needs root,
  so strict RFC 2131 servers never reply to us. The active-lease path is the
  reliable one and always works.
- `trace` over IPv6 needs root on macOS (ICMPv6 datagram sockets are privileged).
- Not published to PyPI yet; installed from source via `uv tool install`.

---

## Questions I would like reviewed

1. **Is `doctor` the right centre of gravity?** Should the individual commands
   be de-emphasised in favour of one adaptive "find my problem" entry point?
2. **What high-value, no-root check is missing?** Candidates considered but not
   built: Wi-Fi signal/channel/noise, LLDP/CDP switch-port identification
   (needs promiscuous capture), SNMP polling, multicast/IGMP health for the NVR
   fleet, continuous monitoring with alerting.
3. **How should thresholds adapt?** They are currently fixed defaults in a
   `Thresholds` dataclass. Wi-Fi and fibre plainly deserve different limits —
   auto-calibrate from a baseline, or keep it explicit?
4. **Is the false-positive discipline sufficient?** For a tool whose output
   drives action, a wrong alarm costs more than a missed one. Is there a
   stronger pattern than "pure evaluators + regression tests per bug"?
5. **Distribution.** Now answered in part: self-contained PyInstaller binaries
   plus one-line installers for all three platforms, built in CI. Two open
   points remain — the binaries ship bytecode, not machine code, so they do not
   protect source; and the Uzbek UI is still the blocker for a wider release.

---

## Repository

`github.com/Azizbek16l/systop` — `README.md`, `README.uz.md`, `CHANGELOG.md`,
`CONTRIBUTING.md`, `SECURITY.md`, `ARCHITECTURE.md` (module map and the
non-obvious decisions), MIT licensed, ruff-clean, GitHub Actions CI with a
locale matrix (C/ascii, ru_RU, de_DE) and a Windows live smoke test.
