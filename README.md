# systop

> A no-root terminal network toolkit (TUI + CLI) for sysadmins — speedtest, ping, traceroute/mtr, LAN discovery, port scan, DNS, bandwidth, TLS/HTTP and connections, in one tool.

[O'zbekcha](README.uz.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

<!-- Badges: wire these up once the repo is public and CI runs. -->
[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](#)
[![PyPI](https://img.shields.io/badge/PyPI-soon-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

<!-- A terminal recording can be produced from `demo.tape` with charmbracelet/vhs
     (`vhs demo.tape`); it is not committed yet, so no image is embedded here. -->

---

## Why systop?

Diagnosing a network usually means juggling a fistful of single-purpose tools:
`ping` here, `mtr` there, `traceroute`, `dig`, `nmap`, `openssl s_client`, `iftop`,
`ss`/`netstat`, plus a browser tab open on a speed-test site. Each has its own
flags, its own output format, and several need root.

`systop` folds a sysadmin's day-to-day network tasks into **one tool** that:

- **Cross-platform, no root.** Runs on **Linux, Windows and macOS**. ICMP uses
  unprivileged datagram sockets (`SOCK_DGRAM`) on Linux/macOS and the Win32
  `IcmpSendEcho` API on Windows — so `ping`, `traceroute` and `mtr` work without
  `sudo` or Administrator on every platform. See
  [Platform support](#platform-support) for the handful of per-OS caveats.
- **Works two ways.** A full-screen **Textual TUI dashboard** for interactive
  monitoring, and **one-shot CLI commands** for everything else.
- **Is scriptable.** Every command speaks `--json` / `--format csv` with clean
  stdout and **meaningful exit codes**, so it drops straight into monitoring
  scripts, CI checks and cron jobs.
- **Is offline-testable and dependency-light.** Pure-Python core, no `nmap`,
  `scapy`, or `speedtest-cli`. The OUI (MAC vendor) lookup ships built in.

The network logic lives in a UI-independent `core/` layer, so the same async
functions back the TUI, the CLI, and the test suite — which runs entirely
offline (`uv run pytest` needs no network at all).

---

## Feature matrix

How systop compares to popular focused tools. systop's aim is breadth in one
binary, not beating each specialist at its own depth.

| Capability              | systop | gping | trippy | dog | naabu | bandwhich |
|-------------------------|:------:|:-----:|:------:|:---:|:-----:|:---------:|
| Speed test (down/up)    |   ✅   |  —    |   —    |  —  |   —   |    —      |
| Ping (multi-target)     |   ✅   |  ✅   |   —    |  —  |   —   |    —      |
| Live ping monitor       |   ✅   |  ✅   |   —    |  —  |   —   |    —      |
| Traceroute              |   ✅   |  —    |   ✅   |  —  |   —   |    —      |
| Live mtr (per-hop loss) |   ✅   |  —    |   ✅   |  —  |   —   |    —      |
| LAN discovery + vendor  |   ✅   |  —    |   —    |  —  |   —   |    —      |
| TCP port scan           |   ✅   |  —    |   —    |  —  |   ✅  |    —      |
| DNS resolver compare    |   ✅   |  —    |   —    |  ✅ |   —   |    —      |
| Per-interface bandwidth |   ✅   |  —    |   —    |  —  |   —   |    ✅     |
| Per-process bandwidth   |   —    |  —    |   —    |  —  |   —   |    ✅     |
| TLS certificate check   |   ✅   |  —    |   —    |  —  |   —   |    —      |
| HTTP status check       |   ✅   |  —    |   —    |  —  |   —   |    —      |
| Active connections      |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Admin-panel discovery** |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Auto problem finder**   |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **IPv6 (scan + discovery)** |   ✅   |  —    |   —    |  ✅ |   —   |    —      |
| **LAN-wide port sweep**   |   ✅   |  —    |   —    |  —  |   ✅  |    —      |
| **Service banners (-sV)** |   ✅   |  —    |   —    |  —  |   ✅  |    —      |
| **Raw TCP/TLS client**    |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Clock skew (SNTP)**     |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Route table + next-hop**|   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Path MTU discovery**    |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Rogue DHCP detection**  |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **ARP/NDP change watch**  |   ✅   |  —    |   —    |  —  |   —   |    —      |
| **Wi-Fi signal / channel**|   ✅   |  —    |   —    |  —  |   —   |    —      |
| Interactive TUI         |   ✅   |  ✅   |   ✅   |  —  |   —   |    ✅     |
| JSON output             |   ✅   |  —    |   ✅   |  ✅ |   ✅  |    —      |
| No root required        |   ✅   |  ✅   |  ⚠️*  |  ✅ |   ✅  |   ⚠️*    |
| Single tool, all above  |   ✅   |  —    |   —    |  —  |   —   |    —      |

<sub>✅ supported · — not a feature of that tool · ⚠️ depends on platform/mode.
This matrix reflects each tool's headline purpose; the specialists generally go
deeper in their own niche.</sub>

---

## Install

systop targets **Python 3.11+** and runs on **Linux, Windows and macOS**.

### Standalone binary (no Python required)

Every tagged release ships a self-contained executable for each platform on the
[Releases](https://github.com/azizbek/systop/releases) page — download, mark
executable, run:

| Platform | Asset |
|----------|-------|
| Windows  | `systop-windows-x86_64.exe` |
| Linux    | `systop-linux-x86_64` |
| macOS    | `systop-macos-arm64` |

```powershell
# Windows (PowerShell)
.\systop-windows-x86_64.exe
```
```bash
# Linux / macOS
chmod +x systop-linux-x86_64 && ./systop-linux-x86_64
```

### Run without installing (recommended for a quick try)

```bash
uvx systop            # run the latest published version in an ephemeral env
```

### Install as a tool

```bash
uv tool install systop      # via uv
pipx install systop         # via pipx
```

### From source

```bash
git clone https://github.com/azizbek/systop
cd systop
uv sync                                   # create venv + install deps
uv run systop                             # run the dashboard
uv tool install . --force --reinstall     # put `systop` on your PATH
```

### Homebrew

```bash
# brew install systop      # coming soon
```

---

## Usage

Running `systop` with no arguments opens the interactive dashboard. Every
subcommand below also works as a one-shot, script-friendly call.

```bash
systop                       # interactive TUI dashboard (default)
systop dashboard             # the same, spelled out

systop speed                 # download / upload / latency / jitter
systop speed --local         # also measure local/IX endpoints (see speed_local_urls)
systop speed --local-url URL # ad-hoc local endpoint (repeatable; overrides config)
systop ping                  # local gateway + global targets
systop ping --watch          # live ping monitor (Ctrl+C to stop)
systop ping --ipv6           # add IPv6 global targets
systop ping --targets 1.1.1.1,8.8.8.8   # explicit targets

systop trace 1.1.1.1         # traceroute
systop trace 1.1.1.1 --continuous   # same as `mtr`
systop mtr 1.1.1.1           # live mtr-style: per-hop loss% / avg / best / worst

systop scan example.com                 # TCP port scan (common ports)
systop scan example.com --ports 22,80,443
systop scan example.com --ports 1-1024
systop scan 10.0.0.0/24 --top 20        # LAN-wide port sweep
systop scan example.com --banner        # service/version banners
systop scan -6 example.com              # IPv6 scan (-4 forces IPv4)

systop nc example.com 25                # raw TCP client (ncat-style)
systop nc example.com 6379 --send 'PING\r\n'
systop nc example.com 443 --tls --hex   # TLS handshake, hexdump the reply

systop dns example.com       # resolve + compare public DNS resolver latency
systop lan                   # LAN host discovery (IP / MAC / vendor / hostname)
systop lan -6                # also IPv6 (ff02::1 multicast + NDP table)
systop lan -6 --global-only  # drop link-local (fe80::) addresses

systop bw                    # per-interface bandwidth (RX/TX) snapshot
systop bw --watch            # live bandwidth monitor

systop tls example.com       # TLS cert: expiry days, issuer, SAN, version
systop tls example.com:8443 --warn-days 30
systop http https://example.com   # HTTP status, redirects, timing

systop conn                  # active network connections
systop conn --listen         # only listening sockets

systop web                   # web services + admin panels across the LAN
systop web --http80          # only port 80 (find plaintext HTTP exposure)
systop web --mgmt            # only network gear (router / firewall / switch / NVR)
systop web --polite          # slow mode for networks with IPS / anti-scan

systop doctor                # auto-find network problems, ranked by severity
systop doctor --quick        # fast mode (skips the web scan and IPv6)

systop ntp                   # clock skew (SNTP) — the silent cause of auth/TLS failures
systop route                 # route table + next-hop reachability
systop mtu                   # path MTU via DF-ping binary search (default 1.1.1.1)
systop mtu example.com --low 1200 --high 1500
systop dhcp                  # detect DHCP server(s) — catches a rogue DHCP
systop arpwatch              # ARP/NDP changes since the last run (MAC swap, dup IP)
systop wifi                  # Wi-Fi signal / SNR / channel / band / PHY rate
systop wifi --neighbours     # also list nearby APs (channel congestion)

systop info                  # interfaces, gateway, public IP
systop config                # show config file path + effective settings
```

### Scripting: JSON, CSV and exit codes

Every command accepts global flags. In `--json` / `--format csv` mode stdout
stays machine-clean (status spinners and notes go to stderr).

```bash
systop speed --json
systop ping --format csv
systop tls example.com --json | jq '.days_left'
systop scan host --ports 1-1024 --json

# Flags: --json, --format {table,json,csv}, -q/--quiet, -v/--verbose, --no-color
# NO_COLOR is also honored.
```

**Exit codes** (so scripts can branch):

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | General error (bad argument, internal error) |
| `2`  | Unreachable: host down, port closed, certificate expired/expiring, or resolve failed |

```bash
# Example: fail CI if a cert expires within 30 days
systop tls example.com --warn-days 30 --json || echo "cert needs renewal"
```

---

## Dashboard keybindings

The TUI shows a status bar (gateway / public IP / interface), live speed and
ping panels, and a 6-tab diagnostics panel (LAN, traceroute, port scan, DNS,
bandwidth, connections).

| Key | Action |
|-----|--------|
| `s` | Run speed test |
| `r` | Refresh ping |
| `l` | Scan LAN |
| `t` | Focus traceroute |
| `d` | Toggle theme (dark / light) |
| `?` | Help |
| `q` | Quit |

---

## Configuration

systop reads an optional TOML file from `~/.config/systop/config.toml`
(override the path with the `SYSTOP_CONFIG` environment variable). If the file
is missing or invalid, sensible defaults are used silently — bad values are
ignored, never fatal.

```toml
# ~/.config/systop/config.toml

ping_targets   = ["1.1.1.1", "8.8.8.8"]   # extra ping targets
dns_resolvers  = ["1.1.1.1", "9.9.9.9"]   # resolvers to compare in `dns`
speed_duration = 10.0                       # speed test duration (seconds)
speed_parallel = 4                          # parallel speed-test streams
theme          = "dark"                     # "dark" or "light"
scan_ports     = "1-1024"                   # default port set for `scan`
```

### `speed_local_urls` — local (IX) speed endpoints

`systop speed --local` measures your throughput to *local* endpoints and
compares it with the international figure. That answers the question a
speed-test site cannot: "is my uplink slow, or is only the route abroad slow?"

The endpoints are **deliberately not hardcoded** — they are per-country. Baking
a list of Uzbek TAS-IX mirrors into the source would bind the tool to one
country and quietly produce wrong numbers everywhere else, so `core/config.py`
ships an empty default and you supply your own IX. No code change is needed for
plain-HTTP mirrors either: `config.py` already whitelists both `http://` and
`https://` (anything else in the list is dropped).

```toml
speed_local_urls = [
  "https://speedtest.uz/backend/garbage.php?ckSize=100",
  "http://speedtest.spy.uz/backend/garbage.php?ckSize=100",  # http:// — the cert is issued to another name
  "http://mirror.dc.uz/rockylinux/9/isos/x86_64/Rocky-9-latest-x86_64-boot.iso",
]
```

The example above is a working Uzbek (TAS-IX) set. Elsewhere, point it at your
own IX mirror — any URL that serves a large file over HTTP(S) works. Ad-hoc
runs do not need the config file at all:

```bash
systop speed --local                     # use speed_local_urls from config
systop speed --local-url https://mirror.example.uz/100MB.bin   # repeatable
```

```bash
systop config           # show path, existence, env override, effective settings
systop config --path    # print only the config file path (script-friendly)
systop config --show    # show effective settings as a table
systop config --json    # config + _config_path + _config_exists
```

---

## Development

```bash
uv sync --extra dev               # install dev dependencies

uv run pytest                     # run the offline test suite
uv run pytest tests/test_core.py::test_interface_cidr   # one test
uv run ruff check .               # lint
uv run ruff format .              # format

uv run textual run --dev systop.app:SystopApp   # TUI in dev mode
# (run `textual console` in another terminal for live logs)
```

The codebase splits strictly into a UI-independent async `core/` layer and its
two callers (`cli.py` and the Textual `widgets/`). See
[CONTRIBUTING.md](CONTRIBUTING.md) for conventions, including the offline-test
rule and the Uzbek user-facing-text rule.

---

## Platform support

systop runs on **Linux, Windows and macOS**, and every command is designed to
work as an ordinary user. Where an OS makes that impossible, systop degrades to
a weaker source rather than failing — and says so in its output.

| Area | Linux | Windows | macOS |
|------|-------|---------|-------|
| `ping` / `trace` / `mtr` (IPv4) | `icmplib`, `SOCK_DGRAM`, no root | Win32 `IcmpSendEcho` via ctypes, no Administrator | `icmplib`, `SOCK_DGRAM`, no root |
| `trace` over IPv6 | no root | no Administrator | **needs root** — ICMPv6 datagram sockets are privileged on macOS. An OS restriction, not a systop bug |
| `conn` | psutil (process names) | psutil (process names) | psutil always raises `AccessDenied` without root, so systop falls back to `netstat -an -p tcp` — full port list, **no PID/process name**. `--json` reports the source |
| `mtu` | `ping -M do` | `ping -f -l` | `ping -D` (the "Message too long" line arrives on **stderr**, which systop reads) |
| `route` | `ip route` | `route print` | `netstat -rn` |
| `wifi` | `iw dev <iface> link` / `scan` | `netsh wlan show interfaces` (output is localized; systop parses several languages) | `system_profiler SPAirPortDataType` (`airport -I` was removed in macOS 14.4 and `wdutil` needs sudo, so neither is used) |
| `dhcp` | `dhclient` lease files | `ipconfig /all` | `ipconfig getpacket` |
| Console encoding / glyphs | UTF-8 | OEM codepage decoded explicitly; Unicode glyphs fall back to ASCII on a legacy `cmd.exe` | UTF-8 |

Cross-OS behaviour lives in one place, `core/_platform.py`, so a command never
grows its own subprocess or encoding handling.

### A note on ICMP permissions

No `sudo` is required. `ping`, `traceroute` and `mtr` pass `privileged=False`
to `icmplib` everywhere (unprivileged ICMP datagram sockets on Linux/macOS),
and Windows uses the `IcmpSendEcho` API, which does not need Administrator.
The two exceptions above are the only ones: IPv6 `trace` on macOS, and the
`conn` process-name column on macOS.

---

## License

[MIT](LICENSE) © 2026 Azizbek
