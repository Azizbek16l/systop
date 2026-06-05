# systop

> A no-root terminal network toolkit (TUI + CLI) for sysadmins — speedtest, ping, traceroute/mtr, LAN discovery, port scan, DNS, bandwidth, TLS/HTTP and connections, in one tool.

[O'zbekcha](README.uz.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

<!-- Badges: wire these up once the repo is public and CI runs. -->
[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](#)
[![PyPI](https://img.shields.io/badge/PyPI-soon-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

![demo](assets/demo.gif)

<!-- The GIF above is produced from `demo.tape` with charmbracelet/vhs (`vhs demo.tape`). -->

---

## Why systop?

Diagnosing a network usually means juggling a fistful of single-purpose tools:
`ping` here, `mtr` there, `traceroute`, `dig`, `nmap`, `openssl s_client`, `iftop`,
`ss`/`netstat`, plus a browser tab open on a speed-test site. Each has its own
flags, its own output format, and several need root.

`systop` folds 12 common network tasks into **one tool** that:

- **Needs no root.** ICMP runs over unprivileged datagram sockets (`SOCK_DGRAM`)
  on macOS and Linux — `ping`, `traceroute` and `mtr` work without `sudo`.
- **Works two ways.** A full-screen **Textual TUI dashboard** for interactive
  monitoring, and **one-shot CLI commands** for everything else.
- **Is scriptable.** Every command speaks `--json` / `--format csv` with clean
  stdout and **meaningful exit codes**, so it drops straight into monitoring
  scripts, CI checks and cron jobs.
- **Is offline-testable and dependency-light.** Pure-Python core, no `nmap`,
  `scapy`, or `speedtest-cli`. The OUI (MAC vendor) lookup ships built in.

The network logic lives in a UI-independent `core/` layer, so the same async
functions back the TUI, the CLI, and the test suite — 200+ offline tests.

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
| Interactive TUI         |   ✅   |  ✅   |   ✅   |  —  |   —   |    ✅     |
| JSON output             |   ✅   |  —    |   ✅   |  ✅ |   ✅  |    —      |
| No root required        |   ✅   |  ✅   |  ⚠️*  |  ✅ |   ✅  |   ⚠️*    |
| Single tool, all above  |   ✅   |  —    |   —    |  —  |   —   |    —      |

<sub>✅ supported · — not a feature of that tool · ⚠️ depends on platform/mode.
This matrix reflects each tool's headline purpose; the specialists generally go
deeper in their own niche.</sub>

---

## Install

systop targets **Python 3.11+**.

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

systop speed                 # download / upload / latency / jitter
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

systop dns example.com       # resolve + compare public DNS resolver latency
systop lan                   # LAN host discovery (IP / MAC / vendor / hostname)

systop bw                    # per-interface bandwidth (RX/TX) snapshot
systop bw --watch            # live bandwidth monitor

systop tls example.com       # TLS cert: expiry days, issuer, SAN, version
systop tls example.com:8443 --warn-days 30
systop http https://example.com   # HTTP status, redirects, timing

systop conn                  # active network connections
systop conn --listen         # only listening sockets

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

## Notes on permissions (ICMP)

`ping`, `traceroute` and `mtr` use `privileged=False` (unprivileged ICMP
datagram sockets), so no root is needed on macOS or Linux. If your system blocks
unprivileged ICMP sockets, run with `sudo` or set `privileged=True` in the core
functions. The active-connections view (`conn`) may show a fuller table with
root on macOS.

---

## License

[MIT](LICENSE) © 2026 Azizbek
