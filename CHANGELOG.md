# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- PyPI release and `uvx`/`pipx` install.
- Homebrew formula.

## [0.3.0] — 2026-06-06

Cross-platform: first-class **Windows** support alongside Linux and macOS.

### Added

- **Windows support.** `systop` now runs natively on Windows. Default-gateway
  detection (`route print` / `Get-NetRoute`), ICMP `ping`/`traceroute`/`mtr`,
  the LAN ping sweep, and ARP-table parsing all have Windows code paths — and
  still need **no Administrator** (ICMP falls back to the system `ping`/`tracert`
  on Windows). Linux/macOS behavior is unchanged.
- **Standalone per-OS binaries.** Tagged releases now publish self-contained
  executables for Windows, Linux and macOS (PyInstaller) attached to the GitHub
  Release — no Python install required.
- **Cross-OS CI matrix.** Every push is tested on `ubuntu-latest`,
  `windows-latest` and `macos-latest` across Python 3.11–3.13.
- **Local pre-commit gate** extended with `mypy` and `pytest` so every commit is
  validated before it lands.

### Changed

- Platform detection centralized in `core/_platform.py`; network commands select
  the right OS strategy at runtime.

## [0.2.0] — 2026-06-05

Scriptability, new diagnostics, and configuration.

### Added

- **Scriptable output layer.** Global `--json` and `--format {table,json,csv}`
  flags on every command, plus `-q/--quiet`, `-v/--verbose`, and `--no-color`
  (the `NO_COLOR` environment variable is honored). In machine modes stdout is
  kept clean; status and notes go to stderr.
- **Meaningful exit codes.** `0` success, `1` general error, `2` unreachable
  (host down / port closed / certificate expired or expiring / resolve failed)
  — so scripts and CI can branch on the result.
- **Live mtr** (`systop mtr HOST`, also `systop trace HOST --continuous`):
  per-hop loss% / last / avg / best / worst, streamed via `trace_stream` and
  `rich.Live`.
- **Per-interface bandwidth** (`systop bw`, `--watch` for live RX/TX/pps).
- **TLS certificate check** (`systop tls HOST[:PORT]`): expiry days, issuer,
  subject, SAN count, TLS version, with a `--warn-days` threshold that drives
  the exit code.
- **HTTP status check** (`systop http URL`): status, final URL, redirect chain,
  server, timing.
- **Active connections** (`systop conn`, `--listen` for listening sockets only).
- **Configuration file** at `~/.config/systop/config.toml` (override via
  `SYSTOP_CONFIG`): `ping_targets`, `dns_resolvers`, `speed_duration`,
  `speed_parallel`, `theme`, `scan_ports`. Missing/invalid files fall back to
  defaults silently. New `systop config` command (`--path`, `--show`, `--json`).
- **Built-in MAC vendor lookup** (OUI). LAN discovery now shows the vendor for
  each host using a bundled offline OUI table — no network call, no extra
  dependency.
- **TUI dashboard** expanded to a 6-tab diagnostics panel: LAN, traceroute,
  port scan, DNS, bandwidth, connections.

### Changed

- `systop ping` accepts `--targets` to override config targets explicitly.
- The async `core/` layer gained `bandwidth`, `tls`, `connections`, `config`,
  and `oui` modules; every command shares the same UI-independent functions.

### Fixed

- **Upload byte counting** in the speed test now measures actual uploaded bytes
  for accurate Mbps.

## [0.1.0] — Initial release

First working version.

### Added

- **Speed test** without `speedtest-cli` — uses Cloudflare's open `__down` /
  `__up` endpoints with time-boxed parallel streams and a warmup window.
- **Ping** to the local gateway and global targets, with `--ipv6`, `--watch`
  (live monitor), and a build-targets helper.
- **Traceroute** and **LAN discovery** (ping sweep + ARP table, no scapy/root).
- **TCP port scanner** (stdlib asyncio connect scan, parallel, semaphore-bound).
- **DNS diagnostics** — system resolve plus public-resolver latency comparison.
- **Interactive Textual TUI** dashboard: status bar, live speed/ping panels,
  tabbed topology panel, and a help screen (`?`).
- Unprivileged ICMP throughout (`privileged=False`): no root on macOS/Linux.
- Offline test suite covering pure logic (regex, dataclasses, target building,
  the mock-transport speed test).
