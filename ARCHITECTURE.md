# Architecture and development guide

This document is for developers working in the `systop` codebase: the layers,
a map of the modules, and the decisions that are INVISIBLE from the code (why
things are the way they are). Read the "Key decisions" section before adding a
feature — every entry there was written in the aftermath of a real bug.

## The project

`systop` is a terminal network tool for sysadmins that never requires root
(TUI + CLI) and runs on **Linux, Windows and macOS**. It puts a sysadmin's
day-to-day network tasks into a single tool: internet speed (international +
local/IX), local and global ping, traceroute/mtr, LAN discovery (IPv4+IPv6),
port scanning and banner grabbing, a raw TCP/TLS client, DNS comparison,
per-interface bandwidth, TLS/HTTP checks, active connections, a web/management
panel inventory, auto-diagnostics, clock skew (SNTP), the route table, path
MTU, DHCP detection, ARP/NDP watching and Wi-Fi analysis. Every command is
script-friendly (`--json`/`--format`, meaningful exit codes). Stack:
**Python 3.11+**, **Textual** (TUI), **httpx**, **icmplib**, **psutil**.
Package manager: **uv**.

> **The single source of truth for the command list is `_build_parser()` in
> `cli.py`.** Do not hand-maintain the list below by counting; when it drifts,
> `tests/test_docs.py` fails. If you add a subcommand you MUST also update the
> `cli.py` module docstring AND `README.md` — that is exactly what the parity
> test verifies.

## Commands

```bash
uv sync                          # environment + dependencies (for dev: uv sync --extra dev)
uv run systop                    # dashboard (TUI) — the default
uv run systop {speed|ping|lan|info|conn}   # one-shot commands
uv run systop ping --watch       # continuous ping monitor (rich.Live)
uv run systop ping --ipv6        # also include global IPv6 targets
uv run systop ping --targets 1.1.1.1,8.8.8.8   # explicit targets (overrides the config)
uv run systop trace <host> [--continuous]   # traceroute (--continuous == mtr)
uv run systop mtr <host> [--interval 1.0 --cycles N]   # live mtr (per-hop loss/avg/best/worst)
uv run systop scan <host> [--ports 22,80,443|1-1024]   # TCP port scanner
uv run systop dns <name> [--resolvers ...]   # DNS resolve + per-server latency comparison
uv run systop bw [--watch --interval 1.0]   # per-interface bandwidth (RX/TX/pps)
uv run systop tls <host[:port]> [--warn-days 14]   # TLS certificate (expiry, issuer, SAN)
uv run systop http <url>         # HTTP status (status, redirects, timing)
uv run systop conn [--listen]    # active connections (LISTEN only as well)
uv run systop web [HOST...]      # web services + management panels (LAN detected automatically)
uv run systop web --http80       # port 80 only: find plaintext HTTP exposure locally
uv run systop web --mgmt         # network management devices only
uv run systop web --polite       # slow mode (for networks with IPS/anti-scan)
uv run systop doctor             # find network problems automatically
uv run systop doctor --quick     # fast mode (skips web/IPv6)
uv run systop scan -6 HOST       # IPv6 port scan (-4 forces IPv4)
uv run systop lan -6             # LAN: IPv4 + IPv6 (ff02::1 + NDP table)
uv run systop lan --global-only  # exclude link-local addresses on IPv6
uv run systop scan 10.0.0.0/24 --top 20   # port sweep across the LAN (nmap -sT)
uv run systop scan HOST --banner          # service version (lightweight nmap -sV)
uv run systop nc HOST PORT [--send 'PING\r\n'] [--tls] [--hex]   # ncat style
uv run systop speed --local      # local (IX) endpoints vs international (speed_local_urls)
uv run systop speed --local-url URL   # one-off local endpoint (overrides the config)
uv run systop ntp [--servers a,b]     # clock skew (SNTP)
uv run systop route              # route table + next-hop reachability
uv run systop mtu [HOST] [--low 1200 --high 1500]   # path MTU (DF-ping binary search)
uv run systop dhcp [--listen 4.0]     # DHCP server(s) — rogue DHCP detection
uv run systop arpwatch [--no-update|--reset]   # ARP/NDP diff (MAC change, duplicate)
uv run systop wifi [--neighbours]     # Wi-Fi signal/SNR/channel (+ neighbouring APs)
uv run systop config [--path|--show]   # config file path / effective settings

# Global (script-friendly) flags — available on every command:
#   --json / --format {table,json,csv}   machine-readable output (clean stdout)
#   -q/--quiet, -v/--verbose, --no-color (NO_COLOR env is honoured too)
# Exit codes: 0 OK, 1 general error, 2 unreachable/dead/expired/no resolution

uv run pytest                    # the whole suite (offline)
uv run pytest tests/test_core.py::test_interface_cidr   # a single test
uv run ruff check .              # lint
uv run ruff format .             # format
uv run textual run --dev systop.app:SystopApp   # TUI in dev/debug mode (console: `textual console`)
```

## Architecture

Strictly split into two layers — **the core logic is independent of the TUI**:

The tree below is the **complete** list (every module under `src/` is here).
When you add a module, add it to the tree as well.

```
src/systop/
  __main__.py       # `python -m systop` entry point -> cli.main()
  cli.py            # argparse entry point; default -> dashboard, otherwise a one-shot command
                    #   + scriptability layer: _resolve_format, emit_json/emit_csv, _to_dict,
                    #     status()/note()/error() (stdout stays clean in machine mode), exit codes
                    #   SINGLE source of truth for subcommands: `_build_parser()` (the docs parity
                    #     test reads it)
  app.py            # SystopApp (Textual App): status bar + left column (speed+ping) + topology
  _render.py        # design layer for the CLI (Rich) output: styled_table + rtt_cell/loss_cell/
                    #   alive_cell gradation (30/100 ms, 50% loss thresholds — same as the TUI).
                    #   "table" mode ONLY; JSON/CSV do not depend on it.
                    #   NOTE: `glyph`/`data_cell` are NOT here — they live in `widgets/_glyphs.py`
                    #   (deliberately placed there to avoid a circular import)
  styles.tcss       # dashboard CSS (grid, panel borders, sparkline colours)
  core/             # network logic — async, NOT tied to Textual, usable on its own
    _platform.py    #   ★ OS strategy layer — EVERY platform branch belongs HERE:
                    #     IS_WINDOWS/IS_MACOS/IS_LINUX, `run_command(cmd, timeout, include_stderr)`
                    #     (the one and only async subprocess helper), decode_console (Windows OEM cp),
                    #     init_console/unicode_ok, Win32 IcmpSendEcho ping/traceroute (ctypes),
                    #     parse_windows_ping / _tracert / _route_print.
                    #     If you need to shell out to an OS command, do NOT write `subprocess`
                    #     yourself — use `run_command`. Forgetting `include_stderr=True` produces
                    #     real bugs: macOS `ping` writes "Message too long" to stderr, and that
                    #     silently broke path-MTU detection completely.
    netinfo.py      #   interfaces (psutil), default_gateway (OS route table), public_ip; gather_summary
    ping.py         #   ping_once/ping_many (icmplib async_*), build_targets(gateway), ping_stream (--watch)
    speed.py        #   run_speedtest -> Cloudflare __down/__up, time-boxed parallel streams + warmup
    topology.py     #   trace_path/traceroute (asyncio.to_thread), trace_stream (mtr), discover_lan (ping+ARP+vendor)
    ports.py        #   scan_host -> asyncio TCP connect port scanner (stdlib, parallel, semaphore), parse_ports
                    #     + family (auto|ipv4|ipv6), family_of() pure function
    netcat.py       #   `nc` — raw TCP/TLS CLIENT (no listen mode, no root needed):
                    #     connect + optional --send + response (text or hexdump), full IPv6
    webscan.py      #   discover_web/probe_service -> HTTP fingerprint + admin panel;
                    #     classify() is a PURE function (no network, tested offline)
    diagnose.py     #   run_diagnostics -> Report(Finding[]); evaluate_* PURE evaluators,
                    #     Thresholds, RISKY_LISTENERS, is_management_device
    dns.py          #   diagnose_dns -> system resolution + per-server latency comparison via dig/nslookup
    bandwidth.py    #   sample_bandwidth/bandwidth_stream -> per-interface RX/TX/pps (psutil deltas)
    tls.py          #   check_tls (certificate: days_left/issuer/SAN/version), check_http (status/redirect/timing)
    connections.py  #   list_connections -> psutil.net_connections + process name (sync, via to_thread)
                    #     + scan_connections -> ConnScan(permitted, source): on macOS psutil without root
                    #       ALWAYS raises AccessDenied => `netstat -an -p tcp` fallback path
    ntp.py          #   check_ntp -> SNTP (stdlib UDP/123), clock skew/offset/delay; no root needed
    routes.py       #   route table (`ip route`/`netstat -rn`/`route print`) + next-hop reachability;
                    #     the parse_* helpers are PURE functions (two default routes, the VPN 0.0.0.0/1 trick)
    mtu.py          #   discover_path_mtu -> DF-ping binary search; classify_ping_output is PURE
                    #     (ok | too_big | no_reply — conflate them and a host that blocks ICMP reports MTU 0)
    dhcp.py         #   DHCP DISCOVER (from an ephemeral port, no root) + lease source; rogue DHCP.
                    #     No answer does NOT mean "no server" => `partial=True`
    arpwatch.py     #   ARP/NDP snapshot + baseline diff (MAC change, duplicate IP, new host);
                    #     diff_snapshots is a PURE function, baseline kept as JSON in the config dir
    wifi.py         #   Wi-Fi signal/SNR/channel/band/PHY + neighbouring APs; a root-free source on
                    #     each OS (system_profiler / iw / netsh), the parsers are PURE functions
    config.py       #   load_config -> ~/.config/systop/config.toml (tomllib), SystopConfig dataclass, SYSTOP_CONFIG
                    #     speed_local_urls defaults to empty DELIBERATELY (the IX differs per country);
                    #     both http:// and https:// are allow-listed
    oui.py          #   lookup_vendor(mac) -> OUI vendor (offline), normalize_oui, is_locally_administered
  data/
    oui_min.py      #   small built-in OUI->vendor table (~60 vendors; not the full IEEE database)
  widgets/          # Textual panels that call into core (each does its async work under @work)
    _glyphs.py      #   ★ glyph()/data_cell()/dash()/ellipsis() + unicode_ok() — Unicode with an ASCII
                    #     fallback (old cmd.exe). `cli.py` AND every widget take their symbols from
                    #     here. Why not in `_render.py`: so that the `_render` <- `_glyphs` dependency
                    #     stays one-way (avoids a circular import)
    status_bar.py   #   top status bar (gateway/public IP/interface)
    speed_panel.py  #   speed panel (sparkline)
    ping_panel.py   #   ping panel (live table)
    help_screen.py  #   help modal, opened with `?`
    topology_panel.py #   6 tabs: LAN, traceroute, port scan, DNS, bandwidth, connections
                      #   (each in its own @work group: lan/trace/scan/dns/bw/conn)
```

**Data flow:** `widgets/*` and `cli.py` are the only two callers. Both call the
same async functions from `core/*`. To add a new measurement: first write a
pure async function in `core/` (no UI, return a dataclass), then wire it into
`cli.py` with a Rich table + JSON/CSV, and into `widgets/` with a panel.
JSON/CSV work automatically in the CLI: `_to_dict` serialises dataclasses (and
properties such as `loss_pct`/`cidr`/`total_bps`/`is_open`) — a new dataclass
only has to name those properties consistently.

### Key decisions (not visible from the code)

- **`getaddrinfo` HIDES AAAA records.** If the host has no global IPv6 route
  the OS filters AAAA out entirely and hands back `::ffff:1.2.3.4`
  (IPv4-mapped) — RFC 6724 address selection. A diagnostic tool has to show
  **what DNS actually says**, so the real AAAA is fetched separately via
  `dig +short AAAA` and `::ffff:` forms are dropped from the A list.
- **Banner grabbing: handshake TLS ports first.** Sending cleartext HTTP to
  443/4081/8006/8443… gets you nothing but "400 Bad Request". Ports listed in
  `_TLS_PORTS` are connected with `ssl=`, and only then is the request sent.
- **The `idna` codec does NOT support the `errors=` argument.**
  `host.encode("idna", "ignore")` -> `UnicodeError`, and a broad `except`
  swallowed it, silently destroying the banner. ASCII is enough for the Host
  header.
- **IPv6 CIDR ranges are never swept.** `parse_targets` deliberately rejects an
  IPv6 `/64` (2^64 addresses); a single IPv6 address is accepted. Use
  `discover_lan6` to find IPv6 hosts.
- **`trace` requires root on IPv6 (macOS).** The ICMPv6 datagram socket is
  privileged — unlike ICMPv4. That is an OS restriction, not something that can
  be fixed in code.

- **Admin-panel detection — a product fingerprint ALONE is not enough.** In
  `webscan` the fingerprints are split into two classes: `admin`
  (Kerio/Hikvision/Proxmox — +2 points) and `infra` (nginx/Apache/Caddy/Traefik
  — **0 points**, identification only). Without that split a plain nginx welcome
  page was being flagged as an "admin panel". The patterns are deliberately long
  as well: a short fragment (`hass`, `syno`, bare `docker`) can land inside
  another word and produce a false positive (`chassis` -> `hass`).
- **IPv6 LAN discovery is NOT a sweep.** A /64 holds 2^64 addresses — a ping
  sweep is impossible. `discover_lan6` pings `ff02::1` (all-nodes multicast) and
  then reads the OS neighbour table (`ip -6 neigh` / `ndp -an` / `netsh`). The
  zone suffix (`fe80::1%en0`) **is preserved** — a link-local address is
  unusable without its zone. macOS prints short MAC octets (`0:1c:42:3:4:5`), so
  `parse_ndp_output` pads them back to two digits.
- **Scan speed is deliberately low.** `web`/`doctor` default to
  `concurrency=16`, and `--polite` drops to 4 + 300 ms. The reason: a fast, wide
  scan trips IPS/anti-scan protection and the scanning IP gets temporarily
  blocked. The symptom is misleading — ICMP still works, existing connections
  still work, only NEW TCP connections come back "Connection refused" (this cost
  hours of chasing the wrong lead on 2026-07-28).
- **The `_to_dict` property list is a silent-loss source.** When you add a
  property to a dataclass, add it to the list in `cli.py` as well; otherwise it
  **silently disappears** from `--json`/`--format csv` output. The current list:
  `loss_pct, cidr, total_bps, is_open, url, risk, is_link_local, is_problem,
  worst_severity, counts`.
- **`diagnose` stages are independent.** In `run_diagnostics` every check sits
  in its own `try` and records failures in `report.skipped`. A diagnostic tool
  that falls over itself is useless — if one check (DNS, say) breaks, the rest
  must still produce results.
- **`evaluate_*` are pure, not orchestrators.** The evaluation logic is
  separated from the network calls, which is why the whole test suite runs
  offline (for the exact count run `uv run pytest -q` — don't write a number
  here, it goes stale). Keep the same shape when you add a check: take the
  measurement as an argument, return a `Finding`.

- **Speed without `speedtest-cli`.** Instead of the stale library, Cloudflare's
  open endpoints are used (`speed.cloudflare.com/__down`, `/__up`). The
  measurement is **time-boxed**: several parallel connections are opened, a
  shared `stop` event is set once `duration` seconds have elapsed, and Mbps is
  computed from bytes/elapsed. `_run_phase` and the workers MUST share **one
  single `stop` event** — hand them separate events and stopping never works.
- **ICMP without root.** `icmplib` is given `privileged=False` everywhere
  (SOCK_DGRAM ICMP on macOS/Linux). Do not change that default, or `sudo`
  becomes mandatory. traceroute runs in the same mode. Windows skips `icmplib`
  entirely: `_platform.win_icmp_ping`/`win_icmp_traceroute` (Win32
  `IcmpSendEcho`) are used, and they do not require Administrator either. The
  single exception is IPv6 `trace` on macOS (see the `trace` decision).
- **LAN discovery without scapy.** So that root is never needed: ping-sweep the
  `/24` (`async_multiping`) plus read the OS ARP table (`arp -a` / `ip neigh`)
  with a regex. `max_hosts` caps large networks.
- **traceroute is synchronous.** `icmplib.traceroute` is not async, so it is
  called through `asyncio.to_thread` to keep the event loop unblocked.
- **Textual workers.** Network work in the panels lives in
  `@work(exclusive=True)` methods. Async workers run on the event loop, so it is
  safe to update widgets **directly** from progress callbacks
  (`call_from_thread` is not required). The 4 operations in `TopologyPanel`
  (LAN/trace/scan/dns) **each get their own `group=`** — otherwise they all land
  in one default group and starting one cancels another (a LAN scan and DNS
  could not run at the same time, for instance).
- **Event-loop starvation in speed.py.** `_download_stream`/`_upload_stream`
  re-issue requests until `stop` is set (in ~50 MB chunks, because Cloudflare
  `__down` returns 403 for 100 MB). An **`await asyncio.sleep(0)`** after every
  request is MANDATORY: with a transport that answers instantly (the test mock)
  it prevents the monitor coroutine from being starved and `stop` from never
  being set. `warmup` (1s by default) keeps TCP slow-start bytes out of the
  measurement (more accurate Mbps).
- **ICMP/port scanning are untested.** The network-bound functions
  (ping/traceroute/scan/dns) cannot be exercised offline; speed.py, by contrast,
  is tested without a network via `httpx.MockTransport` (`tests/test_speed.py`).
  Because the mock answers instantly, the test hangs without the `sleep(0)`
  above.
- **Scriptability — a single JSON/CSV layer.** The output format is driven by
  the global `_FORMAT` (table|json|csv) in `cli.py` (`_resolve_format`:
  `--format` > `--json` > table). In machine mode (`_is_machine()`) the status
  spinner, the notes and the Rich table are **suppressed** — only the pure
  result goes to stdout, errors go to stderr (`error()`). Command handlers take
  a `core/` dataclass and pass it to `emit_json`/`emit_csv`/a Rich table. **A new
  field is automatically a new line in the JSON** — `_to_dict` walks
  `dataclasses.fields`, drops internal `_`-prefixed fields, and manually adds the
  selected properties (`loss_pct`/`cidr`/`total_bps`/`is_open`).
- **Exit-code scheme.** `0` OK, `1` a general error (bad argument / exception —
  caught in `main()`), `2` "unreachable" (host dead, no port open, certificate
  expired or close to it, no DNS resolution, traceroute with no hops). Every
  handler returns an `int`; `tls`/`http` have their own `_tls_exit_code`/
  `_http_exit_code` (status>=400 or days_left<=warn_days => 2). The live
  `--watch`/`mtr` mode does not work in a machine format (it errors out);
  `mtr --json` runs several cycles and prints the final snapshot.
- **Upload byte fix.** In the upload phase `speed.py` counts the bytes that were
  **actually sent** (every chunk in the generator/stream is counted); otherwise
  the Mbps figure came out wrong (far too high). Same `stop` event-time logic as
  the download.
- **`trace_stream` — the basis for mtr.** Both `mtr` and `trace --continuous`
  are fed by the `trace_stream(host, interval, cycles)` async generator in
  `core`: each cycle re-probes the hops and updates the per-hop `HopStat`
  (loss%/last/avg/best/worst). The CLI renders that live with `rich.Live`;
  `cycles=None` => run forever (Ctrl+C stops it).
- **OUI vendor lookup — offline.** During LAN discovery the vendor is derived
  from the MAC via `core/oui.py` using a small built-in table (`data/oui_min.py`,
  ~60 vendors) — no network access, no extra dependency. A locally-administered
  MAC does not identify a global vendor => `None`. The full IEEE database (~30k)
  is intentionally NOT included (file size).
- **Configuration — optional, silent defaults.** `core/config.py` is stdlib only
  (`tomllib`); if the file is missing, malformed or unreadable, a fully default
  `SystopConfig` is returned (NO exception). Only known keys are read, and a
  value of the wrong type is silently ignored. Lookup order: argument >
  `SYSTOP_CONFIG` env > `~/.config/systop/config.toml`. `core/config.py` imports
  no other core module.

## Conventions

- All user-facing text (panel titles, table headers, error messages,
  docstrings) is in **English**, code identifiers included.

  > **Migration in progress.** A large part of `src/` and `tests/` is still
  > written in Uzbek — the language the project was originally built in. New
  > code must be English; existing text is being converted module by module.
  > Do not treat the remaining Uzbek as the convention.
- Every `core/` function returns a dataclass or a plain value (never a UI
  object), so the CLI, the TUI and the tests can all consume it identically.
- Tests must be **offline** (no network access) — exercise pure logic such as
  regexes, dataclasses and `build_targets`. Network-bound functions cannot be
  tested.
- **Docs move in lockstep with the code.** `tests/test_docs.py` checks that
  every subcommand in `_build_parser()` appears in `README.md`, and that the set
  of commands in the `cli.py` module docstring matches the parser EXACTLY. A new
  subcommand means updating all three: the parser, the docstring and the README.
- **Platform branching belongs in `core/_platform.py` only.** Do not write
  `platform.system()`/`subprocess` in any other module; call
  `_platform.run_command(...)`, and don't forget `include_stderr=True` when the
  OS writes its message to stderr.
