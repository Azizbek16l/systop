# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.2] — 2026-07-31

### Fixed

- **`doctor` reported false "all DNS servers down" on localized Windows.**
  Found on a live server (Russian-language Windows 10): `ipconfig
  /all` prints `DNS-серверы`, not `DNS Servers`, so the label regex never
  matched, `system_resolvers()` returned empty, and the check fell back to
  public resolvers only — producing exactly the false HIGH this release series
  set out to eliminate, just on a different OS.
  This is the same class of defect as the v0.3.2 ping bug, where English-only
  output parsing made every target look dead on Russian Windows. The lesson was
  already learned once; the new code reintroduced it.
  Two changes: `Get-DnsClientServerAddress` (structured, locale-independent) is
  now the primary Windows source, and the `ipconfig` fallback no longer matches
  on the English label — it accepts any `DNS`-bearing label and decides by the
  *shape of the value*, so `DNS-суффикс` / `DNS Suffix` lines drop out on their
  own. Tested against Russian, German and English output.

## [0.10.1] — 2026-07-31

### Fixed

- **`wifi` never reported 5 GHz channel collisions.** Overlap detection existed
  only for 2.4 GHz, so the single most damaging case — another AP sitting on
  *exactly* your 5 GHz channel, i.e. full co-channel contention — was silently
  absent from both the table and `doctor`. Measured on a real network: the host
  was on channel 64 with two neighbours also on 64, and the tool said nothing.
  Added `channel_span()` and `overlapping_channels()`, both pure. 5/6 GHz
  channels do not slide into each other the way 2.4 GHz does — they occupy
  fixed blocks, and an 80 MHz AP covers four 20 MHz channels, so comparing
  channel *numbers* misses the overlap entirely. The UNII-3 block (149+) is not
  reachable by arithmetic — `(149-36)/4` is not an integer — so the blocks are
  a table, not a formula.

### Added

- `wifi --neighbours` now shows an **SSID** column and an **interference**
  column (`same channel` / `overlaps` / `no`), with the interfering APs
  sorted to the top. Reading the old table meant comparing channel numbers by
  eye, which is exactly the work the tool exists to do.
- When the OS withholds SSIDs (macOS hides them without Location Services
  permission) the tool now says so and names the setting, instead of rendering
  an unexplained empty column.

## [0.11.0] — 2026-07-31

### Fixed

- `wifi --neighbours` no longer reports "2 APs interfering, 2 of them on the
  same channel" when all of them are — three distinct messages now cover the
  three cases (all co-channel, partly overlapping, overlap only).
- The published installer URLs pointed at `/main/`, but the default branch is
  `master`; copy-pasting the documented one-liner returned 404.
- The Intel macOS asset no longer exists (GitHub retired the runner), so an
  Intel Mac downloaded a 404 page and failed with "download failed". It now
  explains why and points at the source build.
- The release matrix still listed the retired `macos-13` runner. With
  `fail-fast: false` the other three platforms finished, but the release job
  waits on the whole matrix — one dead entry stalled every release for an hour.

### Added

- A test that compares `diagnose.MANAGEMENT_KINDS` against the `device_kind`
  values `webscan` actually emits. They are a data contract between the two
  modules, and the failure mode is silent: if they drift, `web --mgmt` filters
  everything away and reports "no management devices", which reads like good
  news rather than a bug.

### Removed

- `wheel`/`sdist` builds and the PyPI publish step. Both carry `src/` verbatim,
  so distributing them hands out the source; only the standalone binaries are
  released now. Worth noting the PyPI job was armed — the environment existed
  and it ran on every `v*` tag — and had only ever failed because Trusted
  Publishing was not configured.

## [Unreleased]

### Planned

- PyPI release and `uvx`/`pipx` install.
- Homebrew formula.

## [0.10.0] — 2026-07-31

Second audit pass. The theme is the same as 0.9.0 and worth stating plainly:
**a check that cannot run is more dangerous than a check that fails**, because
it reports success. Three of the fixes below are cases where `systop` counted a
check as "run" while it had produced no data at all.

Cross-platform parity is now explicit: every parser added here is exercised
against real macOS, Linux **and** Windows command output in the test suite.

### Fixed

- **`doctor`'s exposure check was dead code on macOS.** `psutil.net_connections()`
  raises `AccessDenied` for every non-root uid on macOS (structural — `_psosx.py`
  walks all pids). `list_connections` swallowed it and returned `[]`, so the whole
  `RISKY_LISTENERS` table — Docker API on 2375, Redis, telnet, MongoDB, VNC —
  **never fired**, while `checks_run` still incremented and `skipped` stayed empty.
  Verified end to end: with a socket bound to `0.0.0.0:6379` the old path found
  nothing; the new one reports `high — Redis is exposed to the whole network`.
  Added `scan_connections() -> ConnScan(conns, permitted, source)` with a pure
  `parse_netstat_listeners()` fallback. When neither source works the check is
  no longer counted, and an INFO finding says so out loud.
  `lsof` was rejected as the fallback: measured, it misses root-owned listeners
  (8021, 43434) — exactly the services this table targets.
- **`doctor` reported healthy corporate networks as broken DNS.** Nothing ever
  asked the machine which resolvers it uses; only 8.8.8.8/1.1.1.1/9.9.9.9/
  208.67.222.222 were probed, so a network that deliberately blocks egress
  UDP/53 produced `high — All DNS servers are unresponsive`, **exit 2 on a
  working network, with the wrong remediation**. `--resolvers` and the config
  key `dns_resolvers` were dead code.
  Added `system_resolvers()` plus pure parsers for all three platforms, and
  `evaluate_dns` now keys severity on whether a resolver is the system's own:
  system resolver dead → `high`; system fine but public blocked → `info`.
- **`routes` hid every RA-derived IPv6 default gateway.** `routable_defaults`
  dropped *all* link-local next-hops to silence macOS's `fe80::%utunN`
  placeholders — but in a normal IPv6 network the router advertises its
  link-local address as the default gateway, so an IPv6-only host got a false
  `critical — No default route`. Now the discriminator is a **zero
  interface-ID**, not link-local-ness. `routable_default_gateways` also
  zone-qualifies (`fe80::1` + `dev eth0` → `fe80::1%eth0`); Linux prints these
  un-zoned and an un-zoned link-local ping always reports dead.
- **SNTP accepted forged and malformed packets.** The socket was never
  `connect()`ed, so any stray datagram landing on the ephemeral port was read as
  the server's reply; the request carried an all-zero originate timestamp, so
  there was nothing to correlate against. A well-formed **stratum-0
  Kiss-of-Death** packet was reported as `severity='ok'` — silent false
  reassurance in the exact AD/Kerberos scenario this module exists for.
  Now: `connect()` + `sendall`, an 8-byte `secrets` nonce echoed in the
  originate field, rejection of `mode != 4`, `LI == 3`, stratum 0 (kiss code
  decoded) and stratum > 15, a `T2 or T3` zero guard (was `and`), the RFC 4330
  era rule so post-2036 timestamps stop yielding ±2e9 s offsets, and a
  causality envelope applied to the **raw** delay before `max(delay, 0)` clamps
  it — the clamp was hiding impossible measurements as perfect ones.
  Verified the envelope still reports a genuine 56-year dead-RTC skew.
- **`doctor` scanned itself and double-counted facts.** Stage 7b fed this host's
  own `fe80::…%en0` addresses back in as "other devices to secure"; duplicate
  MACs were reported by both the LAN stage and `arpwatch`; a dead gateway was
  reported by both the ping stage and the route stage.
- **`arpwatch` flagged this host's own interfaces forever.** On macOS `awdl0`
  and `llw0` share one MAC and one `fe80::` address, differing only by zone —
  reported as duplicate-MAC on every run, so the spoofing detector permanently
  accused itself. Own NICs are now excluded, address scopes (`ipv4`/`ipv6`/
  `link-local`/`apipa`) are compared separately, and dedup strips the zone.
- A corrupt baseline file now returns empty instead of escaping as an unhandled
  `UnicodeDecodeError`. `errors="replace"` was deliberately **not** used: it
  parses the corruption into `hosts={"10.0.0.1": "��"}` and
  manufactures a `high` "ARP spoofing (MITM)" alert out of a bad disk.
- `_to_dict` now detects serialisable properties automatically instead of using
  a hand-maintained allowlist — 38 properties were silently missing from
  `--json`/`--csv`. `doctor`'s exit code is now computed once and shared, so
  table, JSON and CSV can no longer disagree on the same network.

### Added

- Offline test coverage for the five modules that had **zero**: `routes`, `ntp`,
  `dhcp`, `arpwatch` (and `mtu`). Every fix above is pinned by a regression test
  named after the false positive it prevents.
- `netstat` listener parsing for macOS/BSD, Linux and Windows in one function,
  with a test asserting all three produce the identical result set — the tool's
  conclusion must not depend on the OS it runs on.

### Changed

- `evaluate_routes` is evaluated per address family, and the IPv6 pass only runs
  when the host actually has a global IPv6 address — a missing IPv6 default on
  an IPv4-only LAN is normal, not a finding.
- DNS slowness is measured against the system resolver when one is known;
  a distant public resolver at 900 ms is expected, the local one at 900 ms is not.

## [0.9.0] — 2026-07-31

Four defects found during a systematic audit, each reproduced independently before
being fixed. Three of them made a documented capability quietly untrue.

### Fixed

- **`scan -6` and `nc -6` silently ran over IPv4.** `_resolve` accepted
  IPv4-mapped addresses (`::ffff:104.16.132.229`) as genuine IPv6, so on a host
  without a global IPv6 route the tool reported success while every packet went
  over IPv4 — the "IPv6 supported" claim was false in exactly the case where it
  mattered. IPv4-mapped results are now rejected when IPv6 is explicitly
  requested, with an error that names the real cause; `auto` mode still honours
  whatever the OS picks.
- **IPv6 zone identifiers were stripped**, turning `fe80::1%en0` into `fe80::1`.
  A link-local address cannot be used without its zone, so every link-local port
  was reported CLOSED. The zone is now recovered from the `scope_id` that
  `getaddrinfo` returns separately from the address string.
- **The routing-table parser silently discarded 75 of 93 lines** (and 46 of 46
  IPv6 lines). The regex assumed the line ended after the interface column, but
  `netstat -rn` has a trailing *Expire* column that may hold a number, `!`, or
  nothing. Replaced with column splitting, which is robust to that; link-layer
  entries (`link#11`, MAC addresses) are now correctly reported as having no
  next-hop rather than being parsed as gateways.
- **Path-MTU detection could never report "too big" on macOS.** `run_command`
  sent stderr to `DEVNULL`, and macOS `ping` writes *"Message too long"* there —
  so an oversized packet looked identical to no reply. `run_command` gained
  `include_stderr`, which `mtu` now uses. Verified: 1472 bytes → `ok`,
  1500 bytes → `too_big`.
- **`doctor` blamed you for a neighbour's open port.** The IPv6 exposure stage
  fed remote hosts into the local-listener evaluator, producing "your service is
  exposed — bind it to localhost" for a device you do not control. Remote
  findings now go through `evaluate_remote_exposure`, which names the affected
  addresses, lowers the severity by one level, and advises VLAN/ACL segmentation
  instead of editing your own bind address.

### Added

- **Local (IX) vs international speed comparison**: `speed --local` /
  `speed --local-url URL`, backed by a `speed_local_urls` config key. Many
  countries meter exchange-local traffic differently from international transit
  (TAS-IX in Uzbekistan, KazIX, MSK-IX, …), so full local speed with throttled
  international speed is a *tariff*, not a fault — and the two cannot be told
  apart without measuring both. Endpoints are deliberately **not** hardcoded:
  they differ per country, and baking one country's exchange into the tool would
  make it wrong everywhere else.

## [0.8.0] — 2026-07-30

Thresholds that adapt to the network instead of assuming one.

### Added

- **Adaptive thresholds by link type.** `doctor` now detects whether it is on
  wired, Wi-Fi, cellular or VPN and picks limits to match, reporting the choice
  as `link_type`. One absolute number cannot be right everywhere: 50 ms to the
  gateway is a disaster on wired (normal is under 2 ms), unremarkable on Wi-Fi,
  good on LTE and excellent on satellite. Wi-Fi is identified by association
  state rather than interface name, because on macOS the Wi-Fi interface is also
  called `en0`. Anything set explicitly in config still wins over the profile,
  and an unrecognised link gets the lenient profile — a strict default on an
  unknown network only produces noise.
- **IPv6 reachability, not just presence.** `doctor` pings the IPv6 gateway and
  an IPv6 internet target, so a dual-stack network whose IPv6 path is broken is
  caught. That failure is invisible while IPv4 still works, and it is a common
  cause of "some sites are slow" — applications try IPv6 first and wait for the
  timeout.
- `netinfo.default_gateway_v6()`.

### Fixed

- The new IPv6 reachability check initially fired on networks with **no global
  IPv6 at all**, where a failed IPv6 ping is the expected outcome and is already
  covered by the "link-local only" finding. It now runs only when the host
  actually holds a global IPv6 address.

## [0.7.0] — 2026-07-30

Radio and link-layer diagnostics — the layer beneath "the internet is slow".

### Added

- **`systop wifi`** and a new `core/wifi.py`: signal, noise, SNR, channel, width,
  PHY mode, negotiated rate, security, country, and the surrounding networks.
  No root on any platform — macOS uses `system_profiler SPAirPortDataType`
  (`wdutil` needs sudo and `airport -I` was removed in macOS 14.4, so neither is
  used), Linux `iw dev link`, Windows `netsh wlan show interfaces`.
- **Wi-Fi problem detection in `doctor`**: weak signal, low SNR, sitting on
  2.4 GHz while 5 GHz is in range, PHY below what the card supports, 2.4 GHz
  channel congestion, a non-1/6/11 channel, WEP or open security, and a narrow
  5 GHz channel. Channel congestion accounts for the fact that 2.4 GHz channels
  physically overlap (±4, and ±8 for a 40 MHz neighbour), which is why only
  1/6/11 are non-overlapping.
- **Link-speed detection**: a gigabit-capable port negotiated at 100 or 10 Mbps
  is reported as a probable cable, connector or duplex fault. This is the classic
  invisible failure — everything works, just ten times slower.

### Fixed

- Duplicate-MAC detection counted **broadcast and multicast** addresses as
  devices, so `ff:ff:ff:ff:ff:ff` (and `01:00:5e:…`, `33:33:…`) were reported as
  a device holding several IPs. Added `is_real_device_mac()`, which checks the
  I/G bit, and applied it in both `diagnose.evaluate_lan` and `arpwatch`.

### Notes

Wi-Fi checks return nothing at all when there is no Wi-Fi hardware or no
association — a wired server must never be told it has a Wi-Fi problem. Virtual
interfaces (`utun*`, `awdl0`, `llw0`, `bridge*`, `veth*`, `docker*`) are excluded
from link-speed checks for the same reason.

## [0.6.1] — 2026-07-30

### Added

- **Gateway now shows its prefix** — `10.171.7.3/24` instead of `10.171.7.3`,
  in both the TUI status bar and `systop info`. The prefix is the fastest way to
  read network size at a glance: `/24` means 254 hosts, `/23` means 510 — which
  directly sets scan scope and DHCP pool expectations.
- `Interface.prefixlen` and `Interface.host_count` (usable network size, with
  network and broadcast excluded; `/31` correctly yields 0 rather than a
  negative number).
- `systop info` now shows the network as `10.171.7.0/24 · 254` and adds an IPv6
  column carrying **global addresses only** — link-local exists on nearly every
  interface and would be pure noise in that table.

## [0.6.0] — 2026-07-30

Five new problem classes systop could not see before, and dual-stack throughout.

### Added

- **`ntp`** — clock-skew detection over SNTP (UDP/123, no root). Queries several
  servers and uses the **median**, so one lying server cannot skew the verdict.
  Matters because skew fails silently: Kerberos/AD rejects auth past 300 s, TLS
  certificates look "expired", TOTP codes are refused, and logs stop lining up
  across hosts — none of which says "time" anywhere in the error.
- **`route`** — routing table plus next-hop reachability. Detects no default
  route, several default routes (the "works sometimes" symptom), a dead
  gateway, and the VPN `0.0.0.0/1 + 128.0.0.0/1` catch-all. Link-local
  next-hops are excluded from the verdict — macOS always carries several
  `utun*` interfaces whose `fe80::` defaults never answer, and counting them
  would report a healthy Mac as broken.
- **`mtu`** — path MTU discovery by binary-searching DF-bit ping sizes. Finds
  the PMTUD black hole behind VPN/PPPoE/GRE, where ping and SSH work but pages
  hang half-loaded. Recognises common tunnel MTUs by value.
- **`dhcp`** — DHCP server discovery. Reads the **active lease** (macOS
  `ipconfig getpacket`, Linux dhclient leases, Windows `ipconfig /all`) — this
  path always works without root and answers "which server configured me?".
  A broadcast DISCOVER probe is also sent from an ephemeral port; when nothing
  answers the result is marked `partial`, because a strict RFC 2131 server
  replies only to port 68, which needs root to bind. Absence of a reply is
  never reported as absence of a server.
- **`arpwatch`** — ARP/NDP baseline diff over time. A single snapshot cannot
  show ARP spoofing: the table looks correct, only the MAC changed. Persists a
  baseline and reports MAC-changed-for-IP, duplicate MAC, new and disappeared
  hosts, with vendor names ("Hikvision → Apple" is far more legible than two
  hex strings).
- **Dual-stack interfaces** — `Interface` now carries IPv6 addresses with
  prefixes and exposes `ipv6_global`, `ipv6_link_local`, `ipv6_cidrs` and
  `has_dual_stack`. Interfaces with IPv6 but no IPv4 are no longer skipped,
  so an IPv6-only network is visible at all.
- **Multi-interface LAN discovery** — `discover_lan(all_interfaces=True)` and
  `lan_cidrs()` sweep every active interface's subnet instead of only the
  primary one; with Wi-Fi, Ethernet and VPN connected at once, scanning one and
  concluding "that's the network" is wrong.
- **`scan --lan` / `scan --lan6`** — take targets from discovery. IPv6 cannot be
  swept (2^64 addresses in a /64), so `--lan6` scans the exact addresses found
  in the neighbour table. This is how "are any IPv6 ports open?" gets answered.
- **`doctor` now runs 13 checks** including all of the above plus IPv6 port
  exposure, and reports what it had to skip.

### Fixed

- ARP-watch duplicate-MAC detection compared across address families, so every
  dual-stack device (one IPv4 + one IPv6 address, same MAC) was flagged as a
  duplicate — 34 false positives on a normal LAN. Comparison is now per family.

## [0.5.1] — 2026-07-30

Three defects found by looking at the running TUI, plus subnet scanning there.

### Fixed

- **MAC addresses and IPv6 addresses were corrupted on screen.** A MAC of
  `62:46:3c:ab:d1:1a` rendered as `62:46:3c🆎d1:1a` — Rich treats `:ab:` as the
  emoji shortcode for 🆎. The CLI was safe (`Console(emoji=False)`) but the
  Textual TUI renders through its own pipeline where substitution is on, so the
  MAC a sysadmin read off the screen was **not the real MAC**. Ten shortcodes
  are hex-only and therefore reachable from address text: `:a:`→🅰, `:b:`→🅱,
  `:ab:`→🆎, `:cd:`→💿, `:abc:`→🔤, `:abcd:`→🔡, `:bed:`→🛏, `:bee:`→🐝,
  `:100:`→💯, `:1234:`→🔢 — IPv6 is affected more than MAC. Added `data_cell()`,
  which wraps data in `rich.text.Text` so it is never parsed as markup or
  emoji, and applied it to every MAC / IP / hostname / address / service cell in
  the TUI. A test asserts the hex-only shortcode set, so a future Rich release
  adding one (e.g. `:dead:`) fails the suite instead of silently corrupting output.
- **Traceroute returned no hops at all on macOS** ("Route not detected" in the
  TUI) while ping to the same host worked. Cause: changing TTL needs a **raw**
  socket, so `icmplib.traceroute(privileged=False)` raises
  `SocketPermissionError`; ping only needs a datagram socket, which is why one
  worked and the other did not. Now falls back to the system `traceroute` /
  `traceroute6` binary, which ships setuid-root on macOS and with `CAP_NET_RAW`
  on Linux — still no sudo required. Applies to `trace`, `mtr` and the TUI.
- An offline test began reaching the real network once the fallback existed; it
  now mocks both probe paths.

### Added

- **Subnet scanning in the TUI Port scan tab** — the input accepts CIDR and
  ranges (`10.0.0.0/24`, `10.0.0.1-50`), matching the CLI. One host keeps the
  per-port view; several switch the table to a per-host summary.

## [0.5.0] — 2026-07-30

nmap/ncat-style capabilities, and IPv6 audited across every command.

### Added

- **LAN-wide port scanning** (nmap `-sT` equivalent). `scan` now takes any
  number of targets in CIDR, range or list form — `scan 10.0.0.0/24`,
  `scan 10.0.0.1-50`, `scan a.example b.example`. One host still prints the
  detailed port table; several print a per-host sweep summary.
- **`--top N`** — scan the N most common ports (nmap `--top-ports` idea), and
  `--open-only` to hide hosts with nothing open.
- **Banner grabbing / service versions** (`--banner`, nmap `-sV` lite). Reads
  the service greeting where one is sent (SSH, SMTP, FTP, POP3, IMAP, MySQL,
  Redis) and probes HTTP otherwise. **TLS ports are handshaked first** —
  sending plaintext HTTP to 443 only ever returns "400 Bad Request", so ports
  443/465/993/995/4081/8006/8443/9443/2376 negotiate TLS before probing.
- **`systop nc`** — ncat-style raw TCP/TLS client for hand-checking a service:
  `--send` with `\r\n`/`\t`/`\xNN` escapes, `--tls` (reports version, cipher
  and certificate SHA-256 fingerprint), `--hex` hexdump, and automatic hexdump
  for binary replies. Client only — no listen mode, nothing requiring root.
- **AAAA records in `dns`.** `getaddrinfo` hides AAAA entirely when the host has
  no global IPv6 route (RFC 6724 address selection), returning IPv4-mapped
  `::ffff:` forms instead. A diagnostic tool must report what DNS *says*, so
  real AAAA records are now queried directly via dig/nslookup, in parallel with
  the resolver comparison, and IPv4-mapped addresses are filtered out of the A
  list where they were misleading.
- 63 new offline tests (535 total).

### Fixed

- **Banner grabbing silently returned nothing for every HTTP port.** The Host
  header was built with `host.encode("idna", "ignore")`, but the `idna` codec
  does not accept an `errors` argument — it raised `UnicodeError`, which the
  broad `except` swallowed. Now plain ASCII, which is all a Host header needs.
- `--json`/`--format csv` crashed on `nc` output: `bytes` is not JSON
  serialisable. `_to_dict` now decodes bytes, and the computed properties
  `received_text`, `received_bytes_count`, `is_binary`, `total_open` are
  serialised.

### Notes on scope

Honest limits, all of them consequences of the no-root design: SYN/stealth scan
(`-sS`), OS fingerprinting (`-O`), reliable UDP scanning and NSE scripting need
raw sockets or privileges and are **not** provided. `trace` over IPv6 also needs
root on macOS — ICMPv6 datagram sockets are privileged there, unlike ICMPv4.

## [0.4.0] — 2026-07-30

Two new commands (`web`, `doctor`) and full IPv6 support. The tool moves from
"reports measurements" to "tells you what is broken".

### Added

- **`systop doctor`** — automatic network problem finder. Runs interface, ping,
  DNS, listening-service, LAN and web checks, then reports **severity-ranked
  findings** with a concrete fix for each, instead of raw numbers. Exit code 2
  when a critical/high problem is found, so it drops into monitoring. Flags:
  `--quick`, `--no-web`, `--tls host1,host2`, `--max-hosts`.
- **`systop web`** — web-service and **admin-panel discovery** across the LAN.
  Fingerprints ~33 products (Kerio Control, Hikvision, Dahua, UniFi, MikroTik,
  Proxmox, Grafana, Portainer, Synology, pfSense, printers, …), classifies each
  as a management device or not, and rates risk. `--http80` is a shortcut for
  "which hosts have plain HTTP open", `--mgmt` filters to network-management
  devices only, `--admin-only` to admin panels, `--polite` for IPS-guarded
  networks.
- **`core/webscan.py`** — HTTP fingerprinting with a pure `classify()` function
  (offline-testable) separated from the network probe.
- **`core/diagnose.py`** — severity model (`critical`…`info`), `Thresholds`
  dataclass, and pure `evaluate_*` functions per check, plus a
  `run_diagnostics()` orchestrator where every stage is independently guarded
  so one failing check cannot abort the report.
- **IPv6 support across the tool:**
  - `scan -4/-6` — force address family; reports which family was actually used
    and gives a specific error when a host has no A/AAAA record.
  - `lan -6`, `lan --only-ipv6`, `lan --global-only` — IPv6 host discovery via
    `ff02::1` all-nodes multicast plus the OS neighbour table (`ip -6 neigh`,
    `ndp -an`, `netsh`). A /64 cannot be ping-swept, so this is the correct
    mechanism rather than an address sweep.
  - `LanHost.family` / `.source` / `.is_link_local`, `ports.family_of()`.
- 93 new offline tests (481 total).

### Fixed

- **LAN table showed an empty MAC and Vendor column for every host.** Two
  independent causes, both silent: (1) `arp -a` performs a reverse-DNS lookup
  per entry and took **5.2 s** on a /23 with ~280 neighbours, exceeding the
  3 s subprocess timeout — the parser then fell through to `ip neigh` (absent
  on macOS) and returned an empty table; switched to `arp -an` (numeric, 9 ms)
  and raised the timeout. (2) macOS emits unpadded MAC octets
  (`0:15:5d:27:40:3`), which never match the OUI table — added `_normalize_mac`,
  shared with the IPv6 neighbour parser.
- Added virtual-NIC OUIs (Hyper-V, VirtualBox, QEMU/KVM, Xen, Parallels,
  VMware, Docker). On a virtualised LAN this is the difference between "unknown
  device" and "Hyper-V VM" — the single most useful vendor class for a sysadmin.
- `_to_dict` now serialises computed properties `url`, `risk`, `is_link_local`,
  `is_problem`, `worst_severity`, `counts` — previously a new dataclass property
  was silently missing from `--json`/`--format csv` output.
- Admin-panel detection no longer flags plain web servers: product fingerprints
  are split into `admin` and `infra` classes, and an `infra` match (nginx,
  Apache, Caddy, Traefik) contributes identification but **zero** admin score.
  Without this a default nginx welcome page was reported as an admin panel.
- Product fingerprint tokens tightened so short fragments cannot false-match
  inside unrelated words (`hass` in "chassis", bare `docker`, `syno`).

### Changed

- `lan` accepts flags, so it is no longer dispatched as a no-argument command.
- `web`/`doctor` default to low concurrency (16) with an optional `--polite`
  mode (4 concurrent, 300 ms delay). Rapid wide scans trip IPS/anti-scan
  protection and get the scanning host temporarily blocked — the symptom is
  misleading (ICMP works, every new TCP connection is refused).

## [0.3.3] — 2026-06-10

Dashboard idle-state redesign.

### Changed

- **Speed panel is content-fit** (`height: auto`) instead of stretching to half
  the column — the freed space goes to the ping panel, so the idle dashboard no
  longer has a ~70% empty speed panel.
- **Empty sparklines are hidden until there's data** (speed + ping): no more
  "fake" full green graph before a test has run; the ping graph now sits directly
  under its table instead of detaching to the panel bottom.
- **Status bar shows real chips** — gateway / public IP / interface are compact
  and grouped left (`width: auto` + panel background) instead of stretched across
  the full width with `1fr`.
- **Compact speed button** (`width: auto`) and **panel key hints** in the border
  subtitle (`s start` / `r refresh` / `l LAN scan`).
- **Richer empty states** — centered glyph + title + "what to expect" hint
  (e.g. the LAN tab explains the `/24` ping-sweep + ARP it will run).
- **CLI output redesigned to match the TUI design language** (audit C-1/C-2,
  M-1…M-3): one light-chrome table helper (`_render.styled_table`, horizontal
  rules only — no heavy box/vertical bars, left-aligned title); symbols come from
  `glyph()` (no emoji — fixes mojibake and makes `--no-color`/`NO_COLOR` truly
  monochrome via `Console(emoji=False)`); the same `alive`/`dead` lexicon and
  RTT/loss color gradation as the TUI; a dim summary line under each result
  (e.g. `4 targets — 3 alive · 1 dead`). `--json`/`--format csv` output and exit
  codes are unchanged.

## [0.3.2] — 2026-06-10

Windows correctness overhaul — the localized-Windows ping/render defects.

### Fixed

- **Ping reported 100% loss on non-English Windows.** Root cause: the Windows
  path parsed `ping.exe` text, but on Russian Windows (codepage 866, `время=…мс`)
  the RTT regex never matched → every target looked dead even with working
  internet. Windows ICMP now uses the **Win32 `IcmpSendEcho` API** (`iphlpapi.dll`
  via ctypes) — locale- and codepage-independent, structured, no Administrator,
  no flashing console window. Traceroute uses `IcmpSendEcho` with increasing TTL.
- **Mojibake in the TUI / route/ARP parsing on Windows.** The console output
  codepage is now set to UTF-8 (`SetConsoleOutputCP(65001)` + VT processing) at
  startup; subprocess output (route/arp/ip-neigh) is decoded with the actual OEM
  codepage instead of assuming UTF-8.
- **ASCII fallback** for legacy consoles that can't render Unicode block/braille
  glyphs (`unicode_ok()` gate): sparklines hide, emoji/box-drawing degrade to
  ASCII — the dashboard stays readable.
- **APIPA interface selection** — `primary_interface()` now skips `169.254.x`
  link-local / virtual NICs and prefers the gateway's interface.
- **POSIX `LANG=C` safety** — stdout/stderr are hardened so non-ASCII output
  (Uzbek text, JSON) never raises `UnicodeEncodeError`.
- Upload phase no longer looks "stuck": warm-up shows a "preparing" state.

### Added

- CI: locale matrix (C/ascii, ru_RU, de_DE) + a `windows-latest` live smoke job
  (`ping --json --targets 127.0.0.1` must be alive — catches the regression).

## [0.3.1] — 2026-06-08

### Fixed

- **Windows console encoding.** CLI output (emoji/Unicode) no longer crashes
  with `UnicodeEncodeError` on legacy Windows consoles (cp1252): stdout/stderr
  are reconfigured to UTF-8 with `errors="replace"`. Verified on Windows Server 2022.

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
