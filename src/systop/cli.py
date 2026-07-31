"""systop CLI — opens the dashboard by default.

There are also quick (one-shot, script-friendly) commands:
    systop              -> interactive dashboard (TUI)
    systop dashboard    -> the same thing
    systop speed        -> speed test, printed as a table
    systop ping         -> local + global ping (--ipv6, --watch)
    systop trace HOST   -> traceroute
    systop mtr HOST     -> live mtr-style traceroute (Ctrl+C stops it)
    systop lan          -> LAN host discovery (with vendor)
    systop scan TARGET  -> TCP port scanner (host / CIDR / range, --top, --banner)
    systop nc HOST PORT -> raw TCP/TLS connection (ncat style)
    systop dns NAME     -> DNS resolve + resolver latency comparison
    systop bw           -> per-interface bandwidth (--watch for live)
    systop tls HOST     -> TLS certificate check (expiry, issuer, SAN)
    systop http URL     -> HTTP status check (status, redirects, timing)
    systop conn         -> active network connections (--listen for LISTEN only)
    systop web          -> web services + management panels (--http80, --mgmt)
    systop doctor       -> find network problems automatically (by severity)
    systop ntp          -> clock skew check — SNTP
    systop route        -> routing table + next-hop reachability
    systop mtu [HOST]   -> path MTU discovery (DF-ping, binary search)
    systop dhcp         -> detect DHCP server(s) (rogue DHCP)
    systop arpwatch     -> ARP/NDP changes (MAC swap, duplicate)
    systop wifi         -> Wi-Fi signal/SNR/channel (--neighbours for neighbours)
    systop config       -> current configuration / file path
    systop info         -> interfaces, gateway, public IP

Global flags for scripts:
    --json / --format {table,json,csv}   machine-readable output (clean stdout)
    -q/--quiet, -v/--verbose             verbosity level
    --no-color                           no colours (NO_COLOR env is honoured too)

Exit codes (so scripts can tell them apart):
    0  success
    1  general error (bad argument, internal error)
    2  target unreachable / host dead / port closed /
       certificate expired or expiring soon / resolve failed
"""

from __future__ import annotations

# PYTHON_ARGCOMPLETE_OK
import argparse
import asyncio
import csv as _csv
import dataclasses
import io
import json
import os
import sys
from collections.abc import Iterable
from typing import Any

from rich.console import Console
from rich.table import Table

from systop import __version__
from systop._render import (
    ERROR,
    SECONDARY,
    SUCCESS,
    WARNING,
    alive_cell,
    loss_cell,
    rtt_cell,
    styled_table,
)
from systop.core import _platform
from systop.widgets._glyphs import dash, data_cell, glyph

# Exit codes — meaningful, for scripts.
EXIT_OK = 0
EXIT_ERROR = 1  # general error
EXIT_UNREACHABLE = 2  # target unreachable / dead / expired

# The severity at which `doctor` counts as "failed" (same for table/JSON/CSV).
DOCTOR_FAIL_CRITICAL = "critical"
DOCTOR_FAIL_HIGH = "high"

# Global output format (set by main()).
_FORMAT = "table"  # table | json | csv
_QUIET = False
_VERBOSE = False


def _stream_encoding_is_safe(stream: object) -> bool:
    """Does the stream encoding safely accept Unicode (at least UTF) output?

    On POSIX under `LANG=C`/`LC_ALL=C` stdout ends up on the `ascii` codec — any
    non-ASCII character, in the rendered text or in the JSON, raises
    `UnicodeEncodeError`. The test for that case: if the encoding name does not
    start with `utf` (ascii/ANSI_X3.4/POSIX/C) it is not safe.
    """
    enc = getattr(stream, "encoding", None)
    if not enc:
        # Encoding unknown (redirected / unusual stream) — we play it safe.
        return False
    return enc.lower().replace("-", "").startswith("utf")


def _harden_console_streams() -> None:
    """Makes stdout/stderr survive non-ASCII output instead of crashing.

    Covers two cases:

    * **Windows** — the legacy console sits on an OEM/cp1252 codepage; emoji and
      Unicode raise `UnicodeEncodeError`.
    * **POSIX C/ASCII locale** (`LANG=C`) — stdout is on the `ascii` codec; any
      non-ASCII character, in the rendered text or in the JSON, kills it too.

    In both cases we switch to UTF-8 with `errors="replace"`: on a terminal that
    cannot display the character it degrades to `?`/`\\ufffd`, but an exception is
    never raised (the CLI stays script-friendly). A stream that is already UTF is
    left alone (the usual macOS/Linux case does not change).
    """
    for stream in (sys.stdout, sys.stderr):
        if _stream_encoding_is_safe(stream):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            # No reconfigure (older Python / wrapped stream) — carry on quietly;
            # the emit_json/print paths below do errors="replace" anyway.
            pass


# Windows console (UTF-8 + VT) — via `_platform.init_console`; then we make the
# streams ASCII-safe on every platform (the POSIX C locale included).
_platform.init_console()
_harden_console_streams()

# Emoji are NEVER rendered (by design: symbols only via `glyph()`, monochrome).
# `--no-color`/`NO_COLOR` must be truly monochrome — `_apply_color` rebuilds it.
console = Console(emoji=False)


# --------------------------------------------------------------------------- #
# Output control: Rich/status output is shown only in "table" mode.
# In json/csv mode pure machine-readable output goes to stdout, no status.
# --------------------------------------------------------------------------- #


def _is_machine() -> bool:
    """Is the JSON or CSV (machine-readable) mode active?"""
    return _FORMAT in ("json", "csv")


class _NullStatus:
    """No-op stand-in for `console.status` (machine/quiet mode)."""

    def __enter__(self) -> _NullStatus:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def status(message: str) -> Any:
    """Shows a live status only in table mode (and only when not quiet)."""
    if _is_machine() or _QUIET:
        return _NullStatus()
    return console.status(message)


def emit_table(table: Table) -> None:
    """Rich table — printed only in table mode."""
    if not _is_machine():
        console.print(table)


def note(message: str) -> None:
    """Extra note (in table mode, when not quiet)."""
    if not _is_machine() and not _QUIET:
        console.print(message)


def verbose(message: str) -> None:
    """Detailed message, printed only with -v and only in table mode."""
    if _VERBOSE and not _is_machine():
        console.print(f"[dim]{message}[/]")


def _safe_write(stream: Any, text: str) -> None:
    """Writes text to a stream; never crashes, not even in an ASCII locale.

    On a stream where `reconfigure` failed (wrapped / older Python) a
    `UnicodeEncodeError` is still possible — there we re-encode to the stream's
    own encoding with `errors="replace"` and write to its `buffer`. This is the
    last line of defence for emit_json/error (POSIX `LANG=C`).
    """
    try:
        stream.write(text)
    except UnicodeEncodeError:
        enc = getattr(stream, "encoding", None) or "utf-8"
        data = text.encode(enc, errors="replace")
        buffer = getattr(stream, "buffer", None)
        if buffer is not None:
            buffer.write(data)
            buffer.flush()
        else:
            # No buffer (StringIO and friends) — rewrite with replacement chars.
            stream.write(data.decode(enc, errors="replace"))


def error(message: str) -> None:
    """Error message — goes to stderr in JSON/CSV mode too (stdout stays clean)."""
    if _is_machine():
        _safe_write(sys.stderr, message + "\n")
    else:
        console.print(f"[{ERROR}]Error:[/] {message}")


# --------------------------------------------------------------------------- #
# Serialisation: turning core dataclasses into dicts for JSON/CSV.
# Computed (property) fields do not appear in `asdict` — we add them by hand.
# Internal fields (those starting with _) are dropped.
# --------------------------------------------------------------------------- #


# Properties `_to_dict` must NOT add automatically: each is a filtered copy of a
# primary field, so including it doubles the payload for nothing.
_TO_DICT_SKIP: frozenset[str] = frozenset(
    {
        "problems",  # a subset of Report.findings
        "open_ports",  # a subset of ScanResult.ports
        "responsive",  # a subset of SweepResult.hosts
        "defaults",  # a subset of RouteTable.routes
        "routable_defaults",
        "responded",  # a subset of NtpReport.results
        "mac_changes",  # a subset of ArpDiff.changes
        "neighbours",  # WifiStatus.neighbours — already present as a field
    }
)


def _to_dict(obj: Any) -> Any:
    """Turns a dataclass into a cleaned-up dict (properties included).

    - Internal fields starting with `_` are dropped.
    - The computed properties that belong to the dataclass are added
      (loss_pct, cidr, total_bps, ...), so the JSON comes out complete.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            if f.name.startswith("_"):
                continue
            out[f.name] = _to_dict(getattr(obj, f.name))
        # Computed properties are added AUTOMATICALLY.
        #
        # This used to be a hand-written list, and every new dataclass property
        # silently fell out of `--json`/`--format csv` — an audit turned up 38
        # missing fields (`Interface.ipv6_global`, `WifiStatus.snr_db`,
        # `MtuResult.is_reduced` and so on). Maintaining the list did not work,
        # because forgetting it fails SILENTLY.
        #
        # Only SCALAR values and lists of scalars are taken: nested objects blew
        # the payload up several times over and stuffed an entire JSON blob into
        # one CSV cell. The filtered views (`problems`, `open_ports`, ...) are
        # dropped deliberately — they are copies of a primary field.
        for prop in dir(type(obj)):
            if prop.startswith("_") or prop in _TO_DICT_SKIP or prop in out:
                continue
            attr = getattr(type(obj), prop, None)
            if not isinstance(attr, property):
                continue
            try:
                value = getattr(obj, prop)
            except Exception:  # noqa: BLE001 — if computing the property raises
                # Do not drop it silently: make the missing field's cause visible.
                out[prop] = None
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                out[prop] = value
            elif isinstance(value, (list, tuple)) and all(
                isinstance(x, (str, int, float, bool)) for x in value
            ):
                out[prop] = list(value)
            elif isinstance(value, dict) and all(
                isinstance(x, (str, int, float, bool)) for x in value.values()
            ):
                out[prop] = dict(value)
        return out
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        # `json.dumps` cannot serialise bytes and dies with a TypeError — that is
        # exactly how `nc --json` broke. Convert to text; when the raw bytes
        # matter, the `received_bytes_count`/`is_binary` properties are there.
        return bytes(obj).decode("utf-8", errors="replace")
    return obj


def emit_json(payload: Any) -> None:
    """Writes the payload to stdout as pure JSON (json mode only).

    `ensure_ascii=False` keeps non-ASCII text readable. In an ASCII locale
    (`LANG=C`) those non-ASCII bytes used to be fatal; `_safe_write` is the last
    line of defence (it re-encodes with errors="replace").
    """
    _safe_write(sys.stdout, json.dumps(_to_dict(payload), ensure_ascii=False, indent=2) + "\n")


def emit_csv(rows: Iterable[Any]) -> None:
    """Writes a list of dataclasses/dicts to stdout as CSV (csv mode).

    Columns come from the keys of the first row; nested (list/dict) values are
    turned into JSON strings so the CSV stays flat.
    """
    dict_rows = [_flatten_for_csv(_to_dict(r)) for r in rows]
    if not dict_rows:
        # Empty result — signal the absence of a header and leave quietly.
        _safe_write(sys.stdout, "\n")
        return
    fieldnames: list[str] = []
    for row in dict_rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    buf = io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in dict_rows:
        writer.writerow(row)
    _safe_write(sys.stdout, buf.getvalue())


def _flatten_for_csv(d: Any) -> dict[str, Any]:
    """For CSV: turns nested list/dict values into JSON strings."""
    if not isinstance(d, dict):
        return {"value": d}
    flat: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, (list, dict)):
            flat[k] = json.dumps(v, ensure_ascii=False)
        elif v is None:
            flat[k] = ""
        else:
            flat[k] = v
    return flat


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def _add_global_flags(parser: argparse.ArgumentParser) -> None:
    """Adds the script-friendly global flags (everywhere)."""
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the result as pure JSON (not a Rich table)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default=None,
        help="output format: table (default), json or csv",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="less output (result only)")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="detailed output (diagnostics)"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="no colours (NO_COLOR is honoured too)"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="systop",
        description="A network TUI for sysadmins: speed, ping, topology.",
    )
    parser.add_argument("--version", action="version", version=f"systop {__version__}")
    _add_global_flags(parser)
    sub = parser.add_subparsers(dest="command")

    def _with_globals(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        _add_global_flags(p)
        return p

    _with_globals(sub.add_parser("dashboard", help="Interactive TUI dashboard (default)"))
    p_speed = _with_globals(sub.add_parser("speed", help="Measure the internet speed"))
    p_speed.add_argument(
        "--local",
        action="store_true",
        help="also measure local (IX) endpoints and compare with the international one",
    )
    p_speed.add_argument(
        "--local-url",
        action="append",
        default=None,
        metavar="URL",
        help="local endpoint URL (repeatable; overrides the config)",
    )

    p_ping = _with_globals(sub.add_parser("ping", help="Ping the local gateway + global servers"))
    p_ping.add_argument("--ipv6", action="store_true", help="include global IPv6 targets too")
    p_ping.add_argument(
        "--watch",
        action="store_true",
        help="continuous ping: live statistics every second (Ctrl+C stops it)",
    )
    p_ping.add_argument(
        "--targets",
        default=None,
        help="comma-separated targets (overrides the config)",
    )

    p_trace = _with_globals(sub.add_parser("trace", help="Traceroute (the path to a target)"))
    p_trace.add_argument("host", nargs="?", default="8.8.8.8", help="target (default 8.8.8.8)")
    p_trace.add_argument(
        "--continuous",
        action="store_true",
        help="live mtr style (identical to the mtr command)",
    )

    p_mtr = _with_globals(sub.add_parser("mtr", help="Live mtr-style traceroute"))
    p_mtr.add_argument("host", nargs="?", default="8.8.8.8", help="target (default 8.8.8.8)")
    p_mtr.add_argument(
        "--interval", type=float, default=1.0, help="probe interval (seconds, default 1.0)"
    )
    p_mtr.add_argument(
        "--cycles", type=int, default=None, help="how many probe rounds (default: unlimited)"
    )

    p_scan = _with_globals(sub.add_parser("scan", help="TCP port scanner (find exposed ports)"))
    p_scan.add_argument(
        "targets",
        nargs="*",
        help="host / CIDR / range: '10.0.0.5' '10.0.0.0/24' '10.0.0.1-50' 'example.com'",
    )
    p_scan.add_argument(
        "--ports",
        default=None,
        help="ports: '22,80,443' or '1-1024' (default: the common ones)",
    )
    p_scan.add_argument(
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="scan the N most common ports (nmap --top-ports style)",
    )
    p_scan.add_argument(
        "--banner",
        action="store_true",
        help="read the service version off open ports (a light nmap -sV)",
    )
    p_scan.add_argument(
        "--open-only", action="store_true", help="show only hosts that have an open port"
    )
    p_scan.add_argument(
        "--polite",
        action="store_true",
        help="slow mode (for networks with IPS/anti-scan protection)",
    )
    p_scan.add_argument(
        "--lan",
        action="store_true",
        help="take the targets from the LAN automatically (every active interface network)",
    )
    p_scan.add_argument(
        "--lan6",
        action="store_true",
        help="targets: the IPv6 hosts found via NDP (an IPv6 /64 cannot be swept)",
    )
    p_scan.add_argument(
        "--max-hosts",
        type=int,
        default=1024,
        help="maximum hosts to take from a CIDR/range (a safety limit)",
    )
    p_scan.add_argument("--timeout", type=float, default=1.5, help="timeout per port (seconds)")
    _add_family_flags(p_scan)

    # --- nc: an ncat-style raw TCP/TLS client -------------------------------
    p_nc = _with_globals(
        sub.add_parser("nc", help="Raw TCP/TLS connection (ncat style) — banner, manual request")
    )
    p_nc.add_argument("host", help="host (IP or name; IPv6 too)")
    p_nc.add_argument("port", type=int, help="port")
    p_nc.add_argument(
        "--send",
        default=None,
        metavar="TEXT",
        help=r"text to send; the \r\n \t \xNN sequences are honoured",
    )
    p_nc.add_argument(
        "--tls",
        action="store_true",
        help="connect with TLS (the certificate is not verified)",
    )
    p_nc.add_argument("--hex", action="store_true", help="show the reply as a hexdump")
    p_nc.add_argument("--timeout", type=float, default=5.0, help="connect timeout (seconds)")
    p_nc.add_argument(
        "--wait",
        type=float,
        default=None,
        metavar="SEC",
        help="how long to wait for the reply (default: same as timeout)",
    )
    _add_family_flags(p_nc)

    p_dns = _with_globals(sub.add_parser("dns", help="DNS resolve + resolver latency comparison"))
    p_dns.add_argument("name", help="the domain name to resolve")
    p_dns.add_argument(
        "--resolvers",
        default=None,
        help="comma-separated DNS servers (overrides the config)",
    )

    p_bw = _with_globals(sub.add_parser("bw", help="Per-interface bandwidth (RX/TX)"))
    p_bw.add_argument("--watch", action="store_true", help="live stream (Ctrl+C stops it)")
    p_bw.add_argument(
        "--interval", type=float, default=1.0, help="sample interval (seconds, default 1.0)"
    )

    p_tls = _with_globals(sub.add_parser("tls", help="TLS certificate check"))
    p_tls.add_argument("host", help="host or host:port (port 443 by default)")
    p_tls.add_argument("--timeout", type=float, default=5.0, help="connect timeout (seconds)")
    p_tls.add_argument(
        "--warn-days",
        type=int,
        default=14,
        help="exit nonzero when fewer days than this remain (default 14)",
    )

    p_http = _with_globals(sub.add_parser("http", help="HTTP status check"))
    p_http.add_argument("url", help="the URL to check (https://... or http://...)")
    p_http.add_argument("--timeout", type=float, default=5.0, help="request timeout (seconds)")

    p_conn = _with_globals(sub.add_parser("conn", help="Active network connections"))
    p_conn.add_argument(
        "--listen", action="store_true", help="show only the ones in the LISTEN state"
    )

    p_cfg = _with_globals(sub.add_parser("config", help="Current configuration / file path"))
    p_cfg.add_argument("--path", action="store_true", help="print only the configuration file path")
    p_cfg.add_argument("--show", action="store_true", help="show the current (effective) settings")

    p_lan = _with_globals(sub.add_parser("lan", help="Discover hosts on the local network"))
    p_lan.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help="find IPv6 hosts too (ff02::1 multicast + the NDP table)",
    )
    p_lan.add_argument("--only-ipv6", action="store_true", help="IPv6 only (no IPv4 sweep)")
    p_lan.add_argument(
        "--global-only",
        action="store_true",
        help="exclude link-local (fe80::) addresses from the IPv6 results",
    )

    # --- web: find management panels and web services ------------------------
    p_web = _with_globals(
        sub.add_parser("web", help="Find web services + management panels (LAN inventory)")
    )
    p_web.add_argument(
        "hosts",
        nargs="*",
        help="hosts to check; when empty the LAN is discovered automatically",
    )
    p_web.add_argument(
        "--ports",
        default=None,
        help="ports: '80' or '80,443,8080' (default: the common web ports)",
    )
    p_web.add_argument("--admin-only", action="store_true", help="show management panels only")
    p_web.add_argument(
        "--mgmt",
        action="store_true",
        help="only devices that run the network (router/firewall/switch/NVR)",
    )
    p_web.add_argument(
        "--http80",
        action="store_true",
        help="shortcut: check port 80 only (find local HTTP exposure)",
    )
    p_web.add_argument(
        "--polite",
        action="store_true",
        help="slow mode (for networks with IPS/anti-scan protection)",
    )
    p_web.add_argument("--timeout", type=float, default=4.0, help="timeout per request")
    p_web.add_argument("-6", "--ipv6", action="store_true", help="check IPv6 hosts too")

    # --- doctor: find network problems automatically -------------------------
    p_doc = _with_globals(
        sub.add_parser("doctor", help="Find network problems automatically (by severity)")
    )
    p_doc.add_argument(
        "--quick", action="store_true", help="fast mode (the web scan and IPv6 are skipped)"
    )
    p_doc.add_argument("--no-web", action="store_true", help="skip the web/admin panel check")
    p_doc.add_argument("--tls", default=None, help="hosts to check TLS on (comma-separated)")
    p_doc.add_argument("--max-hosts", type=int, default=64, help="maximum hosts on the LAN")

    p_ntp = _with_globals(sub.add_parser("ntp", help="Clock skew (NTP) check"))
    p_ntp.add_argument("--servers", default=None, help="NTP servers (comma-separated)")
    p_ntp.add_argument("--timeout", type=float, default=3.0)

    _with_globals(sub.add_parser("route", help="Routing table + next-hop reachability"))

    p_mtu = _with_globals(sub.add_parser("mtu", help="Path MTU discovery (DF-ping)"))
    p_mtu.add_argument("host", nargs="?", default="1.1.1.1", help="target (default 1.1.1.1)")
    p_mtu.add_argument("--low", type=int, default=1200)
    p_mtu.add_argument("--high", type=int, default=1500)

    p_dhcp = _with_globals(sub.add_parser("dhcp", help="Detect DHCP server(s)"))
    p_dhcp.add_argument(
        "--listen", type=float, default=4.0, help="how long to wait for a broadcast reply (s)"
    )

    p_arp = _with_globals(sub.add_parser("arpwatch", help="ARP/NDP changes (MAC swap, duplicate)"))
    p_arp.add_argument("--no-update", action="store_true", help="do not refresh the baseline")
    p_arp.add_argument("--reset", action="store_true", help="write the baseline from scratch")

    p_wifi = _with_globals(
        sub.add_parser("wifi", help="Wi-Fi state: signal, SNR, channel, neighbours")
    )
    p_wifi.add_argument(
        "--neighbours", action="store_true", help="also show the surrounding networks"
    )

    _with_globals(sub.add_parser("info", help="Network interfaces and public IP"))

    return parser


def _add_family_flags(p: argparse.ArgumentParser) -> None:
    """Adds the `-4`/`-6` address-family flags (mutually exclusive)."""
    g = p.add_mutually_exclusive_group()
    g.add_argument("-4", "--ipv4", action="store_true", help="IPv4 only (A record)")
    g.add_argument("-6", "--ipv6", action="store_true", help="IPv6 only (AAAA record)")


def _resolve_format(args: argparse.Namespace) -> str:
    """Works out the final format from --json and --format (they agree, --json is not king)."""
    if args.format:
        return args.format
    if args.json:
        return "json"
    return "table"


def _apply_color(no_color: bool) -> None:
    """Applies the colour setting: --no-color or the NO_COLOR env => no colours."""
    global console
    disabled = no_color or bool(os.environ.get("NO_COLOR"))
    # Emoji are always off (by design: symbols only via glyph()). In machine mode
    # or under --no-color/NO_COLOR the colours go too — genuinely monochrome.
    if disabled or _is_machine():
        console = Console(no_color=True, highlight=False, emoji=False)


def _split_csv_arg(value: str | None) -> list[str]:
    """'a, b ,c' => ['a','b','c'] (empty items are dropped)."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> None:
    global _FORMAT, _QUIET, _VERBOSE

    # Put the console into a known state (Windows UTF-8/VT + the POSIX C-locale
    # guard). It already ran once at import time, but we repeat it idempotently
    # for the case where `main()` is called directly (tests/embedding).
    _platform.init_console()
    _harden_console_streams()

    parser = _build_parser()

    # Optional shell completion — when argcomplete is installed.
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()
    command = args.command or "dashboard"

    _FORMAT = _resolve_format(args)
    _QUIET = bool(args.quiet)
    _VERBOSE = bool(args.verbose)
    _apply_color(bool(args.no_color))

    if command == "dashboard":
        from systop.app import run as run_dashboard

        run_dashboard()
        return

    try:
        code = asyncio.run(_dispatch(command, args))
    except KeyboardInterrupt:
        note("\n[dim]Stopped.[/]")
        code = EXIT_OK
    except Exception as exc:  # noqa: BLE001 — CLI boundary: turn errors into codes
        error(str(exc))
        code = EXIT_ERROR

    sys.exit(code)


async def _dispatch(command: str, args: argparse.Namespace) -> int:
    """Routes the command to its handler; returns an exit code."""
    if command == "speed":
        return await _cmd_speed(local=args.local, local_urls=args.local_url)
    if command == "ping":
        return await _cmd_ping(ipv6=args.ipv6, watch=args.watch, targets_arg=args.targets)
    if command == "trace":
        if getattr(args, "continuous", False):
            return await _cmd_mtr(args.host, interval=1.0, cycles=None)
        return await _cmd_trace(args.host)
    if command == "mtr":
        return await _cmd_mtr(args.host, interval=args.interval, cycles=args.cycles)
    if command == "scan":
        return await _cmd_scan(
            args.targets,
            args.ports,
            args.timeout,
            family=_family_from_args(args),
            top=args.top,
            banner=args.banner,
            open_only=args.open_only,
            polite=args.polite,
            max_hosts=args.max_hosts,
            from_lan=args.lan,
            from_lan6=args.lan6,
        )
    if command == "nc":
        return await _cmd_nc(
            args.host,
            args.port,
            send=args.send,
            tls=args.tls,
            as_hex=args.hex,
            timeout=args.timeout,
            wait=args.wait,
            family=_family_from_args(args),
        )
    if command == "dns":
        return await _cmd_dns(args.name, resolvers_arg=args.resolvers)
    if command == "bw":
        return await _cmd_bw(watch=args.watch, interval=args.interval)
    if command == "tls":
        return await _cmd_tls(args.host, timeout=args.timeout, warn_days=args.warn_days)
    if command == "http":
        return await _cmd_http(args.url, timeout=args.timeout)
    if command == "conn":
        return await _cmd_conn(listen_only=args.listen)
    if command == "config":
        return await _cmd_config(show=args.show, path_only=args.path)
    if command == "lan":
        return await _cmd_lan(
            ipv6=args.ipv6,
            only_ipv6=args.only_ipv6,
            global_only=args.global_only,
        )
    if command == "web":
        return await _cmd_web(
            hosts=args.hosts,
            ports_spec=("80" if args.http80 else args.ports),
            admin_only=args.admin_only,
            mgmt_only=args.mgmt,
            polite=args.polite,
            timeout=args.timeout,
            ipv6=args.ipv6,
        )
    if command == "doctor":
        return await _cmd_doctor(
            quick=args.quick,
            no_web=args.no_web,
            tls_arg=args.tls,
            max_hosts=args.max_hosts,
        )
    if command == "ntp":
        return await _cmd_ntp(args.servers, args.timeout)
    if command == "route":
        return await _cmd_route()
    if command == "mtu":
        return await _cmd_mtu(args.host, args.low, args.high)
    if command == "dhcp":
        return await _cmd_dhcp(args.listen)
    if command == "arpwatch":
        return await _cmd_arpwatch(update=not args.no_update, reset=args.reset)
    if command == "wifi":
        return await _cmd_wifi(show_neighbours=args.neighbours)
    if command == "info":
        return await _cmd_info()
    error(f"Unknown command: {command}")
    return EXIT_ERROR


def _family_from_args(args: argparse.Namespace) -> str:
    """Turns the `-4`/`-6` flags into a `ports.FAMILY_*` value."""
    from systop.core.ports import FAMILY_AUTO, FAMILY_V4, FAMILY_V6

    if getattr(args, "ipv6", False):
        return FAMILY_V6
    if getattr(args, "ipv4", False):
        return FAMILY_V4
    return FAMILY_AUTO


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


async def _cmd_speed(local: bool = False, local_urls: list[str] | None = None) -> int:
    from systop.core.config import load_config
    from systop.core.speed import run_speedtest

    cfg = load_config()
    verbose(f"speed_duration={cfg.speed_duration}s parallel={cfg.speed_parallel}")
    with status("[bold]Measuring speed (latency → download → upload)..."):
        result = await run_speedtest(duration=cfg.speed_duration, parallel=cfg.speed_parallel)

    if _FORMAT == "json":
        emit_json(result)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv([result])
        return EXIT_OK

    table = styled_table("Internet speed")
    table.show_header = False
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row(f"{glyph('download')} Download", f"[{SUCCESS}]{result.download_mbps:.1f}[/] Mbps")
    table.add_row(f"{glyph('upload')} Upload", f"[{SECONDARY}]{result.upload_mbps:.1f}[/] Mbps")
    # Jitter is NOT its own row — it goes into the latency row in words (as in the TUI).
    table.add_row(
        f"{glyph('latency')} Latency",
        f"{result.latency_ms:.1f} ms   [dim]jitter {result.jitter_ms:.1f} ms[/]",
    )
    emit_table(table)
    note(f"[dim]download {result.download_mbps:.1f} · upload {result.upload_mbps:.1f} Mbps[/]")

    # --- local (IX) vs international ---------------------------------------
    urls = local_urls or (cfg.speed_local_urls if local else [])
    if not urls:
        if local:
            error(
                "No local endpoint was given. Pass one with `--local-url URL`, or add "
                "it to the config:\n"
                '  speed_local_urls = ["https://mirror.example.com/10MB.bin"]\n'
                "The endpoint is deliberately not hard-coded — it differs in every "
                "country (the local internet exchange is not the same one twice)."
            )
            return EXIT_ERROR
        return EXIT_OK

    from systop.core.speed import SpeedComparison, measure_local

    with status(f"[bold]Measuring {len(urls)} local endpoints..."):
        locals_ = await measure_local(urls, duration=min(cfg.speed_duration, 5.0))
    cmp = SpeedComparison(international_mbps=result.download_mbps, local=locals_)

    lt = styled_table("Local (IX) vs international")
    lt.add_column("Endpoint", overflow="ellipsis")
    lt.add_column("Speed", justify="right")
    lt.add_column("Latency", justify="right")
    lt.add_column("State")
    for r in locals_:
        if r.ok:
            lt.add_row(
                data_cell(r.url),
                f"[{SUCCESS}]{r.mbps:.1f}[/] Mbps",
                f"{r.latency_ms:.0f} ms",
                f"[{SUCCESS}]ok[/]",
            )
        else:
            lt.add_row(data_cell(r.url), dash(), dash(), f"[{ERROR}]{r.error}[/]")
    lt.add_row(
        "[dim]international (Cloudflare)[/]",
        f"[{SECONDARY}]{cmp.international_mbps:.1f}[/] Mbps",
        dash(),
        "",
    )
    emit_table(lt)

    ratio = cmp.ratio
    if ratio is not None and cmp.best_local_mbps > 0:
        if cmp.is_throttled_international:
            note(
                f"[{WARNING}]Local is {ratio:.1f}x faster than international[/] — the "
                "international link is capped (tariff or shaping). This is NOT a "
                "hardware fault."
            )
        else:
            note(f"[dim]local/international ratio {ratio:.1f}x — no notable difference[/]")
    return EXIT_OK


async def _cmd_ping(ipv6: bool = False, watch: bool = False, targets_arg: str | None = None) -> int:
    from systop.core.config import load_config
    from systop.core.netinfo import default_gateway
    from systop.core.ping import build_targets, ping_many

    extra: dict[str, str] = {}
    explicit = _split_csv_arg(targets_arg)
    if not explicit:
        # Attach the ping targets from the config as extras.
        explicit = list(load_config().ping_targets)
    for addr in explicit:
        extra[addr] = addr

    if targets_arg:
        # The user named explicit targets — ping only those.
        targets = {addr: addr for addr in _split_csv_arg(targets_arg)}
    else:
        targets = build_targets(default_gateway(), include_ipv6=ipv6, extra_targets=extra)

    if watch:
        return await _cmd_ping_watch(targets)

    with status("[bold]Pinging..."):
        results = await ping_many(targets)

    if _FORMAT == "json":
        emit_json(results)
    elif _FORMAT == "csv":
        emit_csv(results)
    else:
        table = styled_table("Ping results")
        table.add_column("State")
        table.add_column("Target")
        table.add_column("Address")
        table.add_column("Avg ms", justify="right")
        table.add_column("Loss %", justify="right")
        for r in results:
            avg = rtt_cell(r.avg_rtt) if r.alive else f"[dim]{dash()}[/]"
            table.add_row(alive_cell(r.alive), r.label, r.address, avg, loss_cell(r.loss_pct))
        emit_table(table)
        alive = sum(1 for r in results if r.alive)
        dead = len(results) - alive
        note(f"[dim]{len(results)} targets — {alive} alive · {dead} dead[/]")

    # If no target answered at all, treat it as "there is no network".
    return EXIT_OK if any(r.alive for r in results) else EXIT_UNREACHABLE


async def _cmd_ping_watch(targets: dict[str, str]) -> int:
    """Continuous ping: every target in parallel, in a live-updating table."""
    import contextlib

    from rich.live import Live

    from systop.core.ping import WatchStats, ping_stream

    if _is_machine():
        error("--watch only works in table mode (not json/csv).")
        return EXIT_ERROR

    stats: dict[str, WatchStats] = {}

    def render() -> Table:
        table = styled_table("Ping monitor (Ctrl+C stops it)")
        table.add_column("Target")
        table.add_column("Address")
        table.add_column("Last ms", justify="right")
        table.add_column("Avg ms", justify="right")
        table.add_column("Min/Max ms", justify="right")
        table.add_column("Sent", justify="right")
        table.add_column("Loss %", justify="right")
        d = dash()
        for label in targets:
            s = stats.get(label)
            if s is None:
                table.add_row(label, targets[label], d, d, d, "0", d)
                continue
            last = rtt_cell(s.last_rtt) if s.received else f"[dim]{d}[/]"
            avg = rtt_cell(s.avg_rtt) if s.received else f"[dim]{d}[/]"
            minmax = f"{s.min_rtt:.0f}/{s.max_rtt:.0f}" if s.received else f"[dim]{d}[/]"
            table.add_row(label, s.address, last, avg, minmax, str(s.sent), loss_cell(s.loss_pct))
        return table

    async def follow(label: str, address: str, live: Live) -> None:
        async for snap in ping_stream(address, label=label):
            stats[label] = snap
            live.update(render())

    with Live(render(), console=console, refresh_per_second=4) as live:
        tasks = [asyncio.create_task(follow(label, addr, live)) for label, addr in targets.items()]
        try:
            await asyncio.gather(*tasks)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            for t in tasks:
                t.cancel()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await t
    note("\n[dim]Monitor stopped.[/]")
    return EXIT_OK


async def _cmd_scan(
    targets_spec: list[str],
    ports_spec: str | None,
    timeout: float,
    family: str = "auto",
    top: int | None = None,
    banner: bool = False,
    open_only: bool = False,
    polite: bool = False,
    max_hosts: int = 1024,
    from_lan: bool = False,
    from_lan6: bool = False,
) -> int:
    """Port scanner — a single host, a whole LAN (CIDR/range), or IPv6 neighbours.

    When it expands to one host you get a detailed port table; when it expands to
    many, a sweep summary with one row per host (nmap style).
    """
    from systop.core.ports import parse_ports, parse_targets, scan_host, top_ports

    ports = parse_ports(ports_spec) if ports_spec else None
    if ports_spec and not ports:
        error(f"'{ports_spec}' is not a valid port list.")
        return EXIT_ERROR
    if top is not None:
        if top < 1:
            error("--top must be at least 1.")
            return EXIT_ERROR
        ports = top_ports(top)

    hosts = parse_targets(",".join(targets_spec), max_hosts=max_hosts) if targets_spec else []

    # `--lan` / `--lan6`: take the targets from the network automatically. A
    # subnet sweep is impossible on IPv6 (2^64 addresses), so the EXACT addresses
    # found in the NDP neighbour table are what gets scanned.
    if from_lan or from_lan6:
        from systop.core.topology import discover_lan, discover_lan6

        with status("[bold]Discovering targets on the LAN..."):
            if from_lan:
                found = await discover_lan(resolve=False, all_interfaces=True)
                hosts += [h.ip for h in found if h.ip not in hosts]
            if from_lan6:
                found6 = await discover_lan6(include_link_local=True)
                hosts += [h.ip for h in found6 if h.ip not in hosts]
        if from_lan6 and not from_lan:
            family = "ipv6"

    hosts = hosts[:max_hosts]
    if not hosts:
        error(
            f"No target could be determined: {' '.join(targets_spec) or '(empty)'}"
            + ("" if (from_lan or from_lan6) else " — give a host or use --lan/--lan6")
        )
        return EXIT_ERROR

    # Many hosts => sweep mode.
    if len(hosts) > 1:
        return await _scan_sweep(hosts, ports, timeout, family, banner, open_only, polite)

    host = hosts[0]
    count = len(ports) if ports else "common"
    fam_note = "" if family == "auto" else f", {family}"
    with status(f"[bold]Scanning {host} ({count} ports{fam_note})..."):
        result = await scan_host(host, ports=ports, timeout=timeout, family=family)
        if banner:
            from systop.core.ports import grab_banner, parse_banner

            for p in result.open_ports:
                raw = await grab_banner(result.resolved_ip or host, p.port, timeout=timeout)
                if raw:
                    svc, ver = parse_banner(raw)
                    p.banner = ver
                    if svc and not p.service:
                        p.service = svc

    if result.error:
        if _FORMAT == "json":
            emit_json(result)
        else:
            error(result.error)
        return EXIT_UNREACHABLE

    if _FORMAT == "json":
        emit_json(result)
        return EXIT_OK if result.open_ports else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(result.ports)
        return EXIT_OK if result.open_ports else EXIT_UNREACHABLE

    open_ports = result.open_ports
    title = (
        f"Port scan {glyph('gateway')} {result.host} "
        f"({result.resolved_ip}) — {len(open_ports)} open"
    )
    table = styled_table(title)
    table.add_column("Port", justify="right")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("RTT ms", justify="right")
    if not open_ports:
        emit_table(table)
        note(f"[{WARNING}]No port is open[/] ({len(result.ports)} checked).")
        return EXIT_UNREACHABLE
    has_banner = any(p.banner for p in open_ports)
    if has_banner:
        table.add_column("Version / banner", overflow="ellipsis")
    for p in open_ports:
        row = [str(p.port), f"[{SUCCESS}]open[/]", p.service or dash(), rtt_cell(p.rtt_ms)]
        if has_banner:
            row.append(p.banner or dash())
        table.add_row(*row)
    emit_table(table)
    filtered = sum(1 for p in result.ports if p.state == "filtered")
    closed = sum(1 for p in result.ports if p.state == "closed")
    note(
        f"[dim]{len(result.ports)} ports checked — "
        f"{len(open_ports)} open · {closed} closed · {filtered} filtered[/]"
    )
    return EXIT_OK


async def _scan_sweep(
    hosts: list[str],
    ports: list[int] | None,
    timeout: float,
    family: str,
    banner: bool,
    open_only: bool,
    polite: bool,
) -> int:
    """A sweep over many hosts — one row per host (an nmap-style summary)."""
    from systop.core.ports import scan_targets, top_ports

    port_list = ports or top_ports(20)
    conc = 8 if polite else 64
    delay = 0.2 if polite else 0.0
    with status(
        f"[bold]Scanning {len(hosts)} hosts x {len(port_list)} ports"
        + (" (slow mode)" if polite else "")
        + "..."
    ):
        sweep = await scan_targets(
            hosts,
            ports=port_list,
            timeout=timeout,
            concurrency=conc,
            family=family,
            banner=banner,
            delay=delay,
        )

    shown = sweep.responsive if open_only else [h for h in sweep.hosts if not h.error]
    if _FORMAT == "json":
        emit_json(sweep)
        return EXIT_OK if sweep.total_open else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        # In CSV each host must be one row — so the ports get collapsed together.
        rows = [
            {
                "host": h.host,
                "resolved_ip": h.resolved_ip or "",
                "family": h.resolved_family or "",
                "open_ports": " ".join(str(p.port) for p in h.open_ports),
                "open_count": len(h.open_ports),
                "services": " ".join(p.service or "?" for p in h.open_ports),
            }
            for h in shown
        ]
        emit_csv(rows)
        return EXIT_OK if sweep.total_open else EXIT_UNREACHABLE

    if not sweep.responsive:
        note(
            f"[{WARNING}]No open port was found on any host[/] "
            f"({sweep.scanned_hosts} hosts x {sweep.scanned_ports} ports)."
        )
        return EXIT_UNREACHABLE

    table = styled_table(
        f"Port sweep - {sweep.total_open} open ports on "
        f"{len(sweep.responsive)}/{sweep.scanned_hosts} hosts"
    )
    table.add_column("Host", no_wrap=True)
    table.add_column("Open ports", no_wrap=True)
    table.add_column("Services", overflow="ellipsis")
    if banner:
        table.add_column("Banner", overflow="ellipsis")
    for h in shown:
        if not h.open_ports:
            continue
        row = [
            h.resolved_ip or h.host,
            " ".join(f"[{SUCCESS}]{p.port}[/]" for p in h.open_ports),
            ", ".join(p.service or "?" for p in h.open_ports),
        ]
        if banner:
            row.append("; ".join(p.banner for p in h.open_ports if p.banner) or dash())
        table.add_row(*row)
    emit_table(table)

    failed = sum(1 for h in sweep.hosts if h.error)
    parts = [f"{sweep.scanned_hosts} hosts x {sweep.scanned_ports} ports"]
    if failed:
        parts.append(f"{failed} failed to resolve")
    if polite:
        parts.append("slow mode")
    note(f"[dim]{' - '.join(parts)}[/]")
    return EXIT_OK


async def _cmd_nc(
    host: str,
    port: int,
    send: str | None,
    tls: bool,
    as_hex: bool,
    timeout: float,
    wait: float | None,
    family: str,
) -> int:
    """An ncat-style raw TCP/TLS connection."""
    from systop.core.netcat import connect, to_hexdump, unescape

    payload = unescape(send) if send else None
    label = f"{host}:{port}" + (" (TLS)" if tls else "")
    with status(f"[bold]Connecting to {label}..."):
        res = await connect(
            host,
            port,
            send=payload,
            tls=tls,
            timeout=timeout,
            family=family,
            wait_read=wait,
        )

    if _FORMAT == "json":
        emit_json(res)
        return EXIT_OK if res.connected else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv([res])
        return EXIT_OK if res.connected else EXIT_UNREACHABLE

    if not res.connected:
        error(res.error or "could not connect")
        return EXIT_UNREACHABLE

    table = styled_table(f"nc {label}")
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    table.add_row("Address", f"{res.resolved_ip} ({res.family})")
    table.add_row("State", f"[{SUCCESS}]connected[/] - {res.elapsed_ms:.0f} ms")
    if res.tls:
        table.add_row("TLS", f"{res.tls_version or dash()} - {res.tls_cipher or dash()}")
        if res.peer_cert_sha256:
            table.add_row("Cert SHA-256", res.peer_cert_sha256)
    if res.sent_bytes:
        table.add_row("Sent", f"{res.sent_bytes} bytes")
    table.add_row("Received", f"{res.received_bytes_count} bytes")
    emit_table(table)

    if res.received:
        if as_hex or res.is_binary:
            note("[dim]-- reply (hexdump) --[/]")
            console.print(to_hexdump(res.received[:1024]))
        else:
            note("[dim]-- reply --[/]")
            console.print(res.received_text[:4000].rstrip())
    else:
        note("[dim]No reply (the service may be waiting for a request - try --send).[/]")
    return EXIT_OK


async def _cmd_dns(name: str, resolvers_arg: str | None = None) -> int:
    from systop.core.dns import diagnose_dns

    # IMPORTANT: `load_config().dns_resolvers` must NOT be passed unconditionally.
    # `DEFAULT_DNS_RESOLVERS` holds 3 servers and `PUBLIC_RESOLVERS` holds 4 — so
    # every user without a config file silently lost OpenDNS. Only a value the
    # user gave DELIBERATELY may override it.
    resolvers = _split_csv_arg(resolvers_arg)
    override: dict[str, str] | None = {r: r for r in resolvers} if resolvers else None
    verbose(f"resolvers: {', '.join(resolvers) or '(system + public)'}")

    with status(f"[bold]DNS diagnostics for {name}..."):
        result = await diagnose_dns(name, resolvers=override)

    if _FORMAT == "json":
        emit_json(result)
        return EXIT_OK if not result.system_error else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(result.resolvers)
        return EXIT_OK if not result.system_error else EXIT_UNREACHABLE

    if result.system_error:
        error(f"System resolver: {result.system_error}")
    else:
        addrs = ", ".join(result.system_addresses) or dash()
        note(f"[dim]System resolver (A):[/] [bold]{addrs}[/]")
        if result.aaaa_addresses:
            note(f"[dim]AAAA (IPv6):[/] [bold]{', '.join(result.aaaa_addresses)}[/]")
        elif result.tool:
            note("[dim]AAAA (IPv6): no record[/]")

    if not result.resolvers:
        note(
            f"\n[{WARNING}]`dig`/`nslookup` not found[/] — resolver latency could not "
            "be compared (only the system resolve is shown)."
        )
        return EXIT_OK if not result.system_error else EXIT_UNREACHABLE

    table = styled_table(f"DNS server comparison ({result.tool})")
    table.add_column("Server")
    table.add_column("IP")
    table.add_column("RTT ms", justify="right")
    table.add_column("Answer (addresses)")
    table.add_column("State")
    fastest = min((r for r in result.resolvers if r.ok), key=lambda r: r.rtt_ms, default=None)
    for r in result.resolvers:
        if r.ok:
            mark = f"[b {SUCCESS}]fastest[/]" if r is fastest else f"[{SUCCESS}]alive[/]"
            rtt = rtt_cell(r.rtt_ms)
            answers = ", ".join(r.addresses[:3])
            if len(r.addresses) > 3:
                answers += f" (+{len(r.addresses) - 3})"
        else:
            mark = f"[{ERROR}]{r.error or 'error'}[/]"
            rtt = f"[dim]{dash()}[/]"
            answers = dash()
        table.add_row(r.name, r.server, rtt, answers, mark)
    emit_table(table)
    if fastest is not None:
        note(f"[dim]fastest: {fastest.name} ({fastest.server}) — {fastest.rtt_ms:.1f} ms[/]")
    return EXIT_OK if not result.system_error else EXIT_UNREACHABLE


async def _cmd_trace(host: str) -> int:
    from systop.core.topology import trace_path

    with status(f"[bold]Traceroute to {host}..."):
        result = await trace_path(host)

    if _FORMAT == "json":
        emit_json(result)
        return EXIT_UNREACHABLE if (result.error or not result.hops) else EXIT_OK
    if _FORMAT == "csv":
        emit_csv(result.hops)
        return EXIT_UNREACHABLE if (result.error or not result.hops) else EXIT_OK

    if result.error:
        error(result.error)
        return EXIT_UNREACHABLE
    if not result.hops:
        note(f"[{WARNING}]No hop was found (the path is closed or blocked).[/]")
        return EXIT_UNREACHABLE
    table = styled_table(f"Traceroute {glyph('gateway')} {host}")
    table.add_column("#", justify="right")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("RTT ms", justify="right")
    alive_hops = 0
    for hop in result.hops:
        if hop.alive:
            rtt = rtt_cell(hop.rtt_ms)
            alive_hops += 1
        else:
            rtt = f"[dim]{glyph('cross')}[/]"
        table.add_row(str(hop.index), hop.address or "* * *", hop.hostname or dash(), rtt)
    emit_table(table)
    note(f"[dim]{len(result.hops)} hops — {alive_hops} answered[/]")
    return EXIT_OK


async def _cmd_mtr(host: str, interval: float = 1.0, cycles: int | None = None) -> int:
    """Live mtr-style traceroute: trace_stream + rich.Live (Ctrl+C stops it)."""
    from systop.core.topology import HopStat, trace_stream

    # An endless stream makes no sense in JSON/CSV mode — take a few cycles and
    # print the last one.
    if _is_machine():
        machine_cycles = cycles if cycles is not None else 3
        last: list[HopStat] = []
        async for hops in trace_stream(host, interval=interval, cycles=machine_cycles):
            last = hops
        if _FORMAT == "json":
            emit_json(last)
        else:
            emit_csv(last)
        return EXIT_OK if last else EXIT_UNREACHABLE

    from rich.live import Live

    def render(hops: list[HopStat]) -> Table:
        table = styled_table(f"mtr {glyph('gateway')} {host} (Ctrl+C stops it)")
        table.add_column("#", justify="right")
        table.add_column("Host")
        table.add_column("Loss %", justify="right")
        table.add_column("Sent", justify="right")
        table.add_column("Last", justify="right")
        table.add_column("Avg", justify="right")
        table.add_column("Best", justify="right")
        table.add_column("Worst", justify="right")
        d = dash()
        for h in hops:
            name = h.hostname or h.address or "???"
            last = rtt_cell(h.last_rtt) if h.recv else f"[dim]{d}[/]"
            avg = rtt_cell(h.avg_rtt) if h.recv else f"[dim]{d}[/]"
            best = rtt_cell(h.best_rtt) if h.recv else f"[dim]{d}[/]"
            worst = rtt_cell(h.worst_rtt) if h.recv else f"[dim]{d}[/]"
            table.add_row(
                str(h.index), name, loss_cell(h.loss_pct), str(h.sent), last, avg, best, worst
            )
        return table

    saw_hops = False
    with Live(render([]), console=console, refresh_per_second=4) as live:
        try:
            async for hops in trace_stream(host, interval=interval, cycles=cycles):
                saw_hops = saw_hops or bool(hops)
                live.update(render(hops))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
    note("\n[dim]mtr stopped.[/]")
    return EXIT_OK if saw_hops else EXIT_UNREACHABLE


async def _cmd_bw(watch: bool = False, interval: float = 1.0) -> int:
    from systop.core.bandwidth import bandwidth_stream, sample_bandwidth

    if watch and _is_machine():
        error("--watch only works in table mode (not json/csv).")
        return EXIT_ERROR

    if not watch:
        with status(f"[bold]Measuring bandwidth ({interval:.1f}s)..."):
            rates = await sample_bandwidth(interval=interval)
        if _FORMAT == "json":
            emit_json(rates)
            return EXIT_OK
        if _FORMAT == "csv":
            emit_csv(rates)
            return EXIT_OK
        emit_table(_bw_table(rates))
        return EXIT_OK

    # --watch: a live stream (table mode only).
    from rich.live import Live

    with Live(_bw_table([]), console=console, refresh_per_second=2) as live:
        try:
            async for rates in bandwidth_stream(interval=interval):
                live.update(_bw_table(rates))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
    note("\n[dim]Bandwidth monitor stopped.[/]")
    return EXIT_OK


def _human_bps(bps: float) -> str:
    """Turns bits per second into a human-readable unit (bps/Kbps/Mbps/Gbps)."""
    units = ("bps", "Kbps", "Mbps", "Gbps", "Tbps")
    value = float(bps)
    idx = 0
    while value >= 1000.0 and idx < len(units) - 1:
        value /= 1000.0
        idx += 1
    return f"{value:.1f} {units[idx]}"


def _bw_table(rates: list[Any]) -> Table:
    """Builds a Rich table from a list of IfaceRate (RX/TX human-readable)."""
    table = styled_table("Interface bandwidth (Ctrl+C stops it)")
    table.add_column("Interface")
    table.add_column(f"{glyph('download')} RX", justify="right")
    table.add_column(f"{glyph('upload')} TX", justify="right")
    table.add_column("RX pps", justify="right")
    table.add_column("TX pps", justify="right")
    table.add_column("Total", justify="right")
    for r in rates:
        table.add_row(
            r.name,
            f"[{SUCCESS}]{_human_bps(r.rx_bps)}[/]",
            f"[{SECONDARY}]{_human_bps(r.tx_bps)}[/]",
            f"{r.rx_pps:.0f}",
            f"{r.tx_pps:.0f}",
            _human_bps(r.total_bps),
        )
    return table


async def _cmd_tls(host: str, timeout: float = 5.0, warn_days: int = 14) -> int:
    from systop.core.tls import check_tls

    target, port = _split_host_port(host, default_port=443)
    with status(f"[bold]Checking TLS on {target}:{port}..."):
        result = await check_tls(target, port=port, timeout=timeout)

    if _FORMAT == "json":
        emit_json(result)
        return _tls_exit_code(result, warn_days)
    if _FORMAT == "csv":
        emit_csv([result])
        return _tls_exit_code(result, warn_days)

    if not result.ok:
        error(result.error or "The TLS check failed.")
        return EXIT_UNREACHABLE

    table = styled_table(f"TLS certificate {glyph('gateway')} {result.host}:{result.port}")
    table.show_header = False
    table.add_column("Field")
    table.add_column("Value")
    days = result.days_left
    if days is None:
        days_str = dash()
    elif days < 0:
        days_str = f"[{ERROR}]expired ({-days} days ago)[/]"
    elif days <= warn_days:
        days_str = f"[{WARNING}]{days} days (close!)[/]"
    else:
        days_str = f"[{SUCCESS}]{days} days[/]"
    table.add_row("Remaining", days_str)
    table.add_row("Expires", result.not_after or dash())
    table.add_row("Issuer", result.issuer or dash())
    table.add_row("Subject", result.subject or dash())
    table.add_row("SAN count", str(len(result.san)))
    table.add_row("TLS version", result.tls_version or dash())
    emit_table(table)
    code = _tls_exit_code(result, warn_days)
    if code == EXIT_OK:
        note(f"[dim]exit 0 · well clear of the warn-days {warn_days} threshold[/]")
    elif days is not None and days < 0:
        note("[dim]exit 2 · the certificate has expired[/]")
    else:
        note(f"[dim]exit 2 · close to the warn-days {warn_days} threshold[/]")
    return code


def _tls_exit_code(result: Any, warn_days: int) -> int:
    """Exit code from the TLS result: an error, or expired/expiring => nonzero."""
    if not result.ok:
        return EXIT_UNREACHABLE
    if result.days_left is not None and result.days_left <= warn_days:
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_http(url: str, timeout: float = 5.0) -> int:
    from systop.core.tls import check_http

    if "://" not in url:
        url = "https://" + url
    with status(f"[bold]Requesting {url}..."):
        result = await check_http(url, timeout=timeout)

    if _FORMAT == "json":
        emit_json(result)
        return _http_exit_code(result)
    if _FORMAT == "csv":
        emit_csv([result])
        return _http_exit_code(result)

    if result.error:
        error(result.error)
        return EXIT_UNREACHABLE

    table = styled_table(f"HTTP {glyph('gateway')} {result.url}")
    table.show_header = False
    table.add_column("Field")
    table.add_column("Value")
    status_code = result.status or 0
    if 200 <= status_code < 400:
        status_str = f"[{SUCCESS}]{status_code}[/]"
    else:
        status_str = f"[{ERROR}]{status_code}[/]"
    table.add_row("Status", status_str)
    table.add_row("Final URL", result.final_url or dash())
    table.add_row("Time", f"{result.elapsed_ms:.0f} ms")
    table.add_row("Server", result.server or dash())
    if result.redirects:
        table.add_row("Redirects", " -> ".join(result.redirects))
    emit_table(table)
    code = _http_exit_code(result)
    note(f"[dim]exit {code} · {result.elapsed_ms:.0f} ms[/]")
    return code


def _http_exit_code(result: Any) -> int:
    """Exit code from the HTTP result: an error or a >=400 status => nonzero."""
    if result.error:
        return EXIT_UNREACHABLE
    if result.status is None or result.status >= 400:
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_conn(listen_only: bool = False) -> int:
    from systop.core.connections import list_connections

    states = ["LISTEN"] if listen_only else None
    conns = await asyncio.to_thread(list_connections, "inet", states)

    if _FORMAT == "json":
        emit_json(conns)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(conns)
        return EXIT_OK

    table = styled_table(f"Network connections ({len(conns)})")
    table.add_column("Proto")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("State")
    table.add_column("PID", justify="right")
    table.add_column("Process")
    for c in conns:
        table.add_row(
            c.proto,
            c.laddr,
            c.raddr or dash(),
            c.status or dash(),
            str(c.pid) if c.pid is not None else dash(),
            c.process or dash(),
        )
    emit_table(table)
    if not conns:
        note(
            f"[{WARNING}]No connections found[/] — on macOS the full table usually "
            "needs root (sudo)."
        )
    else:
        listening = sum(1 for c in conns if c.status == "LISTEN")
        note(f"[dim]{len(conns)} connections — {listening} LISTEN[/]")
    return EXIT_OK


async def _cmd_config(show: bool = False, path_only: bool = False) -> int:
    from systop.core.config import (
        ENV_VAR,
        config_fields,
        load_config,
    )
    from systop.core.config import (
        _resolve_path as _cfg_path,
    )

    cfg_path = _cfg_path(None)
    cfg = load_config()

    if path_only and not _is_machine():
        # For scripts: the bare path (no Rich markup, `$(systop config --path)`-safe).
        _safe_write(sys.stdout, str(cfg_path) + "\n")
        return EXIT_OK

    if _FORMAT == "json":
        payload = _to_dict(cfg)
        payload["_config_path"] = str(cfg_path)
        payload["_config_exists"] = cfg_path.exists()
        emit_json(payload)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv([cfg])
        return EXIT_OK

    exists = cfg_path.exists()
    note(f"[dim]Configuration file:[/] [bold]{cfg_path}[/]")
    state = f"[{SUCCESS}]present[/]" if exists else f"[{WARNING}]absent (defaults are used)[/]"
    note(f"[dim]State:[/] {state}")
    note(f"[dim]Env override ({ENV_VAR}):[/] {os.environ.get(ENV_VAR) or dash()}")

    if show or not exists:
        table = styled_table("Current (effective) settings")
        table.add_column("Field")
        table.add_column("Value")
        for name in config_fields():
            value = getattr(cfg, name)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            table.add_row(name, str(value))
        emit_table(table)
    return EXIT_OK


async def _cmd_lan(
    ipv6: bool = False,
    only_ipv6: bool = False,
    global_only: bool = False,
) -> int:
    from systop.core.topology import discover_lan, discover_lan6

    hosts: list = []
    if not only_ipv6:
        with status("[bold]Scanning the LAN (IPv4)..."):
            hosts += await discover_lan(resolve=True)
    if ipv6 or only_ipv6:
        with status("[bold]Looking for IPv6 neighbours (ff02::1 + NDP)..."):
            hosts += await discover_lan6(resolve=True, include_link_local=not global_only)

    if _FORMAT == "json":
        emit_json(hosts)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(hosts)
        return EXIT_OK

    v4 = sum(1 for h in hosts if h.family == "ipv4")
    v6 = len(hosts) - v4
    title = f"LAN hosts ({len(hosts)}"
    title += f" — IPv4: {v4}, IPv6: {v6})" if v6 else ")"
    table = styled_table(title)
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Hostname")
    table.add_column("RTT ms", justify="right")
    table.add_column("Role")
    for h in hosts:
        if h.is_gateway:
            role = f"[{WARNING}]{glyph('gateway')}[/] gateway"
        elif h.family == "ipv6":
            role = "[dim]link-local[/]" if h.is_link_local else "IPv6 host"
        else:
            role = "host"
        rtt = rtt_cell(h.rtt_ms) if h.rtt_ms else f"[dim]{dash()}[/]"
        table.add_row(h.ip, h.mac or dash(), h.vendor or dash(), h.hostname or dash(), rtt, role)
    emit_table(table)

    src = []
    if not only_ipv6:
        src.append("/24 ping sweep + ARP")
    if ipv6 or only_ipv6:
        src.append("ff02::1 multicast + NDP")
    note(f"[dim]{len(hosts)} hosts found · {' · '.join(src)}[/]")
    return EXIT_OK


async def _cmd_web(
    hosts: list[str],
    ports_spec: str | None,
    admin_only: bool,
    mgmt_only: bool,
    polite: bool,
    timeout: float,
    ipv6: bool,
) -> int:
    """Finds web services and management panels."""
    from systop.core.diagnose import is_management_device
    from systop.core.ports import parse_ports
    from systop.core.topology import discover_lan, discover_lan6
    from systop.core.webscan import WEB_PORTS, discover_web, summarize

    ports = parse_ports(ports_spec) if ports_spec else None
    if ports_spec and not ports:
        error(f"'{ports_spec}' is not a valid port list.")
        return EXIT_ERROR

    # No host given — discover the LAN ourselves.
    targets = list(hosts)
    if not targets:
        with status("[bold]Looking for LAN hosts..."):
            found = await discover_lan(resolve=False)
            targets = [h.ip for h in found]
            if ipv6:
                v6 = await discover_lan6(include_link_local=False)
                targets += [h.ip for h in v6]
        if not targets:
            error("No host found on the LAN. Give one by hand: systop web 192.168.1.1")
            return EXIT_UNREACHABLE

    n_ports = len(ports) if ports else len(WEB_PORTS)
    delay = 0.3 if polite else 0.0
    conc = 4 if polite else 16
    with status(
        f"[bold]Checking {len(targets)} hosts × {n_ports} ports"
        + (" (slow mode)" if polite else "")
        + "..."
    ):
        services = await discover_web(
            targets,
            ports=ports,
            timeout=timeout,
            concurrency=conc,
            delay=delay,
            admin_only=admin_only,
        )

    if mgmt_only:
        services = [s for s in services if is_management_device(s.device_kind)]

    if _FORMAT == "json":
        emit_json(services)
        return EXIT_OK if services else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(services)
        return EXIT_OK if services else EXIT_UNREACHABLE

    if not services:
        note(f"[{WARNING}]No web service found[/] ({len(targets)} hosts checked).")
        return EXIT_UNREACHABLE

    st = summarize(services)
    table = styled_table(f"Web services ({st['total']} · management panels: {st['admin']})")
    # The address must not be truncated — it is the key to the result (which
    # host, which port).
    table.add_column("Address", no_wrap=True)
    table.add_column("Product", no_wrap=True)
    table.add_column("Kind")
    table.add_column("Title", overflow="ellipsis")
    table.add_column("Code", justify="right")
    table.add_column("Risk")
    for s in services:
        risk_map = {
            "high": f"[{ERROR}]high[/]",
            "medium": f"[{WARNING}]medium[/]",
            "low": f"[{SUCCESS}]low[/]",
            "none": f"[dim]{dash()}[/]",
        }
        addr = f"{s.scheme}://{s.ip}:{s.port}"
        mgmt = " ⚙" if is_management_device(s.device_kind) else ""
        table.add_row(
            addr,
            (s.product or dash()) + mgmt,
            s.device_kind or dash(),
            (s.title or dash())[:38],
            str(s.status or dash()),
            risk_map.get(s.risk, dash()),
        )
    emit_table(table)

    parts = [f"{st['admin']} management panels"]
    if st["insecure_admin"]:
        parts.append(f"[{WARNING}]{st['insecure_admin']} of them over unencrypted HTTP[/]")
    if st["high_risk"]:
        parts.append(f"[{ERROR}]{st['high_risk']} of them send the password in clear text[/]")
    if st["http_80"]:
        parts.append(f"{st['http_80']} of them on port 80")
    note("[dim]⚙ = a device that runs the network · [/]" + " · ".join(parts))
    return EXIT_OK


def _doctor_exit_code(report: Any) -> int:
    """The SINGLE exit-code rule for `doctor` (identical for table, JSON and CSV).

    Table mode and machine mode used to follow different rules: the table
    returned 2 only on critical/high, while `--json` returned 2 on ANY non-INFO
    finding. So `systop doctor` succeeded and `systop doctor --json` failed — on
    the same network, in the same second. For a script that is a silent lie:
    every ordinary LAN (SMB exposed + one slow resolver = medium) counted as
    "failed".
    """
    return (
        EXIT_UNREACHABLE
        if report.worst_severity in (DOCTOR_FAIL_CRITICAL, DOCTOR_FAIL_HIGH)
        else EXIT_OK
    )


async def _cmd_doctor(quick: bool, no_web: bool, tls_arg: str | None, max_hosts: int) -> int:
    """Finds network problems automatically and shows them ordered by severity."""
    from systop.core.diagnose import (
        SEV_CRITICAL,
        SEV_HIGH,
        SEV_INFO,
        SEV_LOW,
        SEV_MEDIUM,
        run_diagnostics,
    )

    tls_hosts = [h.strip() for h in tls_arg.split(",") if h.strip()] if tls_arg else None

    with status("[bold]Checking the network (interface → ping → DNS → LAN → web)..."):
        report = await run_diagnostics(
            quick=quick,
            include_web=not no_web,
            tls_hosts=tls_hosts,
            max_hosts=max_hosts,
        )

    if _FORMAT == "json":
        emit_json(report)
        return _doctor_exit_code(report)
    if _FORMAT == "csv":
        emit_csv(report.findings)
        return _doctor_exit_code(report)

    sev_style = {
        SEV_CRITICAL: f"[{ERROR}]CRITICAL[/]",
        SEV_HIGH: f"[{ERROR}]HIGH[/]",
        SEV_MEDIUM: f"[{WARNING}]MEDIUM[/]",
        SEV_LOW: "[dim]LOW[/]",
        SEV_INFO: "[dim]info[/]",
    }
    counts = report.counts
    head = f"Network diagnostics — {len(report.problems)} problems"
    if not report.problems:
        head = "Network diagnostics — no problems found"
    table = styled_table(head)
    table.add_column("Level")
    table.add_column("Area")
    table.add_column("Problem")
    table.add_column("What to do")
    for f in report.findings:
        table.add_row(
            sev_style.get(f.severity, f.severity),
            f.category,
            f.title,
            (f.fix or f.detail)[:70],
        )
    emit_table(table)

    summary = " · ".join(
        f"{lvl}: {counts[lvl]}"
        for lvl in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO)
        if counts.get(lvl)
    )
    note(
        f"[dim]{report.checks_run} checks · {report.duration_ms / 1000:.1f}s"
        + (f" · {summary}" if summary else "")
        + (f" · skipped: {', '.join(report.skipped)}" if report.skipped else "")
        + "[/]"
    )
    if _VERBOSE:
        for f in report.problems:
            note(f"\n[bold]{f.title}[/]\n  {f.detail}" + (f"\n  → {f.fix}" if f.fix else ""))

    return _doctor_exit_code(report)


async def _cmd_ntp(servers_arg: str | None, timeout: float) -> int:
    """Checks clock skew over NTP."""
    from systop.core.ntp import check_time

    servers = None
    if servers_arg:
        parts = [x.strip() for x in servers_arg.split(",") if x.strip()]
        servers = {p: p for p in parts}
    with status("[bold]Querying NTP servers..."):
        rep = await check_time(servers, timeout=timeout)

    if _FORMAT == "json":
        emit_json(rep)
        return EXIT_OK if rep.responded else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(rep.results)
        return EXIT_OK if rep.responded else EXIT_UNREACHABLE

    med = rep.median_offset_s
    title = "Clock check"
    if med is not None:
        title += f" - median offset {med * 1000:+.0f} ms"
    table = styled_table(title)
    table.add_column("Server", no_wrap=True)
    table.add_column("State")
    table.add_column("Offset", justify="right")
    table.add_column("RTT ms", justify="right")
    table.add_column("Stratum", justify="right")
    sev_color = {"ok": SUCCESS, "warn": WARNING, "high": ERROR, "critical": ERROR}
    for r in rep.results:
        if not r.ok:
            table.add_row(
                data_cell(r.label), f"[{ERROR}]{r.error or 'error'}[/]", dash(), dash(), dash()
            )
            continue
        col = sev_color.get(r.severity, WARNING)
        table.add_row(
            data_cell(r.label),
            f"[{SUCCESS}]ok[/]",
            f"[{col}]{r.offset_ms:+.0f} ms[/]",
            f"{r.delay_ms:.0f}",
            str(r.stratum),
        )
    emit_table(table)
    if med is not None and abs(med) >= 1.0:
        note(
            f"[{WARNING}]The clock has drifted {med:+.1f} s[/] - this can break Kerberos/TLS/logs."
        )
    else:
        note(
            f"[dim]{len(rep.responded)}/{len(rep.results)} servers answered - the clock is fine[/]"
        )
    return EXIT_OK if rep.responded else EXIT_UNREACHABLE


async def _cmd_route() -> int:
    """The routing table and the reachability of the default next hops."""
    from systop.core.routes import check_next_hops, list_routes

    with status("[bold]Reading the routing table..."):
        table_data = await list_routes()
        alive = await check_next_hops(table_data)

    if table_data.error:
        error(table_data.error)
        return EXIT_ERROR
    if _FORMAT == "json":
        emit_json(table_data)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(table_data.routes)
        return EXIT_OK

    t = styled_table(
        f"Routes ({len(table_data.routes)}, "
        f"{len(table_data.routable_defaults)} meaningful defaults)"
    )
    t.add_column("Destination", no_wrap=True)
    t.add_column("Gateway", no_wrap=True)
    t.add_column("Interface")
    t.add_column("Family")
    t.add_column("State")
    for r in table_data.routes:
        state = ""
        if r.is_default and r.gateway in alive:
            state = f"[{SUCCESS}]alive[/]" if alive[r.gateway] else f"[{ERROR}]no answer[/]"
        elif r.is_default:
            state = "[dim]link-local[/]"
        t.add_row(
            data_cell(r.destination),
            data_cell(r.gateway, dash()),
            data_cell(r.interface, dash()),
            r.family,
            state or "[dim]-[/]",
        )
    emit_table(t)
    if table_data.has_vpn_split_hack:
        note(f"[{WARNING}]The VPN has taken all traffic via 0.0.0.0/1 + 128.0.0.0/1[/]")
    dead = [g for g, ok in alive.items() if not ok]
    if dead:
        note(f"[{ERROR}]Unresponsive gateway: {', '.join(dead)}[/]")
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_mtu(host: str, low: int, high: int) -> int:
    """Path MTU discovery."""
    from systop.core.mtu import discover_path_mtu

    with status(f"[bold]Discovering the path MTU to {host} (DF-ping)..."):
        res = await discover_path_mtu(host, low=low, high=high)

    if _FORMAT == "json":
        emit_json(res)
        return EXIT_UNREACHABLE if res.error else EXIT_OK
    if _FORMAT == "csv":
        emit_csv([res])
        return EXIT_UNREACHABLE if res.error else EXIT_OK

    if res.error:
        error(res.error)
        return EXIT_UNREACHABLE
    t = styled_table(f"Path MTU - {host}")
    t.add_column("Field")
    t.add_column("Value")
    t.add_row("Path MTU", f"[b]{res.path_mtu}[/] bytes")
    t.add_row("Max payload", str(res.max_payload))
    t.add_row("Family", res.family)
    t.add_row("Probes", str(res.probes))
    if res.likely_cause:
        t.add_row("Likely cause", res.likely_cause)
    emit_table(t)
    if res.is_reduced:
        note(
            f"[{WARNING}]The MTU is below 1500[/] - sites with large responses can "
            "hang (a PMTUD black hole). Enable MSS clamping."
        )
        return EXIT_UNREACHABLE
    note("[dim]Standard Ethernet MTU - no problem[/]")
    return EXIT_OK


async def _cmd_dhcp(listen_s: float) -> int:
    """Detect DHCP servers + the active lease."""
    from systop.core.dhcp import current_lease, discover_servers

    with status("[bold]Checking DHCP..."):
        lease = await current_lease()
        probe = await discover_servers(listen_s=listen_s)

    if _FORMAT == "json":
        emit_json({"lease": lease, "probe": probe})
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(probe.offers or ([lease] if lease else []))
        return EXIT_OK

    t = styled_table("DHCP")
    t.add_column("Source", no_wrap=True)
    t.add_column("Server", no_wrap=True)
    t.add_column("IP")
    t.add_column("Router")
    t.add_column("DNS")
    t.add_column("Lease")
    if lease:
        t.add_row(
            "active lease",
            data_cell(lease.identity),
            data_cell(lease.offered_ip, dash()),
            data_cell(", ".join(lease.routers), dash()),
            data_cell(", ".join(lease.dns), dash()),
            f"{(lease.lease_seconds or 0) // 3600}h" if lease.lease_seconds else dash(),
        )
    for o in probe.offers:
        t.add_row(
            "broadcast",
            data_cell(o.identity),
            data_cell(o.offered_ip, dash()),
            data_cell(", ".join(o.routers), dash()),
            data_cell(", ".join(o.dns), dash()),
            f"{(o.lease_seconds or 0) // 3600}h" if o.lease_seconds else dash(),
        )
    emit_table(t)

    servers = list(probe.servers)
    if lease and lease.identity not in servers:
        servers.append(lease.identity)
    if len(servers) > 1:
        note(f"[{ERROR}]{len(servers)} DHCP servers found - possible rogue DHCP![/]")
        return EXIT_UNREACHABLE
    if probe.partial:
        note(
            "[dim]The broadcast probe got no reply. That does NOT mean 'there is no "
            "server': port 68 cannot be bound without root, and strict RFC servers "
            "answer only on that port. The active lease is the reliable source.[/]"
        )
    return EXIT_OK


async def _cmd_arpwatch(update: bool, reset: bool) -> int:
    """Compares ARP/NDP changes against the baseline."""
    from systop.core.arpwatch import baseline_path, check

    if reset:
        try:
            baseline_path().unlink(missing_ok=True)
            note("[dim]Baseline deleted - it will be written again.[/]")
        except OSError as exc:
            error(f"the baseline was not deleted: {exc}")
            return EXIT_ERROR

    with status("[bold]Comparing the ARP/NDP table..."):
        diff = await check(update=update)

    if _FORMAT == "json":
        emit_json(diff)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(diff.changes)
        return EXIT_OK

    if diff.first_run:
        note(
            f"[dim]First run - {diff.current_hosts} hosts were saved as the baseline "
            f"({baseline_path()}). The next run will show the differences.[/]"
        )
        return EXIT_OK
    if not diff.changes:
        note(f"[{SUCCESS}]No changes[/] - {diff.current_hosts} hosts, same as the baseline.")
        return EXIT_OK

    t = styled_table(f"ARP changes ({len(diff.changes)})")
    t.add_column("Level")
    t.add_column("Kind")
    t.add_column("IP", no_wrap=True)
    t.add_column("Detail", overflow="fold")
    sev_color = {"high": ERROR, "medium": WARNING, "low": SUCCESS, "info": "dim"}
    kind_label = {
        "mac_changed": "MAC changed",
        "duplicate_mac": "duplicate MAC",
        "new_host": "new host",
        "disappeared": "disappeared",
    }
    for c in diff.changes:
        col = sev_color.get(c.severity, "dim")
        if c.kind == "mac_changed":
            detail = f"{c.old_mac} ({c.old_vendor or '?'}) -> {c.new_mac} ({c.new_vendor or '?'})"
        elif c.kind == "duplicate_mac":
            detail = f"{c.new_mac} is currently on: {', '.join([c.ip, *c.extra_ips][:6])}"
        else:
            detail = f"{c.new_mac or c.old_mac or ''} {c.new_vendor or c.old_vendor or ''}"
        t.add_row(
            f"[{col}]{c.severity}[/]",
            kind_label.get(c.kind, c.kind),
            data_cell(c.ip),
            data_cell(detail, dash()),
        )
    emit_table(t)
    if diff.has_suspicious:
        note(
            f"[{WARNING}]There is a MAC swap/duplicate[/] - check for ARP spoofing or "
            "a duplicate IP"
        )
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_wifi(show_neighbours: bool = False) -> int:
    """Wi-Fi state and the surrounding networks."""
    # The name `status` collides with cli.status (the spinner) — take it aliased.
    from systop.core.wifi import overlapping_channels
    from systop.core.wifi import status as wifi_status

    with status("[bold]Reading the Wi-Fi state..."):
        w = await wifi_status()

    if _FORMAT == "json":
        emit_json(w)
        return EXIT_OK if w.connected else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(w.neighbours or [w])
        return EXIT_OK

    if not w.available:
        note(f"[dim]No Wi-Fi hardware on this machine{' — ' + w.error if w.error else ''}.[/]")
        return EXIT_OK
    if not w.connected:
        note(f"[{WARNING}]Wi-Fi is not connected.[/]")
        return EXIT_UNREACHABLE

    qual_color = {
        "excellent": SUCCESS,
        "good": SUCCESS,
        "fair": WARNING,
        "poor": ERROR,
        "unusable": ERROR,
    }
    t = styled_table(f"Wi-Fi{' - ' + w.ssid if w.ssid else ''}")
    t.add_column("Field")
    t.add_column("Value", overflow="fold")
    col = qual_color.get(w.signal_quality or "", WARNING)
    if w.rssi_dbm is not None:
        t.add_row("Signal", f"[{col}]{w.rssi_dbm} dBm[/] ({w.signal_quality})")
    if w.snr_db is not None:
        snr_col = SUCCESS if w.snr_db >= 25 else (WARNING if w.snr_db >= 15 else ERROR)
        t.add_row("SNR", f"[{snr_col}]{w.snr_db} dB[/] (noise {w.noise_dbm} dBm)")
    if w.channel is not None:
        band_col = WARNING if w.is_24ghz and w.five_ghz_available else SUCCESS
        t.add_row("Channel", f"[{band_col}]{w.channel}[/] ({w.band}, {w.width_mhz or '?'} MHz)")
    if w.phy_mode:
        gen_col = WARNING if (w.phy_generation != w.supported_generation) else SUCCESS
        t.add_row(
            "PHY",
            f"[{gen_col}]{w.phy_mode}[/]"
            + (f"  [dim](card: {w.supported_phy})[/]" if w.supported_phy else ""),
        )
    if w.tx_rate_mbps:
        t.add_row("Rate", f"{w.tx_rate_mbps:.0f} Mbps")
    if w.security:
        _weak = "wep" in w.security.lower() or "none" in w.security.lower()
        sec_col = ERROR if _weak else SUCCESS
        t.add_row("Security", f"[{sec_col}]{w.security}[/]")
    if w.country_code:
        t.add_row("Country", w.country_code)
    if w.neighbours:
        bands: dict[str, int] = {}
        for n in w.neighbours:
            bands[n.band or "?"] = bands.get(n.band or "?", 0) + 1
        t.add_row("Neighbours", ", ".join(f"{k}: {v}" for k, v in sorted(bands.items())))
    emit_table(t)

    if w.channel:
        ov = overlapping_channels(w.channel, w.band, w.width_mhz, w.neighbours)
        same = [n for n in ov if n.channel == w.channel]
        if ov:
            hint = (
                "on 2.4 GHz only 1/6/11 do not overlap"
                if w.is_24ghz
                else f"a {w.width_mhz or 20} MHz channel occupies several 20 MHz slots"
            )
            # When everything sits on one channel, writing "2 APs ... 2 of which"
            # is redundant — state the worst case directly.
            if len(same) == len(ov):
                head = f"Channel {w.channel} carries {len(ov)} more APs — full contention"
            elif same:
                head = (
                    f"{len(ov)} APs are interfering with channel {w.channel}, "
                    f"{len(same)} of them on EXACTLY that channel"
                )
            else:
                head = f"{len(ov)} APs overlap channel {w.channel}"
            note(f"[{WARNING}]{head}[/] [dim]({hint})[/]")
    if w.is_24ghz and w.five_ghz_available:
        note(f"[{WARNING}]5 GHz is available nearby[/] - moving to it raises the speed a lot.")

    if show_neighbours and w.neighbours:
        # The interfering ones are marked SEPARATELY and lifted to the top — the
        # point of this table is not "who is around" but "who is interfering with
        # me". The user should not have to compare the channels by hand.
        clashing: set[int] = set()
        if w.channel:
            clashing = {
                id(n) for n in overlapping_channels(w.channel, w.band, w.width_mhz, w.neighbours)
            }

        nt = styled_table(f"Surrounding networks ({len(w.neighbours)})")
        nt.add_column("Name (SSID)")
        nt.add_column("Channel", justify="right")
        nt.add_column("Band")
        nt.add_column("Width", justify="right")
        nt.add_column("Interference")
        nt.add_column("PHY")
        nt.add_column("Security")
        for n in sorted(
            w.neighbours,
            key=lambda x: (id(x) not in clashing, x.band or "", x.channel or 0),
        ):
            hits = id(n) in clashing
            if hits:
                same = n.channel == w.channel
                mark = f"[{ERROR}]same channel[/]" if same else f"[{WARNING}]overlaps[/]"
            else:
                mark = "[dim]none[/]"
            nt.add_row(
                data_cell(n.ssid, dash()),
                str(n.channel or dash()),
                n.band or dash(),
                f"{n.width_mhz} MHz" if n.width_mhz else dash(),
                mark,
                data_cell(n.phy_mode, dash()),
                data_cell(n.security, dash()),
            )
        emit_table(nt)

        # Since macOS Sonoma the SSID is withheld without Location Services
        # permission ("<redacted>"). Silently leaving an empty column is wrong —
        # the user concludes the tool is broken.
        if not any(n.ssid for n in w.neighbours):
            note(
                "[dim]The SSID names are hidden by the OS. On macOS: "
                "System Settings -> Privacy -> Location Services -> grant the "
                "terminal permission.[/]"
            )
    return EXIT_OK


async def _cmd_info() -> int:
    from systop.core.netinfo import gather_summary

    with status("[bold]Gathering network information..."):
        summary = await gather_summary()

    if _FORMAT == "json":
        emit_json(summary)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(summary.interfaces)
        return EXIT_OK

    table = styled_table("Network interfaces")
    table.add_column("Interface", no_wrap=True)
    table.add_column("IPv4", no_wrap=True)
    table.add_column("Network", no_wrap=True)
    # min_width — keep the header readable even when the column is empty.
    table.add_column("IPv6", overflow="ellipsis", min_width=6)
    table.add_column("MAC", no_wrap=True)
    table.add_column("State")
    for iface in summary.interfaces:
        if iface.is_up:
            st = f"[{SUCCESS}]{glyph('ok')}[/] up"
        else:
            st = f"[{ERROR}]{glyph('dead')}[/] down"
        # Network: CIDR + host capacity ("10.0.0.0/24 · 254") — so the size is
        # visible at a glance. The IPv6 column shows the global address ONLY:
        # link-local exists on nearly every interface and tells you nothing here.
        net = f"{iface.cidr} {glyph('sep')} {iface.host_count}" if iface.cidr else None
        v6 = iface.ipv6_global[0] if iface.ipv6_global else None
        table.add_row(
            data_cell(iface.name),
            data_cell(iface.ipv4, dash()),
            data_cell(net, dash()),
            data_cell(v6, dash()),
            data_cell(iface.mac, dash()),
            st,
        )
    emit_table(table)
    # A prefix next to the gateway: `/24` tells you the network size at a glance.
    primary = next((i for i in summary.interfaces if i.prefixlen and i.ipv4), None)
    gw_text = summary.gateway or dash()
    if summary.gateway and primary:
        gw_text = f"{summary.gateway}/{primary.prefixlen}"
    note(
        f"\n[{WARNING}]{glyph('gateway')}[/] gateway [bold]{gw_text}[/]   "
        f"[dim]public IP[/] [bold]{summary.public_ip or dash()}[/]"
    )
    return EXIT_OK


def _split_host_port(value: str, default_port: int) -> tuple[str, int]:
    """'host:port' or 'host' => (host, port). IPv6 '[::1]:443' is supported too."""
    if value.startswith("[") and "]" in value:
        host, _, rest = value[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host, int(port)
    return value, default_port


if __name__ == "__main__":
    main()
