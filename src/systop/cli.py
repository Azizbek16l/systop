"""systop CLI — default holatda dashboard'ni ochadi.

Qo'shimcha tez (bir martalik, scriptlarga mos) buyruqlar ham bor:
    systop              -> interaktiv dashboard (TUI)
    systop dashboard    -> xuddi shu
    systop speed        -> tezlik testi, jadval bilan chiqaradi
    systop ping         -> lokal + global ping (--ipv6, --watch)
    systop trace HOST   -> traceroute
    systop mtr HOST     -> jonli mtr-uslubi traceroute (Ctrl+C to'xtatadi)
    systop lan          -> LAN host discovery (vendor bilan)
    systop scan HOST    -> TCP port skaner
    systop dns NAME     -> DNS resolve + serverlar latency taqqoslash
    systop bw           -> per-interfeys bandwidth (--watch jonli)
    systop tls HOST     -> TLS sertifikat tekshiruvi (muddat, issuer, SAN)
    systop http URL     -> HTTP holat tekshiruvi (status, redirect, vaqt)
    systop conn         -> faol tarmoq ulanishlari (--listen faqat LISTEN)
    systop config       -> joriy konfiguratsiya / fayl yo'li
    systop info         -> interfeyslar, gateway, public IP

Skriptlar uchun global bayroqlar:
    --json / --format {table,json,csv}   mashinaga mos chiqish (sof stdout)
    -q/--quiet, -v/--verbose             gaplashish darajasi
    --no-color                           ranglarsiz (NO_COLOR env ham hurmat)

Exit kodlari (skriptlar farqlay olsin):
    0  muvaffaqiyat
    1  umumiy xato (noto'g'ri argument, ichki xato)
    2  nishonga yetib bo'lmadi / host o'lik / port yopiq /
       sertifikat muddati tugagan yoki yaqin / resolve bo'lmadi
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
from systop.widgets._glyphs import dash, glyph

# Exit kodlari — mazmunli, skriptlar uchun.
EXIT_OK = 0
EXIT_ERROR = 1  # umumiy xato
EXIT_UNREACHABLE = 2  # nishon yetib bo'lmaydi / o'lik / muddat tugagan

# Global chiqish formati (main() tomonidan o'rnatiladi).
_FORMAT = "table"  # table | json | csv
_QUIET = False
_VERBOSE = False


def _stream_encoding_is_safe(stream: object) -> bool:
    """Oqim kodlashi Unicode (kamida UTF) chiqishini xavfsiz qabul qiladimi?

    POSIX'da `LANG=C`/`LC_ALL=C` ostida stdout `ascii` codec'ida bo'ladi —
    o'zbekcha matn yoki JSON'dagi har qanday ASCII-bo'lmagan belgi
    `UnicodeEncodeError` ko'taradi. Shu holatni aniqlash uchun: kodlash nomi
    `utf` bilan boshlanmasa (ascii/ANSI_X3.4/POSIX/C) — xavfsiz emas.
    """
    enc = getattr(stream, "encoding", None)
    if not enc:
        # Kodlash noma'lum (qayta yo'naltirilgan / g'ayrioddiy oqim) — himoyalaymiz.
        return False
    return enc.lower().replace("-", "").startswith("utf")


def _harden_console_streams() -> None:
    """stdout/stderr'ni ASCII-bo'lmagan chiqishda yiqilmaydigan qiladi.

    Ikki holatni qoplaydi:

    * **Windows** — legacy konsol OEM/cp1252 codepage'da; emoji/Unicode
      `UnicodeEncodeError` beradi.
    * **POSIX C/ASCII lokal** (`LANG=C`) — stdout `ascii` codec'ida; o'zbekcha
      matn yoki JSON'dagi har qanday non-ASCII belgi ham yiqitadi.

    Har ikkalasida `errors="replace"` bilan UTF-8 ga o'tkazamiz: ko'rsata
    olmaydigan terminalda belgi `?`/`\\ufffd` ga aylanadi, ammo hech qachon
    istisno ko'tarilmaydi (CLI skript-do'st bo'lib qoladi). Allaqachon UTF
    bo'lgan oqimga tegmaymiz (macOS/Linux odatiy holati o'zgarmaydi).
    """
    for stream in (sys.stdout, sys.stderr):
        if _stream_encoding_is_safe(stream):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            # reconfigure yo'q (eski Python / o'ralgan oqim) — jim davom etamiz;
            # quyidagi emit_json/print yo'llari baribir errors="replace" qiladi.
            pass


# Windows konsoli (UTF-8 + VT) — `_platform.init_console` orqali; keyin oqimlarni
# har platformada (POSIX C lokal ham) ASCII-xavfsiz qilamiz.
_platform.init_console()
_harden_console_streams()

# Emoji UMUMAN render qilinmaydi (dizayn: belgilar faqat `glyph()` orqali, monoxrom).
# `--no-color`/`NO_COLOR` chinakam monoxrom bo'lsin — `_apply_color` qayta yaratadi.
console = Console(emoji=False)


# --------------------------------------------------------------------------- #
# Chiqishni boshqarish: faqat "table" rejimida Rich/status ko'rsatiladi.
# json/csv rejimida sof mashinaga mos chiqish stdout'ga boradi, status emas.
# --------------------------------------------------------------------------- #


def _is_machine() -> bool:
    """JSON yoki CSV (mashinaga mos) rejim faolmi?"""
    return _FORMAT in ("json", "csv")


class _NullStatus:
    """`console.status` o'rnini bosuvchi no-op (machine/quiet rejimida)."""

    def __enter__(self) -> _NullStatus:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def status(message: str) -> Any:
    """Faqat table rejimida (va quiet emas) jonli status ko'rsatadi."""
    if _is_machine() or _QUIET:
        return _NullStatus()
    return console.status(message)


def emit_table(table: Table) -> None:
    """Rich jadval — faqat table rejimida chiqaradi."""
    if not _is_machine():
        console.print(table)


def note(message: str) -> None:
    """Qo'shimcha izoh (table rejimida, quiet bo'lmasa)."""
    if not _is_machine() and not _QUIET:
        console.print(message)


def verbose(message: str) -> None:
    """Faqat -v berilganda va table rejimida chiqadigan batafsil xabar."""
    if _VERBOSE and not _is_machine():
        console.print(f"[dim]{message}[/]")


def _safe_write(stream: Any, text: str) -> None:
    """Matnni oqimga yozadi; ASCII lokalda ham hech qachon yiqilmaydi.

    `reconfigure` muvaffaqiyatsiz bo'lgan (o'ralgan / eski Python) oqimda
    `UnicodeEncodeError` bo'lishi mumkin — bunda oqim kodlashiga `errors="replace"`
    bilan qayta kodlab, `buffer`ga yozamiz. Bu — emit_json/error uchun oxirgi
    himoya qatlami (POSIX `LANG=C`).
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
            # buffer yo'q (StringIO va h.k.) — replacement belgilar bilan qayta yozamiz.
            stream.write(data.decode(enc, errors="replace"))


def error(message: str) -> None:
    """Xato xabari — JSON/CSV rejimida ham stderr'ga (stdout toza qoladi)."""
    if _is_machine():
        _safe_write(sys.stderr, message + "\n")
    else:
        console.print(f"[{ERROR}]Xato:[/] {message}")


# --------------------------------------------------------------------------- #
# Seriyalashtirish: core dataclass'larni JSON/CSV uchun lug'atga aylantirish.
# Hisoblanadigan (property) maydonlar `asdict` ga kirmaydi — qo'lda qo'shamiz.
# Ichki (_ bilan boshlanuvchi) maydonlar olib tashlanadi.
# --------------------------------------------------------------------------- #


def _to_dict(obj: Any) -> Any:
    """Dataclass'ni tozalangan lug'atga aylantiradi (property'lar bilan).

    - `_` bilan boshlanuvchi ichki maydonlar olib tashlanadi.
    - Tanlangan dataclass'larga mos hisoblanadigan property'lar qo'shiladi
      (loss_pct, cidr, total_bps, ...), shunda JSON to'liq bo'ladi.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            if f.name.startswith("_"):
                continue
            out[f.name] = _to_dict(getattr(obj, f.name))
        # Foydali hisoblanadigan property'larni qo'lda qo'shamiz.
        for prop in ("loss_pct", "cidr", "total_bps", "is_open"):
            if hasattr(type(obj), prop) and isinstance(getattr(type(obj), prop), property):
                out[prop] = getattr(obj, prop)
        return out
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(v) for v in obj]
    return obj


def emit_json(payload: Any) -> None:
    """Payload'ni sof JSON sifatida stdout'ga yozadi (faqat json rejimi).

    `ensure_ascii=False` — o'zbekcha/kirill matn o'qishli chiqsin. ASCII lokalda
    (`LANG=C`) bu non-ASCII baytlar yiqitishi mumkin edi; `_safe_write` oxirgi
    himoya qatlami (errors="replace" bilan qayta kodlaydi).
    """
    _safe_write(sys.stdout, json.dumps(_to_dict(payload), ensure_ascii=False, indent=2) + "\n")


def emit_csv(rows: Iterable[Any]) -> None:
    """Dataclass/dict ro'yxatini CSV sifatida stdout'ga yozadi (csv rejimi).

    Ustunlar birinchi qatordagi kalitlardan olinadi; ichma-ich (list/dict)
    qiymatlar JSON satriga aylantiriladi (CSV tekis bo'lishi uchun).
    """
    dict_rows = [_flatten_for_csv(_to_dict(r)) for r in rows]
    if not dict_rows:
        # Bo'sh natija — hech bo'lmasa header yo'qligini bildirib, jim chiqamiz.
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
    """CSV uchun: ichma-ich list/dict qiymatlarni JSON satriga aylantiradi."""
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
# Argument tahlili
# --------------------------------------------------------------------------- #


def _add_global_flags(parser: argparse.ArgumentParser) -> None:
    """Skriptga mos global bayroqlarni (har joyda) qo'shadi."""
    parser.add_argument(
        "--json",
        action="store_true",
        help="natijani sof JSON sifatida chiqarish (Rich jadval emas)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default=None,
        help="chiqish formati: table (default), json yoki csv",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="kamroq chiqish (faqat natija)")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="batafsil chiqish (diagnostika)"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="rangsiz chiqish (NO_COLOR ham hurmat)"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="systop",
        description="Sysadminlar uchun tarmoq TUI: tezlik, ping, topologiya.",
    )
    parser.add_argument("--version", action="version", version=f"systop {__version__}")
    _add_global_flags(parser)
    sub = parser.add_subparsers(dest="command")

    def _with_globals(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        _add_global_flags(p)
        return p

    _with_globals(sub.add_parser("dashboard", help="Interaktiv TUI dashboard (default)"))
    _with_globals(sub.add_parser("speed", help="Internet tezligini o'lchash"))

    p_ping = _with_globals(
        sub.add_parser("ping", help="Lokal gateway + global serverlarni ping qilish")
    )
    p_ping.add_argument("--ipv6", action="store_true", help="IPv6 global nishonlarni ham qo'shish")
    p_ping.add_argument(
        "--watch",
        action="store_true",
        help="Doimiy ping: har soniyada jonli statistika (Ctrl+C to'xtatadi)",
    )
    p_ping.add_argument(
        "--targets",
        default=None,
        help="vergul bilan ajratilgan nishonlar (config'ni override qiladi)",
    )

    p_trace = _with_globals(sub.add_parser("trace", help="Traceroute (manzilgacha yo'l)"))
    p_trace.add_argument("host", nargs="?", default="8.8.8.8", help="nishon (default 8.8.8.8)")
    p_trace.add_argument(
        "--continuous",
        action="store_true",
        help="jonli mtr-uslubi (mtr buyrug'i bilan bir xil)",
    )

    p_mtr = _with_globals(sub.add_parser("mtr", help="Jonli mtr-uslubi traceroute"))
    p_mtr.add_argument("host", nargs="?", default="8.8.8.8", help="nishon (default 8.8.8.8)")
    p_mtr.add_argument(
        "--interval", type=float, default=1.0, help="probe oralig'i (soniya, default 1.0)"
    )
    p_mtr.add_argument(
        "--cycles", type=int, default=None, help="necha marta probe (default: cheksiz)"
    )

    p_scan = _with_globals(sub.add_parser("scan", help="TCP port skaner (ochiq portlarni topish)"))
    p_scan.add_argument("host", help="skaner qilinadigan host (IP yoki nom)")
    p_scan.add_argument(
        "--ports",
        default=None,
        help="portlar: '22,80,443' yoki '1-1024' (default: keng tarqalganlar)",
    )
    p_scan.add_argument(
        "--timeout", type=float, default=1.5, help="har bir port uchun timeout (soniya)"
    )

    p_dns = _with_globals(sub.add_parser("dns", help="DNS resolve + serverlar latency taqqoslash"))
    p_dns.add_argument("name", help="resolve qilinadigan domen nomi")
    p_dns.add_argument(
        "--resolvers",
        default=None,
        help="vergul bilan ajratilgan DNS serverlar (config'ni override qiladi)",
    )

    p_bw = _with_globals(sub.add_parser("bw", help="Per-interfeys bandwidth (RX/TX)"))
    p_bw.add_argument("--watch", action="store_true", help="jonli oqim (Ctrl+C to'xtatadi)")
    p_bw.add_argument(
        "--interval", type=float, default=1.0, help="o'lchov oralig'i (soniya, default 1.0)"
    )

    p_tls = _with_globals(sub.add_parser("tls", help="TLS sertifikat tekshiruvi"))
    p_tls.add_argument("host", help="host yoki host:port (default port 443)")
    p_tls.add_argument("--timeout", type=float, default=5.0, help="ulanish timeout (soniya)")
    p_tls.add_argument(
        "--warn-days",
        type=int,
        default=14,
        help="muddat shu kundan kam qolsa nonzero exit (default 14)",
    )

    p_http = _with_globals(sub.add_parser("http", help="HTTP holat tekshiruvi"))
    p_http.add_argument("url", help="tekshiriladigan URL (https://... yoki http://...)")
    p_http.add_argument("--timeout", type=float, default=5.0, help="so'rov timeout (soniya)")

    p_conn = _with_globals(sub.add_parser("conn", help="Faol tarmoq ulanishlari"))
    p_conn.add_argument(
        "--listen", action="store_true", help="faqat LISTEN holatdagilarni ko'rsatish"
    )

    p_cfg = _with_globals(sub.add_parser("config", help="Joriy konfiguratsiya / fayl yo'li"))
    p_cfg.add_argument(
        "--path", action="store_true", help="faqat konfiguratsiya fayl yo'lini chiqarish"
    )
    p_cfg.add_argument(
        "--show", action="store_true", help="joriy (samarali) sozlamalarni ko'rsatish"
    )

    _with_globals(sub.add_parser("lan", help="Lokal tarmoq hostlarini topish"))
    _with_globals(sub.add_parser("info", help="Tarmoq interfeyslari va public IP"))

    return parser


def _resolve_format(args: argparse.Namespace) -> str:
    """--json va --format dan yakuniy formatni aniqlaydi (--json ustun emas, mos)."""
    if args.format:
        return args.format
    if args.json:
        return "json"
    return "table"


def _apply_color(no_color: bool) -> None:
    """Rang sozlamasini qo'llaydi: --no-color yoki NO_COLOR env => rangsiz."""
    global console
    disabled = no_color or bool(os.environ.get("NO_COLOR"))
    # Emoji har doim o'chiq (dizayn: belgilar faqat glyph()). Mashina yoki
    # --no-color/NO_COLOR rejimida rang ham o'chadi — chinakam monoxrom chiqish.
    if disabled or _is_machine():
        console = Console(no_color=True, highlight=False, emoji=False)


def _split_csv_arg(value: str | None) -> list[str]:
    """'a, b ,c' => ['a','b','c'] (bo'sh elementlar tashlanadi)."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> None:
    global _FORMAT, _QUIET, _VERBOSE

    # Konsolni (Windows UTF-8/VT + POSIX C-lokal himoyasi) ishonchli holatga
    # keltiramiz. Modul importida bir marta chaqirilgan, ammo `main()` to'g'ridan
    # chaqirilgan (test/embed) holat uchun ham idempotent ravishda takrorlaymiz.
    _platform.init_console()
    _harden_console_streams()

    parser = _build_parser()

    # Ixtiyoriy shell completion — argcomplete o'rnatilgan bo'lsa.
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
        note("\n[dim]To'xtatildi.[/]")
        code = EXIT_OK
    except Exception as exc:  # noqa: BLE001 — CLI chegarasi: xatoni kodga aylantiramiz
        error(str(exc))
        code = EXIT_ERROR

    sys.exit(code)


async def _dispatch(command: str, args: argparse.Namespace) -> int:
    """Buyruqni mos handler'ga yo'naltiradi; exit kod qaytaradi."""
    if command == "speed":
        return await _cmd_speed()
    if command == "ping":
        return await _cmd_ping(ipv6=args.ipv6, watch=args.watch, targets_arg=args.targets)
    if command == "trace":
        if getattr(args, "continuous", False):
            return await _cmd_mtr(args.host, interval=1.0, cycles=None)
        return await _cmd_trace(args.host)
    if command == "mtr":
        return await _cmd_mtr(args.host, interval=args.interval, cycles=args.cycles)
    if command == "scan":
        return await _cmd_scan(args.host, args.ports, args.timeout)
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
        return await _cmd_lan()
    if command == "info":
        return await _cmd_info()
    error(f"Noma'lum buyruq: {command}")
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# Buyruqlar
# --------------------------------------------------------------------------- #


async def _cmd_speed() -> int:
    from systop.core.config import load_config
    from systop.core.speed import run_speedtest

    cfg = load_config()
    verbose(f"speed_duration={cfg.speed_duration}s parallel={cfg.speed_parallel}")
    with status("[bold]Tezlik o'lchanmoqda (latency → download → upload)..."):
        result = await run_speedtest(duration=cfg.speed_duration, parallel=cfg.speed_parallel)

    if _FORMAT == "json":
        emit_json(result)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv([result])
        return EXIT_OK

    table = styled_table("Internet tezligi")
    table.show_header = False
    table.add_column("Ko'rsatkich")
    table.add_column("Qiymat", justify="right")
    table.add_row(f"{glyph('download')} Download", f"[{SUCCESS}]{result.download_mbps:.1f}[/] Mbps")
    table.add_row(f"{glyph('upload')} Upload", f"[{SECONDARY}]{result.upload_mbps:.1f}[/] Mbps")
    # Jitter ALOHIDA qator emas — latency qatoriga so'z bilan (TUI'dagidek).
    table.add_row(
        f"{glyph('latency')} Latency",
        f"{result.latency_ms:.1f} ms   [dim]jitter {result.jitter_ms:.1f} ms[/]",
    )
    emit_table(table)
    note(f"[dim]download {result.download_mbps:.1f} · upload {result.upload_mbps:.1f} Mbps[/]")
    return EXIT_OK


async def _cmd_ping(ipv6: bool = False, watch: bool = False, targets_arg: str | None = None) -> int:
    from systop.core.config import load_config
    from systop.core.netinfo import default_gateway
    from systop.core.ping import build_targets, ping_many

    extra: dict[str, str] = {}
    explicit = _split_csv_arg(targets_arg)
    if not explicit:
        # Config'dagi ping nishonlarini qo'shimcha sifatida ulaymiz.
        explicit = list(load_config().ping_targets)
    for addr in explicit:
        extra[addr] = addr

    if targets_arg:
        # Foydalanuvchi aniq nishonlar bergan — faqat shularni ping qilamiz.
        targets = {addr: addr for addr in _split_csv_arg(targets_arg)}
    else:
        targets = build_targets(default_gateway(), include_ipv6=ipv6, extra_targets=extra)

    if watch:
        return await _cmd_ping_watch(targets)

    with status("[bold]Ping qilinmoqda..."):
        results = await ping_many(targets)

    if _FORMAT == "json":
        emit_json(results)
    elif _FORMAT == "csv":
        emit_csv(results)
    else:
        table = styled_table("Ping natijalari")
        table.add_column("Holat")
        table.add_column("Nishon")
        table.add_column("Manzil")
        table.add_column("Avg ms", justify="right")
        table.add_column("Loss %", justify="right")
        for r in results:
            avg = rtt_cell(r.avg_rtt) if r.alive else f"[dim]{dash()}[/]"
            table.add_row(alive_cell(r.alive), r.label, r.address, avg, loss_cell(r.loss_pct))
        emit_table(table)
        alive = sum(1 for r in results if r.alive)
        dead = len(results) - alive
        note(f"[dim]{len(results)} nishon — {alive} tirik · {dead} o'lik[/]")

    # Hech bir nishon javob bermasa — tarmoq yo'q deb hisoblaymiz.
    return EXIT_OK if any(r.alive for r in results) else EXIT_UNREACHABLE


async def _cmd_ping_watch(targets: dict[str, str]) -> int:
    """Doimiy ping: barcha nishonlarni parallel, jonli yangilanuvchi jadval."""
    import contextlib

    from rich.live import Live

    from systop.core.ping import WatchStats, ping_stream

    if _is_machine():
        error("--watch faqat table rejimida ishlaydi (json/csv emas).")
        return EXIT_ERROR

    stats: dict[str, WatchStats] = {}

    def render() -> Table:
        table = styled_table("Ping monitor (Ctrl+C to'xtatadi)")
        table.add_column("Nishon")
        table.add_column("Manzil")
        table.add_column("Oxirgi ms", justify="right")
        table.add_column("Avg ms", justify="right")
        table.add_column("Min/Max ms", justify="right")
        table.add_column("Yuborildi", justify="right")
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
    note("\n[dim]Monitor to'xtatildi.[/]")
    return EXIT_OK


async def _cmd_scan(host: str, ports_spec: str | None, timeout: float) -> int:
    from systop.core.ports import parse_ports, scan_host

    ports = parse_ports(ports_spec) if ports_spec else None
    if ports_spec and not ports:
        error(f"'{ports_spec}' portlar ro'yxati noto'g'ri.")
        return EXIT_ERROR

    count = len(ports) if ports else "keng tarqalgan"
    with status(f"[bold]{host} skaner qilinmoqda ({count} port)..."):
        result = await scan_host(host, ports=ports, timeout=timeout)

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
        f"Port skaner {glyph('gateway')} {result.host} "
        f"({result.resolved_ip}) — {len(open_ports)} ochiq"
    )
    table = styled_table(title)
    table.add_column("Port", justify="right")
    table.add_column("Holat")
    table.add_column("Xizmat")
    table.add_column("RTT ms", justify="right")
    if not open_ports:
        emit_table(table)
        note(f"[{WARNING}]Hech qaysi port ochiq emas[/] ({len(result.ports)} ta tekshirildi).")
        return EXIT_UNREACHABLE
    for p in open_ports:
        table.add_row(str(p.port), f"[{SUCCESS}]ochiq[/]", p.service or dash(), rtt_cell(p.rtt_ms))
    emit_table(table)
    filtered = sum(1 for p in result.ports if p.state == "filtered")
    closed = sum(1 for p in result.ports if p.state == "closed")
    note(
        f"[dim]{len(result.ports)} port tekshirildi — "
        f"{len(open_ports)} ochiq · {closed} yopiq · {filtered} filtrlangan[/]"
    )
    return EXIT_OK


async def _cmd_dns(name: str, resolvers_arg: str | None = None) -> int:
    from systop.core.config import load_config
    from systop.core.dns import diagnose_dns

    resolvers = _split_csv_arg(resolvers_arg)
    if not resolvers:
        resolvers = list(load_config().dns_resolvers)
    verbose(f"resolverlar: {', '.join(resolvers) or '(default)'}")

    with status(f"[bold]{name} uchun DNS diagnostika..."):
        result = await diagnose_dns(name)

    if _FORMAT == "json":
        emit_json(result)
        return EXIT_OK if not result.system_error else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(result.resolvers)
        return EXIT_OK if not result.system_error else EXIT_UNREACHABLE

    if result.system_error:
        error(f"Tizim resolveri: {result.system_error}")
    else:
        addrs = ", ".join(result.system_addresses) or dash()
        note(f"[dim]Tizim resolveri:[/] [bold]{addrs}[/]")

    if not result.resolvers:
        note(
            f"\n[{WARNING}]`dig`/`nslookup` topilmadi[/] — serverlar latency'sini "
            "taqqoslab bo'lmadi (faqat tizim resolve ko'rsatildi)."
        )
        return EXIT_OK if not result.system_error else EXIT_UNREACHABLE

    table = styled_table(f"DNS serverlar taqqoslovi ({result.tool})")
    table.add_column("Server")
    table.add_column("IP")
    table.add_column("RTT ms", justify="right")
    table.add_column("Javob (manzillar)")
    table.add_column("Holat")
    fastest = min((r for r in result.resolvers if r.ok), key=lambda r: r.rtt_ms, default=None)
    for r in result.resolvers:
        if r.ok:
            mark = f"[b {SUCCESS}]eng tez[/]" if r is fastest else f"[{SUCCESS}]tirik[/]"
            rtt = rtt_cell(r.rtt_ms)
            answers = ", ".join(r.addresses[:3])
            if len(r.addresses) > 3:
                answers += f" (+{len(r.addresses) - 3})"
        else:
            mark = f"[{ERROR}]{r.error or 'xato'}[/]"
            rtt = f"[dim]{dash()}[/]"
            answers = dash()
        table.add_row(r.name, r.server, rtt, answers, mark)
    emit_table(table)
    if fastest is not None:
        note(f"[dim]eng tez: {fastest.name} ({fastest.server}) — {fastest.rtt_ms:.1f} ms[/]")
    return EXIT_OK if not result.system_error else EXIT_UNREACHABLE


async def _cmd_trace(host: str) -> int:
    from systop.core.topology import trace_path

    with status(f"[bold]{host} gacha traceroute..."):
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
        note(f"[{WARNING}]Hech qanday hop topilmadi (yo'l yopiq yoki bloklangan).[/]")
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
    note(f"[dim]{len(result.hops)} hop — {alive_hops} javob berdi[/]")
    return EXIT_OK


async def _cmd_mtr(host: str, interval: float = 1.0, cycles: int | None = None) -> int:
    """Jonli mtr-uslubi traceroute: trace_stream + rich.Live (Ctrl+C to'xtatadi)."""
    from systop.core.topology import HopStat, trace_stream

    # JSON/CSV rejimida cheksiz oqim mantiqsiz — bir necha cycle olib, oxirgisini chiqaramiz.
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
        table = styled_table(f"mtr {glyph('gateway')} {host} (Ctrl+C to'xtatadi)")
        table.add_column("#", justify="right")
        table.add_column("Host")
        table.add_column("Loss %", justify="right")
        table.add_column("Yub.", justify="right")
        table.add_column("Oxirgi", justify="right")
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
    note("\n[dim]mtr to'xtatildi.[/]")
    return EXIT_OK if saw_hops else EXIT_UNREACHABLE


async def _cmd_bw(watch: bool = False, interval: float = 1.0) -> int:
    from systop.core.bandwidth import bandwidth_stream, sample_bandwidth

    if watch and _is_machine():
        error("--watch faqat table rejimida ishlaydi (json/csv emas).")
        return EXIT_ERROR

    if not watch:
        with status(f"[bold]Bandwidth o'lchanmoqda ({interval:.1f}s)..."):
            rates = await sample_bandwidth(interval=interval)
        if _FORMAT == "json":
            emit_json(rates)
            return EXIT_OK
        if _FORMAT == "csv":
            emit_csv(rates)
            return EXIT_OK
        emit_table(_bw_table(rates))
        return EXIT_OK

    # --watch: jonli oqim (faqat table rejimi).
    from rich.live import Live

    with Live(_bw_table([]), console=console, refresh_per_second=2) as live:
        try:
            async for rates in bandwidth_stream(interval=interval):
                live.update(_bw_table(rates))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
    note("\n[dim]Bandwidth monitor to'xtatildi.[/]")
    return EXIT_OK


def _human_bps(bps: float) -> str:
    """bit/sekundni odamga o'qishli birlikka aylantiradi (bps/Kbps/Mbps/Gbps)."""
    units = ("bps", "Kbps", "Mbps", "Gbps", "Tbps")
    value = float(bps)
    idx = 0
    while value >= 1000.0 and idx < len(units) - 1:
        value /= 1000.0
        idx += 1
    return f"{value:.1f} {units[idx]}"


def _bw_table(rates: list[Any]) -> Table:
    """IfaceRate ro'yxatidan Rich jadval yasaydi (RX/TX human-readable)."""
    table = styled_table("Interfeys bandwidth (Ctrl+C to'xtatadi)")
    table.add_column("Interfeys")
    table.add_column(f"{glyph('download')} RX", justify="right")
    table.add_column(f"{glyph('upload')} TX", justify="right")
    table.add_column("RX pps", justify="right")
    table.add_column("TX pps", justify="right")
    table.add_column("Umumiy", justify="right")
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
    with status(f"[bold]{target}:{port} TLS tekshirilmoqda..."):
        result = await check_tls(target, port=port, timeout=timeout)

    if _FORMAT == "json":
        emit_json(result)
        return _tls_exit_code(result, warn_days)
    if _FORMAT == "csv":
        emit_csv([result])
        return _tls_exit_code(result, warn_days)

    if not result.ok:
        error(result.error or "TLS tekshiruvi muvaffaqiyatsiz.")
        return EXIT_UNREACHABLE

    table = styled_table(f"TLS sertifikat {glyph('gateway')} {result.host}:{result.port}")
    table.show_header = False
    table.add_column("Maydon")
    table.add_column("Qiymat")
    days = result.days_left
    if days is None:
        days_str = dash()
    elif days < 0:
        days_str = f"[{ERROR}]muddati tugagan ({-days} kun oldin)[/]"
    elif days <= warn_days:
        days_str = f"[{WARNING}]{days} kun (yaqin!)[/]"
    else:
        days_str = f"[{SUCCESS}]{days} kun[/]"
    table.add_row("Muddat", days_str)
    table.add_row("Tugaydi", result.not_after or dash())
    table.add_row("Issuer", result.issuer or dash())
    table.add_row("Subject", result.subject or dash())
    table.add_row("SAN soni", str(len(result.san)))
    table.add_row("TLS versiya", result.tls_version or dash())
    emit_table(table)
    code = _tls_exit_code(result, warn_days)
    if code == EXIT_OK:
        note(f"[dim]exit 0 · warn-days {warn_days} chegarasidan uzoq[/]")
    elif days is not None and days < 0:
        note("[dim]exit 2 · sertifikat muddati tugagan[/]")
    else:
        note(f"[dim]exit 2 · muddat warn-days {warn_days} chegarasiga yaqin[/]")
    return code


def _tls_exit_code(result: Any, warn_days: int) -> int:
    """TLS natijasidan exit kod: xato yoki muddat tugagan/yaqin => nonzero."""
    if not result.ok:
        return EXIT_UNREACHABLE
    if result.days_left is not None and result.days_left <= warn_days:
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_http(url: str, timeout: float = 5.0) -> int:
    from systop.core.tls import check_http

    if "://" not in url:
        url = "https://" + url
    with status(f"[bold]{url} so'ralmoqda..."):
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
    table.add_column("Maydon")
    table.add_column("Qiymat")
    status_code = result.status or 0
    if 200 <= status_code < 400:
        status_str = f"[{SUCCESS}]{status_code}[/]"
    else:
        status_str = f"[{ERROR}]{status_code}[/]"
    table.add_row("Status", status_str)
    table.add_row("Yakuniy URL", result.final_url or dash())
    table.add_row("Vaqt", f"{result.elapsed_ms:.0f} ms")
    table.add_row("Server", result.server or dash())
    if result.redirects:
        table.add_row("Redirect'lar", " -> ".join(result.redirects))
    emit_table(table)
    code = _http_exit_code(result)
    note(f"[dim]exit {code} · {result.elapsed_ms:.0f} ms[/]")
    return code


def _http_exit_code(result: Any) -> int:
    """HTTP natijasidan exit kod: xato yoki >=400 status => nonzero."""
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

    table = styled_table(f"Tarmoq ulanishlari ({len(conns)} ta)")
    table.add_column("Proto")
    table.add_column("Lokal")
    table.add_column("Masofaviy")
    table.add_column("Holat")
    table.add_column("PID", justify="right")
    table.add_column("Jarayon")
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
            f"[{WARNING}]Ulanishlar topilmadi[/] — macOS'da to'liq jadval uchun "
            "ko'pincha root (sudo) kerak bo'ladi."
        )
    else:
        listening = sum(1 for c in conns if c.status == "LISTEN")
        note(f"[dim]{len(conns)} ulanish — {listening} LISTEN[/]")
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
        # Skript uchun: sof yo'l (Rich markup'siz, `$(systop config --path)` mos).
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
    note(f"[dim]Konfiguratsiya fayli:[/] [bold]{cfg_path}[/]")
    state = f"[{SUCCESS}]mavjud[/]" if exists else f"[{WARNING}]yo`q (default ishlatiladi)[/]"
    note(f"[dim]Holat:[/] {state}")
    note(f"[dim]Env override ({ENV_VAR}):[/] {os.environ.get(ENV_VAR) or dash()}")

    if show or not exists:
        table = styled_table("Joriy (samarali) sozlamalar")
        table.add_column("Maydon")
        table.add_column("Qiymat")
        for name in config_fields():
            value = getattr(cfg, name)
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            table.add_row(name, str(value))
        emit_table(table)
    return EXIT_OK


async def _cmd_lan() -> int:
    from systop.core.topology import discover_lan

    with status("[bold]LAN skanerlanmoqda..."):
        hosts = await discover_lan(resolve=True)

    if _FORMAT == "json":
        emit_json(hosts)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(hosts)
        return EXIT_OK

    table = styled_table(f"LAN hostlar ({len(hosts)} ta)")
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Hostname")
    table.add_column("RTT ms", justify="right")
    table.add_column("Rol")
    for h in hosts:
        role = f"[{WARNING}]{glyph('gateway')}[/] gateway" if h.is_gateway else "host"
        rtt = rtt_cell(h.rtt_ms) if h.rtt_ms else f"[dim]{dash()}[/]"
        table.add_row(h.ip, h.mac or dash(), h.vendor or dash(), h.hostname or dash(), rtt, role)
    emit_table(table)
    note(f"[dim]{len(hosts)} host topildi · /24 ping sweep + ARP[/]")
    return EXIT_OK


async def _cmd_info() -> int:
    from systop.core.netinfo import gather_summary

    with status("[bold]Tarmoq ma'lumoti yig'ilmoqda..."):
        summary = await gather_summary()

    if _FORMAT == "json":
        emit_json(summary)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(summary.interfaces)
        return EXIT_OK

    table = styled_table("Tarmoq interfeyslari")
    table.add_column("Interfeys")
    table.add_column("IPv4")
    table.add_column("Tarmoq (CIDR)")
    table.add_column("MAC")
    table.add_column("Holat")
    for iface in summary.interfaces:
        if iface.is_up:
            st = f"[{SUCCESS}]{glyph('ok')}[/] up"
        else:
            st = f"[{ERROR}]{glyph('dead')}[/] down"
        table.add_row(
            iface.name, iface.ipv4 or dash(), iface.cidr or dash(), iface.mac or dash(), st
        )
    emit_table(table)
    note(
        f"\n[{WARNING}]{glyph('gateway')}[/] gateway [bold]{summary.gateway or dash()}[/]   "
        f"[dim]public IP[/] [bold]{summary.public_ip or dash()}[/]"
    )
    return EXIT_OK


def _split_host_port(value: str, default_port: int) -> tuple[str, int]:
    """'host:port' yoki 'host' => (host, port). IPv6 '[::1]:443' ham qo'llanadi."""
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
