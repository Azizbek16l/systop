"""systop CLI — default holatda dashboard'ni ochadi.

Qo'shimcha tez (bir martalik, scriptlarga mos) buyruqlar ham bor:
    systop              -> interaktiv dashboard (TUI)
    systop dashboard    -> xuddi shu
    systop speed        -> tezlik testi, jadval bilan chiqaradi
    systop ping         -> lokal + global ping (--ipv6, --watch)
    systop trace HOST   -> traceroute
    systop mtr HOST     -> jonli mtr-uslubi traceroute (Ctrl+C to'xtatadi)
    systop lan          -> LAN host discovery (vendor bilan)
    systop scan TARGET  -> TCP port skaner (host / CIDR / diapazon, --top, --banner)
    systop nc HOST PORT -> xom TCP/TLS ulanish (ncat uslubi)
    systop dns NAME     -> DNS resolve + serverlar latency taqqoslash
    systop bw           -> per-interfeys bandwidth (--watch jonli)
    systop tls HOST     -> TLS sertifikat tekshiruvi (muddat, issuer, SAN)
    systop http URL     -> HTTP holat tekshiruvi (status, redirect, vaqt)
    systop conn         -> faol tarmoq ulanishlari (--listen faqat LISTEN)
    systop web          -> web xizmatlar + boshqaruv panellari (--http80, --mgmt)
    systop doctor       -> tarmoq muammolarini avtomatik topish (jiddiylik bo'yicha)
    systop ntp          -> soat siljishi (clock skew) tekshiruvi — SNTP
    systop route        -> marshrut jadvali + next-hop yetishuvi
    systop mtu [HOST]   -> path MTU aniqlash (DF-ping, ikkilik qidiruv)
    systop dhcp         -> DHCP server(lar)ni aniqlash (rogue DHCP)
    systop arpwatch     -> ARP/NDP o'zgarishlari (MAC almashishi, dublikat)
    systop wifi         -> Wi-Fi signal/SNR/kanal (--neighbours qo'shnilar)
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
from systop.widgets._glyphs import dash, data_cell, glyph

# Exit kodlari — mazmunli, skriptlar uchun.
EXIT_OK = 0
EXIT_ERROR = 1  # umumiy xato
EXIT_UNREACHABLE = 2  # nishon yetib bo'lmaydi / o'lik / muddat tugagan

# `doctor` qaysi darajada "yiqildi" deb hisoblansin (jadval/JSON/CSV bir xil).
DOCTOR_FAIL_CRITICAL = "critical"
DOCTOR_FAIL_HIGH = "high"

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


# `_to_dict` avtomatik qo'shmaydigan property'lar: ular asosiy maydonning
# filtrlangan takrori bo'lib, payload'ni behuda ikki barobar qiladi.
_TO_DICT_SKIP: frozenset[str] = frozenset({
    "problems",            # Report.findings ning bir qismi
    "open_ports",          # ScanResult.ports ning bir qismi
    "responsive",          # SweepResult.hosts ning bir qismi
    "defaults",            # RouteTable.routes ning bir qismi
    "routable_defaults",
    "responded",           # NtpReport.results ning bir qismi
    "mac_changes",         # ArpDiff.changes ning bir qismi
    "neighbours",          # WifiStatus.neighbours — maydon sifatida bor
})


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
        # Hisoblanadigan property'larni AVTOMATIK qo'shamiz.
        #
        # Ilgari bu qo'lda yozilgan ro'yxat edi va har yangi dataclass property
        # jimgina `--json`/`--format csv` dan tushib qolardi — audit 38 ta
        # yo'qolgan maydonni topdi (`Interface.ipv6_global`, `WifiStatus.snr_db`,
        # `MtuResult.is_reduced` va h.k.). Ro'yxatni yuritish ishlamadi, chunki
        # uni unutish JIM xato beradi.
        #
        # Faqat SKALYAR yoki skalyar-ro'yxat qiymatlar olinadi: ichma-ich
        # obyektlar payload'ni bir necha barobar shishirardi va CSV katakchasiga
        # butun JSON blokini tiqardi. Filtrlangan ko'rinishlar (`problems`,
        # `open_ports`, ...) ataylab tashlanadi — ular asosiy maydonning
        # takrori.
        for prop in dir(type(obj)):
            if prop.startswith("_") or prop in _TO_DICT_SKIP or prop in out:
                continue
            attr = getattr(type(obj), prop, None)
            if not isinstance(attr, property):
                continue
            try:
                value = getattr(obj, prop)
            except Exception:  # noqa: BLE001 — property hisoblashda xato bo'lsa
                # Jim tashlab ketmaymiz: maydon yo'qligi sababi ko'rinsin.
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
        # `json.dumps` bytes'ni seriyalay olmaydi va TypeError bilan yiqiladi
        # (`nc --json` aynan shunday buzilardi). Matnga aylantiramiz — xom
        # baytlar kerak bo'lsa `received_bytes_count`/`is_binary` xossalari bor.
        return bytes(obj).decode("utf-8", errors="replace")
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
    p_speed = _with_globals(sub.add_parser("speed", help="Internet tezligini o'lchash"))
    p_speed.add_argument(
        "--local", action="store_true",
        help="lokal (IX) endpointlarni ham o'lchab, xalqaro bilan solishtirish",
    )
    p_speed.add_argument(
        "--local-url", action="append", default=None, metavar="URL",
        help="lokal endpoint URL (bir necha marta berish mumkin; config'ni bekor qiladi)",
    )

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
    p_scan.add_argument(
        "targets",
        nargs="*",
        help="host / CIDR / diapazon: '10.0.0.5' '10.0.0.0/24' '10.0.0.1-50' 'example.com'",
    )
    p_scan.add_argument(
        "--ports",
        default=None,
        help="portlar: '22,80,443' yoki '1-1024' (default: keng tarqalganlar)",
    )
    p_scan.add_argument(
        "--top", type=int, default=None, metavar="N",
        help="eng ko'p uchraydigan N portni skan qilish (nmap --top-ports uslubi)",
    )
    p_scan.add_argument(
        "--banner", action="store_true",
        help="ochiq portlardan xizmat versiyasini o'qish (nmap -sV yengil varianti)",
    )
    p_scan.add_argument(
        "--open-only", action="store_true", help="faqat ochiq porti bor hostlarni ko'rsatish"
    )
    p_scan.add_argument(
        "--polite", action="store_true",
        help="sekin rejim (IPS/anti-scan himoyasi bor tarmoq uchun)",
    )
    p_scan.add_argument(
        "--lan", action="store_true",
        help="nishonlarni LAN'dan avtomatik olish (barcha faol interfeys tarmoqlari)",
    )
    p_scan.add_argument(
        "--lan6", action="store_true",
        help="nishonlar: NDP orqali topilgan IPv6 hostlar (IPv6 /64 ni sweep qilib bo'lmaydi)",
    )
    p_scan.add_argument(
        "--max-hosts", type=int, default=1024,
        help="CIDR/diapazondan olinadigan maksimal host soni (himoya chegarasi)",
    )
    p_scan.add_argument(
        "--timeout", type=float, default=1.5, help="har bir port uchun timeout (soniya)"
    )
    _add_family_flags(p_scan)

    # --- nc: ncat uslubidagi xom TCP/TLS mijoz ------------------------------
    p_nc = _with_globals(sub.add_parser(
        "nc", help="Xom TCP/TLS ulanish (ncat uslubi) — banner, qo'lda so'rov"
    ))
    p_nc.add_argument("host", help="host (IP yoki nom; IPv6 ham)")
    p_nc.add_argument("port", type=int, help="port")
    p_nc.add_argument(
        "--send", default=None, metavar="TEXT",
        help=r"yuboriladigan matn; \r\n \t \xNN ketma-ketliklari qo'llanadi",
    )
    p_nc.add_argument(
        "--tls", action="store_true",
        help="TLS bilan ulanish (sertifikat tekshirilmaydi)",
    )
    p_nc.add_argument("--hex", action="store_true", help="javobni hexdump ko'rinishida")
    p_nc.add_argument(
        "--timeout", type=float, default=5.0, help="ulanish timeout (soniya)"
    )
    p_nc.add_argument(
        "--wait", type=float, default=None, metavar="SEC",
        help="javobni qancha kutish (default: timeout bilan bir xil)",
    )
    _add_family_flags(p_nc)

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

    p_lan = _with_globals(sub.add_parser("lan", help="Lokal tarmoq hostlarini topish"))
    p_lan.add_argument(
        "-6", "--ipv6", action="store_true",
        help="IPv6 hostlarni ham topish (ff02::1 multicast + NDP jadval)",
    )
    p_lan.add_argument(
        "--only-ipv6", action="store_true", help="faqat IPv6 (IPv4 sweep qilinmaydi)"
    )
    p_lan.add_argument(
        "--global-only", action="store_true",
        help="IPv6'da link-local (fe80::) manzillarni chiqarib tashlash",
    )

    # --- web: boshqaruv panellari va web xizmatlarni topish ------------------
    p_web = _with_globals(sub.add_parser(
        "web", help="Web xizmatlar + boshqaruv panellarini topish (LAN inventari)"
    ))
    p_web.add_argument(
        "hosts", nargs="*",
        help="tekshiriladigan hostlar; bo'sh bo'lsa LAN avtomatik topiladi",
    )
    p_web.add_argument(
        "--ports", default=None,
        help="portlar: '80' yoki '80,443,8080' (default: keng tarqalgan web portlar)",
    )
    p_web.add_argument(
        "--admin-only", action="store_true", help="faqat boshqaruv panellarini ko'rsatish"
    )
    p_web.add_argument(
        "--mgmt", action="store_true",
        help="faqat tarmoqni boshqaruvchi qurilmalar (router/firewall/switch/NVR)",
    )
    p_web.add_argument(
        "--http80", action="store_true",
        help="qisqa yo'l: faqat 80-portni tekshirish (lokal HTTP ochiqligini topish)",
    )
    p_web.add_argument(
        "--polite", action="store_true",
        help="sekin rejim (IPS/anti-scan himoyasi bor tarmoq uchun)",
    )
    p_web.add_argument(
        "--timeout", type=float, default=4.0, help="har bir so'rov uchun timeout"
    )
    p_web.add_argument(
        "-6", "--ipv6", action="store_true", help="IPv6 hostlarni ham tekshirish"
    )

    # --- doctor: tarmoq muammolarini avtomatik topish ------------------------
    p_doc = _with_globals(sub.add_parser(
        "doctor", help="Tarmoq muammolarini avtomatik topish (jiddiylik bo'yicha)"
    ))
    p_doc.add_argument(
        "--quick", action="store_true", help="tez rejim (web skan va IPv6 tashlanadi)"
    )
    p_doc.add_argument(
        "--no-web", action="store_true", help="web/admin panel tekshiruvini o'tkazib yuborish"
    )
    p_doc.add_argument(
        "--tls", default=None, help="TLS tekshiriladigan hostlar (vergul bilan)"
    )
    p_doc.add_argument(
        "--max-hosts", type=int, default=64, help="LAN'da maksimal host soni"
    )

    p_ntp = _with_globals(sub.add_parser("ntp", help="Soat siljishi (NTP) tekshiruvi"))
    p_ntp.add_argument("--servers", default=None, help="NTP serverlar (vergul bilan)")
    p_ntp.add_argument("--timeout", type=float, default=3.0)

    _with_globals(sub.add_parser("route", help="Marshrut jadvali + next-hop yetishuvi"))

    p_mtu = _with_globals(sub.add_parser("mtu", help="Path MTU aniqlash (DF-ping)"))
    p_mtu.add_argument("host", nargs="?", default="1.1.1.1", help="nishon (default 1.1.1.1)")
    p_mtu.add_argument("--low", type=int, default=1200)
    p_mtu.add_argument("--high", type=int, default=1500)

    p_dhcp = _with_globals(sub.add_parser("dhcp", help="DHCP server(lar)ni aniqlash"))
    p_dhcp.add_argument("--listen", type=float, default=4.0, help="broadcast javobini kutish (s)")

    p_arp = _with_globals(sub.add_parser(
        "arpwatch", help="ARP/NDP o'zgarishlari (MAC almashishi, dublikat)"
    ))
    p_arp.add_argument("--no-update", action="store_true", help="baseline'ni yangilamaslik")
    p_arp.add_argument("--reset", action="store_true", help="baseline'ni qaytadan yozish")

    p_wifi = _with_globals(sub.add_parser(
        "wifi", help="Wi-Fi holati: signal, SNR, kanal, qo'shnilar"
    ))
    p_wifi.add_argument(
        "--neighbours", action="store_true", help="atrofdagi tarmoqlarni ham ko'rsatish"
    )

    _with_globals(sub.add_parser("info", help="Tarmoq interfeyslari va public IP"))

    return parser


def _add_family_flags(p: argparse.ArgumentParser) -> None:
    """`-4`/`-6` manzil oilasi bayroqlarini qo'shadi (o'zaro istisno)."""
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "-4", "--ipv4", action="store_true", help="faqat IPv4 (A yozuvi)"
    )
    g.add_argument(
        "-6", "--ipv6", action="store_true", help="faqat IPv6 (AAAA yozuvi)"
    )


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
    error(f"Noma'lum buyruq: {command}")
    return EXIT_ERROR


def _family_from_args(args: argparse.Namespace) -> str:
    """`-4`/`-6` bayroqlarini `ports.FAMILY_*` qiymatiga aylantiradi."""
    from systop.core.ports import FAMILY_AUTO, FAMILY_V4, FAMILY_V6

    if getattr(args, "ipv6", False):
        return FAMILY_V6
    if getattr(args, "ipv4", False):
        return FAMILY_V4
    return FAMILY_AUTO


# --------------------------------------------------------------------------- #
# Buyruqlar
# --------------------------------------------------------------------------- #


async def _cmd_speed(local: bool = False, local_urls: list[str] | None = None) -> int:
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

    # --- lokal (IX) vs xalqaro ---------------------------------------------
    urls = local_urls or (cfg.speed_local_urls if local else [])
    if not urls:
        if local:
            error(
                "Lokal endpoint berilmagan. `--local-url URL` bilan bering yoki "
                "config'ga qo'shing:\n"
                "  speed_local_urls = [\"https://mirror.example.uz/10MB.bin\"]\n"
                "Endpoint ataylab kodga yozilmagan — u har mamlakatda boshqacha "
                "(TAS-IX, KazIX, MSK-IX va h.k.)."
            )
            return EXIT_ERROR
        return EXIT_OK

    from systop.core.speed import SpeedComparison, measure_local

    with status(f"[bold]{len(urls)} ta lokal endpoint o'lchanmoqda..."):
        locals_ = await measure_local(urls, duration=min(cfg.speed_duration, 5.0))
    cmp = SpeedComparison(international_mbps=result.download_mbps, local=locals_)

    lt = styled_table("Lokal (IX) vs xalqaro")
    lt.add_column("Endpoint", overflow="ellipsis")
    lt.add_column("Tezlik", justify="right")
    lt.add_column("Latency", justify="right")
    lt.add_column("Holat")
    for r in locals_:
        if r.ok:
            lt.add_row(
                data_cell(r.url), f"[{SUCCESS}]{r.mbps:.1f}[/] Mbps",
                f"{r.latency_ms:.0f} ms", f"[{SUCCESS}]ok[/]",
            )
        else:
            lt.add_row(data_cell(r.url), dash(), dash(), f"[{ERROR}]{r.error}[/]")
    lt.add_row(
        "[dim]xalqaro (Cloudflare)[/]",
        f"[{SECONDARY}]{cmp.international_mbps:.1f}[/] Mbps", dash(), "",
    )
    emit_table(lt)

    ratio = cmp.ratio
    if ratio is not None and cmp.best_local_mbps > 0:
        if cmp.is_throttled_international:
            note(
                f"[{WARNING}]Lokal xalqarodan {ratio:.1f}x tez[/] — xalqaro kanal "
                "cheklangan (tarif yoki shaping). Bu apparat nosozligi EMAS."
            )
        else:
            note(f"[dim]lokal/xalqaro nisbati {ratio:.1f}x — sezilarli farq yo'q[/]")
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
    """Port skaner — bitta host, butun LAN (CIDR/diapazon) yoki IPv6 qo'shnilar.

    Bitta hostga kengaysa batafsil port jadvali, ko'pga kengaysa har host bir
    qator ko'rinishidagi sweep xulosasi chiqadi (nmap uslubi).
    """
    from systop.core.ports import parse_ports, parse_targets, scan_host, top_ports

    ports = parse_ports(ports_spec) if ports_spec else None
    if ports_spec and not ports:
        error(f"'{ports_spec}' portlar ro'yxati noto'g'ri.")
        return EXIT_ERROR
    if top is not None:
        if top < 1:
            error("--top kamida 1 bo'lishi kerak.")
            return EXIT_ERROR
        ports = top_ports(top)

    hosts = parse_targets(",".join(targets_spec), max_hosts=max_hosts) if targets_spec else []

    # `--lan` / `--lan6`: nishonlarni tarmoqdan avtomatik olamiz. IPv6'da
    # subnet sweep imkonsiz (2^64 manzil), shuning uchun NDP qo'shni
    # jadvalidan topilgan ANIQ manzillar skan qilinadi.
    if from_lan or from_lan6:
        from systop.core.topology import discover_lan, discover_lan6

        with status("[bold]Nishonlar LAN'dan aniqlanmoqda..."):
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
            f"Nishon aniqlanmadi: {' '.join(targets_spec) or '(bo`sh)'}"
            + ("" if (from_lan or from_lan6) else " — host bering yoki --lan/--lan6 ishlating")
        )
        return EXIT_ERROR

    # Ko'p host => sweep rejimi.
    if len(hosts) > 1:
        return await _scan_sweep(
            hosts, ports, timeout, family, banner, open_only, polite
        )

    host = hosts[0]
    count = len(ports) if ports else "keng tarqalgan"
    fam_note = "" if family == "auto" else f", {family}"
    with status(f"[bold]{host} skaner qilinmoqda ({count} port{fam_note})..."):
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
    has_banner = any(p.banner for p in open_ports)
    if has_banner:
        table.add_column("Versiya / banner", overflow="ellipsis")
    for p in open_ports:
        row = [str(p.port), f"[{SUCCESS}]ochiq[/]", p.service or dash(), rtt_cell(p.rtt_ms)]
        if has_banner:
            row.append(p.banner or dash())
        table.add_row(*row)
    emit_table(table)
    filtered = sum(1 for p in result.ports if p.state == "filtered")
    closed = sum(1 for p in result.ports if p.state == "closed")
    note(
        f"[dim]{len(result.ports)} port tekshirildi — "
        f"{len(open_ports)} ochiq · {closed} yopiq · {filtered} filtrlangan[/]"
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
    """Ko'p host bo'yicha sweep — har host bir qator (nmap uslubi xulosa)."""
    from systop.core.ports import scan_targets, top_ports

    port_list = ports or top_ports(20)
    conc = 8 if polite else 64
    delay = 0.2 if polite else 0.0
    with status(
        f"[bold]{len(hosts)} host x {len(port_list)} port skaner qilinmoqda"
        + (" (sekin rejim)" if polite else "")
        + "..."
    ):
        sweep = await scan_targets(
            hosts, ports=port_list, timeout=timeout, concurrency=conc,
            family=family, banner=banner, delay=delay,
        )

    shown = sweep.responsive if open_only else [h for h in sweep.hosts if not h.error]
    if _FORMAT == "json":
        emit_json(sweep)
        return EXIT_OK if sweep.total_open else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        # CSV'da har host bir qator bo'lishi kerak - portlarni yig'ib beramiz.
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
            f"[{WARNING}]Hech bir hostda ochiq port topilmadi[/] "
            f"({sweep.scanned_hosts} host x {sweep.scanned_ports} port)."
        )
        return EXIT_UNREACHABLE

    table = styled_table(
        f"Port sweep - {len(sweep.responsive)}/{sweep.scanned_hosts} hostda "
        f"{sweep.total_open} ochiq port"
    )
    table.add_column("Host", no_wrap=True)
    table.add_column("Ochiq portlar", no_wrap=True)
    table.add_column("Xizmatlar", overflow="ellipsis")
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
    parts = [f"{sweep.scanned_hosts} host x {sweep.scanned_ports} port"]
    if failed:
        parts.append(f"{failed} resolve bo'lmadi")
    if polite:
        parts.append("sekin rejim")
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
    """ncat uslubidagi xom TCP/TLS ulanish."""
    from systop.core.netcat import connect, to_hexdump, unescape

    payload = unescape(send) if send else None
    label = f"{host}:{port}" + (" (TLS)" if tls else "")
    with status(f"[bold]{label} ga ulanmoqda..."):
        res = await connect(
            host, port, send=payload, tls=tls, timeout=timeout,
            family=family, wait_read=wait,
        )

    if _FORMAT == "json":
        emit_json(res)
        return EXIT_OK if res.connected else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv([res])
        return EXIT_OK if res.connected else EXIT_UNREACHABLE

    if not res.connected:
        error(res.error or "ulanib bo'lmadi")
        return EXIT_UNREACHABLE

    table = styled_table(f"nc {label}")
    table.add_column("Maydon")
    table.add_column("Qiymat", overflow="fold")
    table.add_row("Manzil", f"{res.resolved_ip} ({res.family})")
    table.add_row("Holat", f"[{SUCCESS}]ulandi[/] - {res.elapsed_ms:.0f} ms")
    if res.tls:
        table.add_row("TLS", f"{res.tls_version or dash()} - {res.tls_cipher or dash()}")
        if res.peer_cert_sha256:
            table.add_row("Cert SHA-256", res.peer_cert_sha256)
    if res.sent_bytes:
        table.add_row("Yuborildi", f"{res.sent_bytes} bayt")
    table.add_row("Qabul qilindi", f"{res.received_bytes_count} bayt")
    emit_table(table)

    if res.received:
        if as_hex or res.is_binary:
            note("[dim]-- javob (hexdump) --[/]")
            console.print(to_hexdump(res.received[:1024]))
        else:
            note("[dim]-- javob --[/]")
            console.print(res.received_text[:4000].rstrip())
    else:
        note("[dim]Javob kelmadi (xizmat so'rov kutayotgan bo'lishi mumkin - --send bering).[/]")
    return EXIT_OK


async def _cmd_dns(name: str, resolvers_arg: str | None = None) -> int:
    from systop.core.dns import diagnose_dns

    # MUHIM: `load_config().dns_resolvers` ni SHARTSIZ uzatib bo'lmaydi.
    # `DEFAULT_DNS_RESOLVERS` da 3 ta, `PUBLIC_RESOLVERS` da 4 ta server bor —
    # config fayli yo'q har bir foydalanuvchi jimgina OpenDNS'ni yo'qotardi.
    # Shuning uchun faqat foydalanuvchi ATAYLAB bergan qiymat override qiladi.
    resolvers = _split_csv_arg(resolvers_arg)
    override: dict[str, str] | None = {r: r for r in resolvers} if resolvers else None
    verbose(f"resolverlar: {', '.join(resolvers) or '(tizim + ommaviy)'}")

    with status(f"[bold]{name} uchun DNS diagnostika..."):
        result = await diagnose_dns(name, resolvers=override)

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
        note(f"[dim]Tizim resolveri (A):[/] [bold]{addrs}[/]")
        if result.aaaa_addresses:
            note(
                f"[dim]AAAA (IPv6):[/] [bold]{', '.join(result.aaaa_addresses)}[/]"
            )
        elif result.tool:
            note("[dim]AAAA (IPv6): yozuv yo'q[/]")

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


async def _cmd_lan(
    ipv6: bool = False,
    only_ipv6: bool = False,
    global_only: bool = False,
) -> int:
    from systop.core.topology import discover_lan, discover_lan6

    hosts: list = []
    if not only_ipv6:
        with status("[bold]LAN skanerlanmoqda (IPv4)..."):
            hosts += await discover_lan(resolve=True)
    if ipv6 or only_ipv6:
        with status("[bold]IPv6 qo'shnilari izlanmoqda (ff02::1 + NDP)..."):
            hosts += await discover_lan6(
                resolve=True, include_link_local=not global_only
            )

    if _FORMAT == "json":
        emit_json(hosts)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(hosts)
        return EXIT_OK

    v4 = sum(1 for h in hosts if h.family == "ipv4")
    v6 = len(hosts) - v4
    title = f"LAN hostlar ({len(hosts)} ta"
    title += f" — IPv4: {v4}, IPv6: {v6})" if v6 else ")"
    table = styled_table(title)
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor")
    table.add_column("Hostname")
    table.add_column("RTT ms", justify="right")
    table.add_column("Rol")
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
    note(f"[dim]{len(hosts)} host topildi · {' · '.join(src)}[/]")
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
    """Web xizmatlar va boshqaruv panellarini topadi."""
    from systop.core.diagnose import is_management_device
    from systop.core.ports import parse_ports
    from systop.core.topology import discover_lan, discover_lan6
    from systop.core.webscan import WEB_PORTS, discover_web, summarize

    ports = parse_ports(ports_spec) if ports_spec else None
    if ports_spec and not ports:
        error(f"'{ports_spec}' portlar ro'yxati noto'g'ri.")
        return EXIT_ERROR

    # Host berilmasa — LAN'ni o'zimiz topamiz.
    targets = list(hosts)
    if not targets:
        with status("[bold]LAN hostlari izlanmoqda..."):
            found = await discover_lan(resolve=False)
            targets = [h.ip for h in found]
            if ipv6:
                v6 = await discover_lan6(include_link_local=False)
                targets += [h.ip for h in v6]
        if not targets:
            error("LAN'da host topilmadi. Hostni qo'lda bering: systop web 192.168.1.1")
            return EXIT_UNREACHABLE

    n_ports = len(ports) if ports else len(WEB_PORTS)
    delay = 0.3 if polite else 0.0
    conc = 4 if polite else 16
    with status(
        f"[bold]{len(targets)} host × {n_ports} port tekshirilmoqda"
        + (" (sekin rejim)" if polite else "")
        + "..."
    ):
        services = await discover_web(
            targets, ports=ports, timeout=timeout,
            concurrency=conc, delay=delay, admin_only=admin_only,
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
        note(f"[{WARNING}]Web xizmat topilmadi[/] ({len(targets)} host tekshirildi).")
        return EXIT_UNREACHABLE

    st = summarize(services)
    table = styled_table(
        f"Web xizmatlar ({st['total']} ta · boshqaruv paneli: {st['admin']})"
    )
    # Manzil qisqarmasligi kerak — u natijaning kaliti (qaysi host, qaysi port).
    table.add_column("Manzil", no_wrap=True)
    table.add_column("Mahsulot", no_wrap=True)
    table.add_column("Tur")
    table.add_column("Sarlavha", overflow="ellipsis")
    table.add_column("Kod", justify="right")
    table.add_column("Xavf")
    for s in services:
        risk_map = {
            "high": f"[{ERROR}]yuqori[/]",
            "medium": f"[{WARNING}]o'rta[/]",
            "low": f"[{SUCCESS}]past[/]",
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

    parts = [f"{st['admin']} boshqaruv paneli"]
    if st["insecure_admin"]:
        parts.append(f"[{WARNING}]{st['insecure_admin']} tasi shifrlanmagan HTTP ustida[/]")
    if st["high_risk"]:
        parts.append(f"[{ERROR}]{st['high_risk']} tasida parol ochiq matnda[/]")
    if st["http_80"]:
        parts.append(f"{st['http_80']} tasi 80-portda")
    note("[dim]⚙ = tarmoqni boshqaruvchi qurilma · [/]" + " · ".join(parts))
    return EXIT_OK


def _doctor_exit_code(report: Any) -> int:
    """`doctor` uchun YAGONA exit-kod qoidasi (jadval, JSON va CSV uchun bir xil).

    Ilgari jadval va mashina rejimi turli qoidaga tayanardi: jadval faqat
    critical/high da 2 qaytarardi, `--json` esa INFO bo'lmagan HAR qanday
    topilmada. Natijada `systop doctor` muvaffaqiyat, `systop doctor --json`
    esa muvaffaqiyatsizlik qaytarardi — bir xil tarmoqda, bir xil sekundda.
    Skript uchun bu jim yolg'on: har normal LAN (SMB ochiq + bitta sekin
    resolver = medium) "yiqildi" deb hisoblanardi.
    """
    return EXIT_UNREACHABLE if report.worst_severity in (
        DOCTOR_FAIL_CRITICAL, DOCTOR_FAIL_HIGH
    ) else EXIT_OK


async def _cmd_doctor(
    quick: bool, no_web: bool, tls_arg: str | None, max_hosts: int
) -> int:
    """Tarmoq muammolarini avtomatik topadi va jiddiylik bo'yicha ko'rsatadi."""
    from systop.core.diagnose import (
        SEV_CRITICAL,
        SEV_HIGH,
        SEV_INFO,
        SEV_LOW,
        SEV_MEDIUM,
        run_diagnostics,
    )

    tls_hosts = [h.strip() for h in tls_arg.split(",") if h.strip()] if tls_arg else None

    with status("[bold]Tarmoq tekshirilmoqda (interfeys → ping → DNS → LAN → web)..."):
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
        SEV_CRITICAL: f"[{ERROR}]KRITIK[/]",
        SEV_HIGH: f"[{ERROR}]JIDDIY[/]",
        SEV_MEDIUM: f"[{WARNING}]O'RTA[/]",
        SEV_LOW: "[dim]KICHIK[/]",
        SEV_INFO: "[dim]ma'lumot[/]",
    }
    counts = report.counts
    head = f"Tarmoq diagnostikasi — {len(report.problems)} muammo"
    if not report.problems:
        head = "Tarmoq diagnostikasi — muammo topilmadi"
    table = styled_table(head)
    table.add_column("Daraja")
    table.add_column("Bo'lim")
    table.add_column("Muammo")
    table.add_column("Nima qilish kerak")
    for f in report.findings:
        table.add_row(
            sev_style.get(f.severity, f.severity),
            f.category,
            f.title,
            (f.fix or f.detail)[:70],
        )
    emit_table(table)

    summary = " · ".join(
        f"{lvl}: {counts[lvl]}" for lvl in
        (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO)
        if counts.get(lvl)
    )
    note(
        f"[dim]{report.checks_run} tekshiruv · {report.duration_ms / 1000:.1f}s"
        + (f" · {summary}" if summary else "")
        + (f" · o'tkazib yuborildi: {', '.join(report.skipped)}" if report.skipped else "")
        + "[/]"
    )
    if _VERBOSE:
        for f in report.problems:
            note(f"\n[bold]{f.title}[/]\n  {f.detail}" + (f"\n  → {f.fix}" if f.fix else ""))

    return _doctor_exit_code(report)


async def _cmd_ntp(servers_arg: str | None, timeout: float) -> int:
    """Soat siljishini NTP orqali tekshiradi."""
    from systop.core.ntp import check_time

    servers = None
    if servers_arg:
        parts = [x.strip() for x in servers_arg.split(",") if x.strip()]
        servers = {p: p for p in parts}
    with status("[bold]NTP serverlari so'ralmoqda..."):
        rep = await check_time(servers, timeout=timeout)

    if _FORMAT == "json":
        emit_json(rep)
        return EXIT_OK if rep.responded else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(rep.results)
        return EXIT_OK if rep.responded else EXIT_UNREACHABLE

    med = rep.median_offset_s
    title = "Soat tekshiruvi"
    if med is not None:
        title += f" - mediana siljish {med * 1000:+.0f} ms"
    table = styled_table(title)
    table.add_column("Server", no_wrap=True)
    table.add_column("Holat")
    table.add_column("Siljish", justify="right")
    table.add_column("RTT ms", justify="right")
    table.add_column("Stratum", justify="right")
    sev_color = {"ok": SUCCESS, "warn": WARNING, "high": ERROR, "critical": ERROR}
    for r in rep.results:
        if not r.ok:
            table.add_row(data_cell(r.label), f"[{ERROR}]{r.error or 'xato'}[/]",
                          dash(), dash(), dash())
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
        note(f"[{WARNING}]Soat {med:+.1f} s siljigan[/] - Kerberos/TLS/loglarni buzishi mumkin.")
    else:
        note(f"[dim]{len(rep.responded)}/{len(rep.results)} server javob berdi - soat joyida[/]")
    return EXIT_OK if rep.responded else EXIT_UNREACHABLE


async def _cmd_route() -> int:
    """Marshrut jadvali va default next-hop yetishuvi."""
    from systop.core.routes import check_next_hops, list_routes

    with status("[bold]Marshrut jadvali o'qilmoqda..."):
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
        f"Marshrutlar ({len(table_data.routes)} ta, "
        f"{len(table_data.routable_defaults)} ma'noli default)"
    )
    t.add_column("Nishon", no_wrap=True)
    t.add_column("Gateway", no_wrap=True)
    t.add_column("Interfeys")
    t.add_column("Oila")
    t.add_column("Holat")
    for r in table_data.routes:
        state = ""
        if r.is_default and r.gateway in alive:
            state = f"[{SUCCESS}]tirik[/]" if alive[r.gateway] else f"[{ERROR}]javobsiz[/]"
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
        note(f"[{WARNING}]VPN 0.0.0.0/1 + 128.0.0.0/1 bilan butun trafikni olgan[/]")
    dead = [g for g, ok in alive.items() if not ok]
    if dead:
        note(f"[{ERROR}]Javob bermayotgan gateway: {', '.join(dead)}[/]")
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_mtu(host: str, low: int, high: int) -> int:
    """Path MTU aniqlash."""
    from systop.core.mtu import discover_path_mtu

    with status(f"[bold]{host} gacha path MTU aniqlanmoqda (DF-ping)..."):
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
    t.add_column("Maydon")
    t.add_column("Qiymat")
    t.add_row("Path MTU", f"[b]{res.path_mtu}[/] bayt")
    t.add_row("Max payload", str(res.max_payload))
    t.add_row("Oila", res.family)
    t.add_row("Probe soni", str(res.probes))
    if res.likely_cause:
        t.add_row("Ehtimoliy sabab", res.likely_cause)
    emit_table(t)
    if res.is_reduced:
        note(
            f"[{WARNING}]MTU 1500 dan kichik[/] - katta javobli saytlar qotishi "
            "mumkin (PMTUD qora tuynugi). MSS clamping yoqing."
        )
        return EXIT_UNREACHABLE
    note("[dim]Standart Ethernet MTU - muammo yo'q[/]")
    return EXIT_OK


async def _cmd_dhcp(listen_s: float) -> int:
    """DHCP serverlarni aniqlash + faol lease."""
    from systop.core.dhcp import current_lease, discover_servers

    with status("[bold]DHCP tekshirilmoqda..."):
        lease = await current_lease()
        probe = await discover_servers(listen_s=listen_s)

    if _FORMAT == "json":
        emit_json({"lease": lease, "probe": probe})
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(probe.offers or ([lease] if lease else []))
        return EXIT_OK

    t = styled_table("DHCP")
    t.add_column("Manba", no_wrap=True)
    t.add_column("Server", no_wrap=True)
    t.add_column("IP")
    t.add_column("Router")
    t.add_column("DNS")
    t.add_column("Lease")
    if lease:
        t.add_row(
            "faol lease",
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
        note(f"[{ERROR}]{len(servers)} ta DHCP server topildi - rogue DHCP ehtimoli![/]")
        return EXIT_UNREACHABLE
    if probe.partial:
        note(
            "[dim]Broadcast probe'ga javob kelmadi. Bu 'server yo'q' degani EMAS: "
            "root'siz 68-portga bog'lanib bo'lmaydi, qat'iy RFC serverlar faqat "
            "o'sha portga javob beradi. Faol lease ishonchli manba.[/]"
        )
    return EXIT_OK


async def _cmd_arpwatch(update: bool, reset: bool) -> int:
    """ARP/NDP o'zgarishlarini baseline bilan solishtiradi."""
    from systop.core.arpwatch import baseline_path, check

    if reset:
        try:
            baseline_path().unlink(missing_ok=True)
            note("[dim]Baseline o'chirildi - qaytadan yoziladi.[/]")
        except OSError as exc:
            error(f"baseline o'chirilmadi: {exc}")
            return EXIT_ERROR

    with status("[bold]ARP/NDP jadvali solishtirilmoqda..."):
        diff = await check(update=update)

    if _FORMAT == "json":
        emit_json(diff)
        return EXIT_OK
    if _FORMAT == "csv":
        emit_csv(diff.changes)
        return EXIT_OK

    if diff.first_run:
        note(
            f"[dim]Birinchi ishlash - {diff.current_hosts} host baseline sifatida "
            f"saqlandi ({baseline_path()}). Keyingi ishlashda farq ko'rsatiladi.[/]"
        )
        return EXIT_OK
    if not diff.changes:
        note(f"[{SUCCESS}]O'zgarish yo'q[/] - {diff.current_hosts} host, baseline bilan bir xil.")
        return EXIT_OK

    t = styled_table(f"ARP o'zgarishlari ({len(diff.changes)} ta)")
    t.add_column("Daraja")
    t.add_column("Tur")
    t.add_column("IP", no_wrap=True)
    t.add_column("Tafsilot", overflow="fold")
    sev_color = {"high": ERROR, "medium": WARNING, "low": SUCCESS, "info": "dim"}
    kind_uz = {
        "mac_changed": "MAC o'zgardi",
        "duplicate_mac": "MAC dublikati",
        "new_host": "yangi host",
        "disappeared": "yo'qoldi",
    }
    for c in diff.changes:
        col = sev_color.get(c.severity, "dim")
        if c.kind == "mac_changed":
            detail = f"{c.old_mac} ({c.old_vendor or '?'}) -> {c.new_mac} ({c.new_vendor or '?'})"
        elif c.kind == "duplicate_mac":
            detail = f"{c.new_mac} ayni paytda: {', '.join([c.ip, *c.extra_ips][:6])}"
        else:
            detail = f"{c.new_mac or c.old_mac or ''} {c.new_vendor or c.old_vendor or ''}"
        t.add_row(f"[{col}]{c.severity}[/]", kind_uz.get(c.kind, c.kind),
                  data_cell(c.ip), data_cell(detail, dash()))
    emit_table(t)
    if diff.has_suspicious:
        note(
            f"[{WARNING}]MAC almashishi/dublikati bor[/] - ARP spoofing yoki "
            "IP dublikatini tekshiring"
        )
        return EXIT_UNREACHABLE
    return EXIT_OK


async def _cmd_wifi(show_neighbours: bool = False) -> int:
    """Wi-Fi holati va atrofdagi tarmoqlar."""
    # `status` nomi cli.status (spinner) bilan to'qnashadi — alias bilan olamiz.
    from systop.core.wifi import overlapping_24ghz
    from systop.core.wifi import status as wifi_status

    with status("[bold]Wi-Fi holati o'qilmoqda..."):
        w = await wifi_status()

    if _FORMAT == "json":
        emit_json(w)
        return EXIT_OK if w.connected else EXIT_UNREACHABLE
    if _FORMAT == "csv":
        emit_csv(w.neighbours or [w])
        return EXIT_OK

    if not w.available:
        note(f"[dim]Bu mashinada Wi-Fi apparati topilmadi{' — ' + w.error if w.error else ''}.[/]")
        return EXIT_OK
    if not w.connected:
        note(f"[{WARNING}]Wi-Fi ulanmagan.[/]")
        return EXIT_UNREACHABLE

    qual_color = {
        "excellent": SUCCESS, "good": SUCCESS, "fair": WARNING,
        "poor": ERROR, "unusable": ERROR,
    }
    t = styled_table(f"Wi-Fi{' - ' + w.ssid if w.ssid else ''}")
    t.add_column("Maydon")
    t.add_column("Qiymat", overflow="fold")
    col = qual_color.get(w.signal_quality or "", WARNING)
    if w.rssi_dbm is not None:
        t.add_row("Signal", f"[{col}]{w.rssi_dbm} dBm[/] ({w.signal_quality})")
    if w.snr_db is not None:
        snr_col = SUCCESS if w.snr_db >= 25 else (WARNING if w.snr_db >= 15 else ERROR)
        t.add_row("SNR", f"[{snr_col}]{w.snr_db} dB[/] (shovqin {w.noise_dbm} dBm)")
    if w.channel is not None:
        band_col = WARNING if w.is_24ghz and w.five_ghz_available else SUCCESS
        t.add_row("Kanal", f"[{band_col}]{w.channel}[/] ({w.band}, {w.width_mhz or '?'} MHz)")
    if w.phy_mode:
        gen_col = WARNING if (w.phy_generation != w.supported_generation) else SUCCESS
        t.add_row(
            "PHY",
            f"[{gen_col}]{w.phy_mode}[/]"
            + (f"  [dim](karta: {w.supported_phy})[/]" if w.supported_phy else ""),
        )
    if w.tx_rate_mbps:
        t.add_row("Tezlik", f"{w.tx_rate_mbps:.0f} Mbps")
    if w.security:
        _weak = "wep" in w.security.lower() or "none" in w.security.lower()
        sec_col = ERROR if _weak else SUCCESS
        t.add_row("Xavfsizlik", f"[{sec_col}]{w.security}[/]")
    if w.country_code:
        t.add_row("Davlat", w.country_code)
    if w.neighbours:
        bands: dict[str, int] = {}
        for n in w.neighbours:
            bands[n.band or "?"] = bands.get(n.band or "?", 0) + 1
        t.add_row("Qo'shnilar", ", ".join(f"{k}: {v}" for k, v in sorted(bands.items())))
    emit_table(t)

    if w.channel and w.is_24ghz:
        ov = overlapping_24ghz(w.channel, w.neighbours)
        if ov:
            note(
                f"[{WARNING}]Kanal {w.channel} ga {len(ov)} ta AP xalaqit beryapti[/] "
                "[dim](2.4 GHz da faqat 1/6/11 ustma-ust tushmaydi)[/]"
            )
    if w.is_24ghz and w.five_ghz_available:
        note(f"[{WARNING}]Atrofda 5 GHz mavjud[/] - unga o'tsangiz tezlik sezilarli oshadi.")

    if show_neighbours and w.neighbours:
        nt = styled_table(f"Atrofdagi tarmoqlar ({len(w.neighbours)} ta)")
        nt.add_column("Kanal", justify="right")
        nt.add_column("Diapazon")
        nt.add_column("Kenglik", justify="right")
        nt.add_column("PHY")
        nt.add_column("Xavfsizlik")
        for n in sorted(w.neighbours, key=lambda x: (x.band or "", x.channel or 0)):
            nt.add_row(
                str(n.channel or dash()), n.band or dash(),
                f"{n.width_mhz} MHz" if n.width_mhz else dash(),
                data_cell(n.phy_mode, dash()), data_cell(n.security, dash()),
            )
        emit_table(nt)
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
    table.add_column("Interfeys", no_wrap=True)
    table.add_column("IPv4", no_wrap=True)
    table.add_column("Tarmoq", no_wrap=True)
    # min_width — ustun bo'sh bo'lsa ham sarlavha o'qilsin.
    table.add_column("IPv6", overflow="ellipsis", min_width=6)
    table.add_column("MAC", no_wrap=True)
    table.add_column("Holat")
    for iface in summary.interfaces:
        if iface.is_up:
            st = f"[{SUCCESS}]{glyph('ok')}[/] up"
        else:
            st = f"[{ERROR}]{glyph('dead')}[/] down"
        # Tarmoq: CIDR + host sig'imi ("10.0.0.0/24 · 254") — hajm bir qarashda
        # ko'rinsin. IPv6 ustunida FAQAT global manzil: link-local deyarli har
        # interfeysda bor va bu jadvalda hech qanday ma'lumot bermaydi.
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
    # Gateway yoniga prefiks: `/24` bir qarashda tarmoq hajmini aytadi.
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
