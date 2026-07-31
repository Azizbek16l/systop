"""Platforma-bog'liq umumiy yordamchilar (cross-platform qatlam).

Bu modul platforma aniqlashni, Windows konsol kodlash/Unicode masalalarini VA
Windows ICMP'ni (ping/traceroute) bitta joyga jamlaydi. Boshqa `core/` modullari
(`netinfo`, `ping`, `topology`, `dns`) platforma shoxini shu yerdan oladi —
shunda mantiq takrorlanmaydi va offline sinaladi.

Dizayn qarorlari:

* **Windows'da ICMP — Win32 IcmpSendEcho (ildiz yechim).** Matn-parse o'rniga
  `iphlpapi.dll`'ning `IcmpSendEcho`/`Icmp6SendEcho2` funksiyalari ctypes orqali
  chaqiriladi. Bu admin talab qilmaydi VA tizim lokalizatsiyasi/kodlash sahifasi
  (codepage)'dan butunlay mustaqil — ruscha/nemischa Windows ham bir xil ishlaydi.
  `IcmpSendEcho` mavjud bo'lmasa (juda eski/g'ayrioddiy muhit), `ping.exe`/
  `tracert.exe` chiqishini parse qiluvchi til-mustaqil zaxira ishlatiladi.
* **OEM codepage decode.** Subprocess (route/arp/ip-neigh/dns) hali ham matn
  qaytaradi; RUS konsoli cp866 yozadi (UTF-8 emas). `decode_console` haqiqiy
  konsol kodlash sahifasini (`GetConsoleOutputCP`) o'qib to'g'ri dekodlaydi —
  kirill mojibake'ning oldini oladi.
* **Konsol init.** `init_console` Windows'da konsolni UTF-8 (65001) + VT
  (virtual terminal) rejimiga o'tkazadi — Textual sparkline/braille/box
  belgilari legacy cmd.exe'da ham to'g'ri ko'rinadi.
* **Faqat stdlib.** `platform`, `subprocess`, `asyncio`, `re`, `ctypes`,
  `socket`, `os` — qo'shimcha bog'liqlik yo'q.
* **Parse funksiyalari sof.** Tarmoqqa chiqmaydi, faqat satr/bayt -> qiymat;
  real chiqish namunalari (cp866 baytlari ham) bilan offline sinaladi.

Eslatma: bu konstantalar (`IS_WINDOWS` va h.k.) modul-darajasida; testlarda
`monkeypatch.setattr(_platform, "IS_WINDOWS", True)` bilan almashtirilishi
mumkin, lekin chaqiruvchi modullar ularni `_platform.IS_WINDOWS` orqali (atribut
sifatida) o'qishi shart — shunda monkeypatch ta'sir qiladi.
"""

from __future__ import annotations

import asyncio
import ctypes
import functools
import os
import platform
import re
import shutil
import socket
import struct
import subprocess

# --- Platforma konstantalari (bitta manba) ----------------------------------

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# Windows'da subprocess oynasi miltillamasligi uchun (faqat win32'da mavjud).
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def subprocess_flags() -> int:
    """Subprocess `creationflags` qiymati: Windows'da CREATE_NO_WINDOW, aks holda 0.

    Konsol oynasining miltillashini (flash) oldini oladi. Boshqa OS'da 0
    (`creationflags` POSIX'da ham qabul qilinadi, lekin ta'sirsiz).
    """
    return _CREATE_NO_WINDOW if IS_WINDOWS else 0


# --- Konsol kodlash sahifasi (codepage) va Unicode --------------------------


def decode_console(data: bytes | str) -> str:
    """Bayt chiqishini to'g'ri dekodlaydi (Windows konsol OEM codepage'ini hisobga olib).

    Windows konsoli (cmd.exe) UTF-8 emas, OEM kodlash sahifasida yozadi
    (RUS = cp866, DE = cp850 va h.k.). Default UTF-8 dekodlash kirill/lotin
    bo'lmagan belgilarni mojibake qiladi. Bu funksiya `GetConsoleOutputCP` orqali
    haqiqiy sahifani aniqlab, `cp<N>` bilan dekodlaydi.

    Boshqa OS'da (yoki codepage aniqlanmasa) UTF-8 ishlatiladi. Har holatda
    `errors="replace"` — buzuq bayt istisno ko'tarmaydi. Allaqachon `str` kelsa
    (masalan `text=True` subprocess yoki test fixture) — o'zgartirmasdan qaytaradi.
    """
    if isinstance(data, str):
        return data
    if IS_WINDOWS:
        cp = _console_output_cp()
        if cp:
            try:
                return data.decode(f"cp{cp}", errors="replace")
            except LookupError:
                # Noma'lum/qo'llab-quvvatlanmaydigan codepage — UTF-8'ga tushamiz.
                pass
    return data.decode("utf-8", errors="replace")


def _console_output_cp() -> int:
    """Joriy konsol chiqish kodlash sahifasini (codepage) qaytaradi; xato bo'lsa 0."""
    try:
        return int(ctypes.windll.kernel32.GetConsoleOutputCP())  # type: ignore[attr-defined]
    except (AttributeError, OSError, ValueError):
        return 0


# ENABLE_VIRTUAL_TERMINAL_PROCESSING (konsol ANSI/VT ketma-ketliklarini tushunadi).
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11
_STD_ERROR_HANDLE = -12
_CP_UTF8 = 65001


def init_console() -> None:
    """Konsolni UTF-8 (65001) + VT rejimiga o'tkazadi (Windows'da; aks holda no-op).

    Textual TUI va Rich chiqishi Unicode (braille sparkline, box belgilar) va
    ANSI ranglardan foydalanadi. Legacy cmd.exe default'da OEM codepage va
    VT'siz — natija mojibake bo'ladi. Bu funksiya:

    * `SetConsoleOutputCP(65001)` + `SetConsoleCP(65001)` — UTF-8 kirish/chiqish;
    * stdout/stderr handle'lariga `ENABLE_VIRTUAL_TERMINAL_PROCESSING` qo'shadi.

    Har bir qadam xatosi JIM yutiladi (qayta yo'naltirilgan oqim / eski Windows /
    ruxsat yo'q holatlarida ilova baribir ishlashda davom etadi). cli/app
    ishga tushishda bir marta chaqiradi.
    """
    if not IS_WINDOWS:
        return
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return
    try:
        kernel32.SetConsoleOutputCP(_CP_UTF8)
        kernel32.SetConsoleCP(_CP_UTF8)
    except OSError:
        pass
    for std_handle in (_STD_OUTPUT_HANDLE, _STD_ERROR_HANDLE):
        try:
            handle = kernel32.GetStdHandle(std_handle)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                continue
            kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        except OSError:
            continue


def unicode_ok() -> bool:
    """Terminal Unicode blok/emoji ko'rsata olishini taxmin qiladi (heuristika).

    * Windows: Windows Terminal (`WT_SESSION` env) ostida YOKI konsol UTF-8
      (codepage 65001) bo'lsa True; aks holda (legacy raster cmd.exe) False.
    * Boshqa OS (macOS/Linux): har doim True.

    Layer B (cli/app) ASCII-fallback (sodda jadval/belgilar) tanlash uchun
    ishlatadi — shunda eski cmd.exe'da ham mojibake bo'lmaydi.
    """
    if not IS_WINDOWS:
        return True
    if os.environ.get("WT_SESSION"):
        return True
    return _console_output_cp() == _CP_UTF8


# --- Windows ICMP: Win32 IcmpSendEcho (iphlpapi.dll) ------------------------
#
# Til/codepage'dan mustaqil ildiz yechim. `iphlpapi.dll`'ning ICMP API'si
# admin talab qilmaydi (ping.exe ham shuni ishlatadi). Quyidagi struct'lar
# Win32 SDK (ipexport.h) ta'riflariga mos.

# IP status kodlari (ipexport.h).
IP_SUCCESS = 0
IP_TTL_EXPIRED_TRANSIT = 11013  # TTL nolga yetdi — oraliq hop (traceroute uchun).
IP_REQ_TIMED_OUT = 11010


class _ICMP_ECHO_REPLY(ctypes.Structure):
    """ICMP_ECHO_REPLY (IPv4) — `IcmpSendEcho` to'ldiradigan struktura.

    Faqat o'qiydigan maydonlar: `Status` (IP_* kodi) va `RoundTripTime` (ms).
    Reply ma'lumotlarining qolgan qismi (`Data`, `Options`) bizga kerak emas,
    lekin struct hajmi to'g'ri bo'lishi shart (API buffer'ga yozadi).
    """

    _fields_ = (
        ("Address", ctypes.c_uint32),  # javob bergan manba IP (network byte order)
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options_Ttl", ctypes.c_uint8),
        ("Options_Tos", ctypes.c_uint8),
        ("Options_Flags", ctypes.c_uint8),
        ("Options_OptionsSize", ctypes.c_uint8),
        ("Options_OptionsData", ctypes.c_void_p),
    )


class _IP_OPTION_INFORMATION(ctypes.Structure):
    """IP_OPTION_INFORMATION — TTL'ni boshqarish uchun (traceroute hop'lari).

    `Ttl` ni 1..max_hops qilib ketma-ket yuborib, TTL_EXPIRED javob bergan
    oraliq router IP'sini olamiz.
    """

    _fields_ = (
        ("Ttl", ctypes.c_uint8),
        ("Tos", ctypes.c_uint8),
        ("Flags", ctypes.c_uint8),
        ("OptionsSize", ctypes.c_uint8),
        ("OptionsData", ctypes.c_void_p),
    )


# IcmpSendEcho'ga yuboriladigan "payload" (ixtiyoriy 32 bayt — ping.exe kabi).
_ICMP_PAYLOAD = b"systop-icmp-probe-padding-32byte"  # 32 bayt
# Javob buferi: ECHO_REPLY + payload + qo'shimcha (8 bayt ICMP header zaxirasi).
_ICMP_REPLY_BUF_SIZE = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(_ICMP_PAYLOAD) + 8

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _iphlpapi() -> ctypes.WinDLL | None:  # type: ignore[name-defined]
    """`iphlpapi.dll`'ni yuklaydi; mavjud bo'lmasa None (zaxiraga o'tiladi)."""
    try:
        return ctypes.WinDLL("iphlpapi.dll")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def _resolve_ipv4(address: str) -> str | None:
    """Manzilni IPv4 nuqta-o'nlik satrga aylantiradi (nom bo'lsa resolve qiladi).

    IcmpSendEcho faqat IPv4 manzil (DWORD) qabul qiladi; nomni o'zimiz resolve
    qilamiz. Resolve bo'lmasa None.
    """
    try:
        infos = socket.getaddrinfo(address, None, family=socket.AF_INET)
    except (OSError, UnicodeError):
        return None
    for info in infos:
        return str(info[4][0])
    return None


def _addr_to_dword(ipv4: str) -> int | None:
    """IPv4 satrni IcmpSendEcho kutgan DWORD (network byte order) ga aylantiradi."""
    try:
        packed = socket.inet_aton(ipv4)
    except OSError:
        return None
    return int(struct.unpack("<I", packed)[0])


def _dword_to_addr(dword: int) -> str:
    """ECHO_REPLY.Address (network byte order DWORD) -> IPv4 satr."""
    return socket.inet_ntoa(struct.pack("<I", dword & 0xFFFFFFFF))


def icmp_ping_ipv4(
    ipv4: str,
    timeout_ms: int,
    ttl: int | None = None,
) -> tuple[int, float, str | None]:
    """Bitta IPv4 ICMP echo yuboradi (Win32 IcmpSendEcho).

    Argumentlar:
        ipv4 — nuqta-o'nlik IPv4 manzil (oldindan resolve qilingan).
        timeout_ms — javob kutish (millisekund).
        ttl — None bo'lsa standart; aks holda IP_OPTION_INFORMATION.Ttl
            (traceroute hop'i uchun 1..max_hops).

    Qaytaradi: `(status, rtt_ms, reply_source_ip)`.
        status — IP_* kodi (0=SUCCESS, 11013=TTL_EXPIRED, 11010=TIMED_OUT, ...).
        rtt_ms — RoundTripTime (status SUCCESS/TTL_EXPIRED bo'lsa ma'noli).
        reply_source_ip — javob bergan manba IP (TTL_EXPIRED'da oraliq router).

    `iphlpapi` yo'q / handle ochilmasa -> `(IP_REQ_TIMED_OUT, 0.0, None)`.
    """
    dll = _iphlpapi()
    if dll is None:
        return IP_REQ_TIMED_OUT, 0.0, None

    dest = _addr_to_dword(ipv4)
    if dest is None:
        return IP_REQ_TIMED_OUT, 0.0, None

    dll.IcmpCreateFile.restype = ctypes.c_void_p
    handle = dll.IcmpCreateFile()
    if not handle or handle == _INVALID_HANDLE_VALUE:
        return IP_REQ_TIMED_OUT, 0.0, None

    try:
        reply_buf = ctypes.create_string_buffer(_ICMP_REPLY_BUF_SIZE)
        opt_ptr = None
        if ttl is not None:
            opts = _IP_OPTION_INFORMATION(Ttl=max(1, min(255, ttl)))
            opt_ptr = ctypes.byref(opts)

        dll.IcmpSendEcho.restype = ctypes.c_uint32
        n = dll.IcmpSendEcho(
            ctypes.c_void_p(handle),
            ctypes.c_uint32(dest),
            _ICMP_PAYLOAD,
            ctypes.c_uint16(len(_ICMP_PAYLOAD)),
            opt_ptr,
            reply_buf,
            ctypes.c_uint32(_ICMP_REPLY_BUF_SIZE),
            ctypes.c_uint32(max(1, timeout_ms)),
        )
        if n == 0:
            # Javob yo'q (timeout yoki xato). GetLastError ham status berishi
            # mumkin (TTL_EXPIRED ba'zi versiyalarda n=0 + LastError bilan),
            # lekin biz buni "javob yo'q" deb degrade qilamiz (oddiy/barqaror).
            return IP_REQ_TIMED_OUT, 0.0, None
        reply = ctypes.cast(reply_buf, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
        status = int(reply.Status)
        rtt = float(reply.RoundTripTime)
        src = _dword_to_addr(int(reply.Address)) if reply.Address else None
        return status, rtt, src
    except OSError:
        return IP_REQ_TIMED_OUT, 0.0, None
    finally:
        try:
            dll.IcmpCloseHandle(ctypes.c_void_p(handle))
        except OSError:
            pass


def win_icmp_ping(
    address: str,
    count: int,
    timeout: float,
) -> tuple[bool, list[float], float] | None:
    """Windows ICMP ping (IcmpSendEcho) — (alive, rtts_ms, loss) yoki None.

    `count` marta IPv4 echo yuborib, SUCCESS javoblardan RTT yig'adi.
    Loss = (yuborilgan - qabul qilingan) / yuborilgan.

    None qaytaradi, agar:
      * manzil IPv4'ga resolve bo'lmasa (chaqiruvchi nom/IPv6 zaxirasiga o'tadi),
      * `iphlpapi` umuman mavjud bo'lmasa (DLL yo'q).
    Bu holda chaqiruvchi (`ping._win_ping`) `ping.exe` parse zaxirasiga o'tadi.
    """
    if _iphlpapi() is None:
        return None
    ipv4 = _resolve_ipv4(address)
    if ipv4 is None:
        return None

    count = max(1, count)
    timeout_ms = max(1, int(timeout * 1000))
    rtts: list[float] = []
    received = 0
    for _ in range(count):
        status, rtt, _src = icmp_ping_ipv4(ipv4, timeout_ms)
        if status == IP_SUCCESS:
            received += 1
            rtts.append(rtt)
    loss = (count - received) / count if count else 1.0
    return (received > 0), rtts, loss


def win_icmp_traceroute(
    address: str,
    max_hops: int,
    timeout: float,
) -> list[tuple[int, str | None, float, bool]] | None:
    """Windows traceroute (IcmpSendEcho + TTL) — hop ro'yxati yoki None.

    Har TTL (1..max_hops) uchun bitta echo yuboradi:
      * status SUCCESS  -> manzilga yetdi (oxirgi hop), to'xtaymiz;
      * status TTL_EXPIRED -> oraliq router (reply.Address), davom etamiz;
      * javob yo'q -> `* * *` hop (addr=None, alive=False).

    Qaytaradi: har element `(hop_index, address|None, rtt_ms, alive)` —
    `parse_windows_tracert` bilan bir xil shakl. None qaytaradi, agar manzil
    IPv4'ga resolve bo'lmasa yoki `iphlpapi` yo'q bo'lsa (chaqiruvchi `tracert`
    parse zaxirasiga o'tadi).
    """
    if _iphlpapi() is None:
        return None
    ipv4 = _resolve_ipv4(address)
    if ipv4 is None:
        return None

    timeout_ms = max(1, int(timeout * 1000))
    hops: list[tuple[int, str | None, float, bool]] = []
    for ttl in range(1, max(1, max_hops) + 1):
        status, rtt, src = icmp_ping_ipv4(ipv4, timeout_ms, ttl=ttl)
        if status == IP_SUCCESS:
            hops.append((ttl, src or ipv4, rtt, True))
            break
        if status == IP_TTL_EXPIRED_TRANSIT and src is not None:
            hops.append((ttl, src, rtt, True))
            continue
        # Javob yo'q / boshqa xato -> timeout hop.
        hops.append((ttl, None, 0.0, False))
    return hops


# --- Windows `ping` chiqishini parse qilish (TIL-MUSTAQIL ZAXIRA) ------------
#
# IcmpSendEcho mavjud bo'lmasa (juda kam) `ping.exe` chiqishini parse qilamiz.
# Regexlar TILGA BOG'LIQ EMAS: ASCII 'ms' VA kirill 'мс' (м=U+043C) ni ham
# tushunadi, o'nlik vergulni ham (RUS/DE `время=1,5 мс`).

# RTT: "time=12ms", "time<1ms", "время=84мс", "Zeit=12ms", "1,5 ms".
# "=" yoki "<" + raqam (vergul/nuqta o'nlik) + birlik (ascii m / kirill м).
_WIN_PING_RTT_RE = re.compile(
    r"[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*(?:ms|мс|m|м)",
    re.IGNORECASE | re.UNICODE,
)
# "time<1ms" / "время<1мс" => 1ms'dan kichik -> 0.5ms (taxminiy).
_WIN_PING_SUBMS_RE = re.compile(r"<\s*1\s*(?:ms|мс|m|м)", re.IGNORECASE | re.UNICODE)
# Yakuniy statistika: "(0% loss)" / "(0% потерь)" / "(0% Verlust)" — foiz.
_WIN_PING_LOSS_PCT_RE = re.compile(r"\(\s*([0-9]+)\s*%")
# `Packets:` statistika qatori — Sent/Received (RTT qatorlaridan farqlash uchun).
# RUS: "Отправлено = 4, получено = 4, потеряно = 0".
_WIN_PING_STATS_LINE_RE = re.compile(
    r"(?:Sent|Received|Lost|Отправлено|Получено|Потеряно|Gesendet|Empfangen|Verloren)"
    r"\s*=\s*\d",
    re.IGNORECASE | re.UNICODE,
)
_WIN_PING_SENT_RE = re.compile(
    r"(?:Sent|Отправлено|Gesendet)\s*=\s*([0-9]+)", re.IGNORECASE | re.UNICODE
)
_WIN_PING_RECV_RE = re.compile(
    r"(?:Received|Получено|Empfangen)\s*=\s*([0-9]+)", re.IGNORECASE | re.UNICODE
)
# TTL belgisi har tilda lotin "TTL" bo'lib qoladi (RUS chiqishida ham "TTL=").
# Shuning uchun javob qatorini aniqlash uchun "ttl" ni qidiramiz (til-mustaqil).


def parse_windows_ping(output: str, expected_count: int) -> tuple[bool, list[float], float]:
    """Windows `ping` chiqishini (alive, rtts_ms, loss) ga aylantiradi.

    TIL-MUSTAQIL: ingliz, rus (cp866 dekodlangan), nemis chiqishini tushunadi.
    Bu — IcmpSendEcho mavjud bo'lmagan holatdagi zaxira yo'l.

    Argumentlar:
        output — `ping ...` to'liq stdout matni (allaqachon dekodlangan).
        expected_count — yuborilgan paketlar soni (loss zaxira hisobi uchun).

    Qaytaradi:
        alive — kamida bitta javob kelganmi.
        rtts_ms — har javob RTT'si (ms); javobsizlar kirmaydi.
        loss — paket yo'qotish ulushi (0.0..1.0).
    """
    rtts: list[float] = []
    for line in output.splitlines():
        # Javob qatorini "TTL" bo'yicha aniqlaymiz (RUS chiqishida ham "TTL=").
        low = line.lower()
        if "ttl=" not in low and "ttl =" not in low:
            continue
        if _WIN_PING_SUBMS_RE.search(line):
            rtts.append(0.5)
            continue
        m = _WIN_PING_RTT_RE.search(line)
        if m:
            rtts.append(float(m.group(1).replace(",", ".")))

    # Loss: avval yakuniy statistika foizidan ("(25% loss)") — til-mustaqil.
    loss: float | None = None
    pct = _WIN_PING_LOSS_PCT_RE.search(output)
    if pct:
        loss = int(pct.group(1)) / 100.0
    else:
        for line in output.splitlines():
            if not _WIN_PING_STATS_LINE_RE.search(line):
                continue
            sent_m = _WIN_PING_SENT_RE.search(line)
            recv_m = _WIN_PING_RECV_RE.search(line)
            if sent_m and recv_m:
                sent = int(sent_m.group(1))
                received = int(recv_m.group(1))
                loss = (sent - received) / sent if sent else 1.0
                break

    alive = len(rtts) > 0
    if loss is None:
        count = expected_count if expected_count > 0 else 1
        loss = max(0.0, (count - len(rtts)) / count)
    return alive, rtts, loss


# --- Windows `tracert` chiqishini parse qilish (TIL-MUSTAQIL ZAXIRA) ---------

_WIN_TRACERT_LINE_RE = re.compile(
    r"^\s*(\d+)\s+(.*?)\s*$",
)
# RTT ustuni: ascii "12 ms" yoki kirill "12 мс" (o'nlik vergul ham).
_WIN_TRACERT_RTT_RE = re.compile(r"([0-9]+(?:[.,][0-9]+)?)\s*(?:ms|мс)", re.IGNORECASE | re.UNICODE)
_WIN_TRACERT_SUBMS_RE = re.compile(r"<\s*1\s*(?:ms|мс)", re.IGNORECASE | re.UNICODE)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F:]{2,}:[0-9a-fA-F:]*)\b")


def parse_windows_tracert(output: str) -> list[tuple[int, str | None, float, bool]]:
    """Windows `tracert -d` chiqishini hop ro'yxatiga aylantiradi (til-mustaqil).

    Qaytaradi: har element `(hop_index, address|None, avg_rtt_ms, alive)`.

    `address` topilmasa (`* * *` / `Request timed out` / `Превышен интервал`) ->
    None, alive=False, rtt=0. RTT — qatordagi o'lchovlar o'rtachasi (ms).
    `<1 ms`/`<1 мс` => 0.5ms. IcmpSendEcho yo'q holatdagi zaxira.
    """
    hops: list[tuple[int, str | None, float, bool]] = []
    for line in output.splitlines():
        m = _WIN_TRACERT_LINE_RE.match(line)
        if not m:
            continue
        index = int(m.group(1))
        rest = m.group(2)

        addr: str | None = None
        ip4 = _IPV4_RE.search(rest)
        if ip4:
            addr = ip4.group(1)
        else:
            ip6 = _IPV6_RE.search(rest)
            if ip6 and ":" in ip6.group(1):
                addr = ip6.group(1)

        measure_part = rest
        if addr:
            measure_part = rest.replace(addr, " ")

        rtts: list[float] = []
        subms = len(_WIN_TRACERT_SUBMS_RE.findall(measure_part))
        rtts.extend([0.5] * subms)
        cleaned = _WIN_TRACERT_SUBMS_RE.sub(" ", measure_part)
        for rm in _WIN_TRACERT_RTT_RE.finditer(cleaned):
            rtts.append(float(rm.group(1).replace(",", ".")))

        alive = addr is not None
        avg_rtt = sum(rtts) / len(rtts) if rtts else 0.0
        hops.append((index, addr, avg_rtt, alive))
    return hops


# --- Windows `route print` chiqishidan default gateway ----------------------

_WIN_ROUTE_DEFAULT_RE = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.MULTILINE,
)
_WIN_NETROUTE_NEXTHOP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})",
)


def parse_windows_route_print(output: str) -> str | None:
    """`route print -4` chiqishidan default (0.0.0.0/0) gateway IP'ni oladi."""
    m = _WIN_ROUTE_DEFAULT_RE.search(output)
    if m and m.group(1) != "0.0.0.0":
        return m.group(1)
    return None


# --- Umumiy async subprocess yordamchisi ------------------------------------


# Tarmoq buyruqlarining ko'pchiligi PATH'da BO'LMAYDIGAN kataloglarda yotadi:
# `system_profiler`, `ndp`, `arp`, `route`, `ifconfig` -> /usr/sbin yoki /sbin.
# Interaktiv qobiqda ular PATH'da bo'ladi, lekin `cron`, `systemd` va launchd
# odatda `PATH=/usr/bin:/bin` beradi — aynan sysadmin toolni avtomatlashtirgan
# joyda. O'lchab ko'rildi: shunday PATH bilan `doctor` link turini "wifi"
# o'rniga "wired" deb aniqlab, chegaralarni noto'g'ri tanladi.
_EXTRA_BIN_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin")


@functools.lru_cache(maxsize=64)
def resolve_binary(name: str) -> str:
    """Buyruq nomini to'liq yo'lga aylantiradi; topilmasa nomni qaytaradi.

    Avval PATH, keyin `_EXTRA_BIN_DIRS`. Topilmasa nom o'zgarishsiz qaytadi —
    `create_subprocess_exec` o'zi `FileNotFoundError` beradi va `run_command`
    uni bo'sh satrga aylantiradi (mavjud xatti-harakat saqlanadi).

    Yo'l (`/` yoki `\\` bor) berilgan bo'lsa tegilmaydi.
    """
    if os.sep in name or (os.altsep and os.altsep in name):
        return name
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_BIN_DIRS:
        candidate = os.path.join(d, name)
        if os.access(candidate, os.X_OK):
            return candidate
    return name


async def run_command(
    cmd: list[str],
    timeout: float,
    include_stderr: bool = False,
) -> str:
    """Buyruqni async ishga tushirib stdout matnini qaytaradi (bloklanmaydi).

    Chiqish `decode_console` bilan dekodlanadi — Windows OEM codepage (cp866/
    cp850) to'g'ri o'qiladi (kirill mojibake yo'q). Windows'da CREATE_NO_WINDOW
    bilan ishga tushadi (konsol oynasi miltillamasin).

    `include_stderr=True` — stderr ham qo'shiladi. Ba'zi diagnostika xabarlari
    AYNAN stderr'ga yoziladi: macOS `ping` "Message too long" ni shu yerga
    chiqaradi va uni tashlab yuborish path-MTU aniqlashni butunlay ishlamas
    qilardi ("juda katta" javobi hech qachon ko'rinmasdi).

    Xato (buyruq yo'q / timeout / OS) bo'lsa bo'sh satr qaytaradi — chaqiruvchi
    "natija yo'q" deb degrade qilaverishi uchun (istisno ko'tarilmaydi).
    """
    cmd = [resolve_binary(cmd[0]), *cmd[1:]] if cmd else cmd
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=(
                asyncio.subprocess.STDOUT if include_stderr
                else asyncio.subprocess.DEVNULL
            ),
            creationflags=subprocess_flags(),
        )
    except (OSError, ValueError):
        return ""
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return ""
    except OSError:
        return ""
    return decode_console(stdout)
