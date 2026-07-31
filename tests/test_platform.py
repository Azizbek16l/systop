"""_platform Windows parse funksiyalari testlari — OFFLINE.

Windows `ping` / `tracert` / `route print` ning REAL chiqish namunalari bilan
sof parse mantiqi sinaladi. Hech qanday subprocess yoki tarmoq chaqiruvi yo'q —
faqat satr -> qiymat. CI keyin real Windows'da haqiqiy buyruqlar bilan sinaydi.
"""

from __future__ import annotations

import pytest

from systop.core import _platform
from systop.core._platform import (
    parse_windows_ping,
    parse_windows_route_print,
    parse_windows_tracert,
)

# --- parse_windows_ping -----------------------------------------------------

# Tipik muvaffaqiyatli `ping -n 4 8.8.8.8` chiqishi (en-US).
_PING_OK = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=12ms TTL=117
Reply from 8.8.8.8: bytes=32 time=11ms TTL=117
Reply from 8.8.8.8: bytes=32 time=13ms TTL=117
Reply from 8.8.8.8: bytes=32 time=12ms TTL=117

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 13ms, Average = 12ms
"""

# Lokal gateway — submilliyenniy RTT ("time<1ms").
_PING_SUBMS = """
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
"""

# Qisman yo'qotish.
_PING_PARTIAL = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=20ms TTL=58
Request timed out.
Reply from 1.1.1.1: bytes=32 time=22ms TTL=58
Request timed out.

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 20ms, Maximum = 22ms, Average = 21ms
"""

# Butunlay yetib bo'lmagan host.
_PING_DEAD = """
Pinging 10.255.255.1 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 10.255.255.1:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
"""

# "Destination host unreachable" — javob bor, lekin TTL'siz; RTT yo'q.
_PING_UNREACHABLE = """
Pinging 192.168.5.5 with 32 bytes of data:
Reply from 192.168.1.10: Destination host unreachable.
Reply from 192.168.1.10: Destination host unreachable.

Ping statistics for 192.168.5.5:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
"""


def test_parse_ping_ok_all_replies():
    alive, rtts, loss = parse_windows_ping(_PING_OK, expected_count=4)
    assert alive is True
    assert rtts == [12.0, 11.0, 13.0, 12.0]
    assert loss == pytest.approx(0.0)


def test_parse_ping_submillisecond():
    alive, rtts, loss = parse_windows_ping(_PING_SUBMS, expected_count=3)
    assert alive is True
    # "time<1ms" -> 0.5ms deb olinadi.
    assert rtts == [0.5, 0.5, 0.5]
    assert loss == pytest.approx(0.0)


def test_parse_ping_partial_loss():
    alive, rtts, loss = parse_windows_ping(_PING_PARTIAL, expected_count=4)
    assert alive is True
    assert rtts == [20.0, 22.0]
    assert loss == pytest.approx(0.5)


def test_parse_ping_dead_host():
    alive, rtts, loss = parse_windows_ping(_PING_DEAD, expected_count=4)
    assert alive is False
    assert rtts == []
    assert loss == pytest.approx(1.0)


def test_parse_ping_unreachable_no_ttl_not_counted():
    """`Destination host unreachable` qatorlari TTL'siz -> RTT sifatida sanalmaydi."""
    alive, rtts, loss = parse_windows_ping(_PING_UNREACHABLE, expected_count=2)
    # TTL bo'lmagani uchun hech qanday RTT olinmaydi -> alive=False.
    assert rtts == []
    assert alive is False
    # Loss esa statistika qatoridan ("0% loss") aniq olinadi.
    assert loss == pytest.approx(0.0)


def test_parse_ping_empty_output():
    alive, rtts, loss = parse_windows_ping("", expected_count=4)
    assert alive is False
    assert rtts == []
    assert loss == pytest.approx(1.0)


def test_parse_ping_loss_falls_back_to_sent_recv_without_pct():
    """Foiz ko'rinmasa, `Sent = X, Received = Y, Lost = Z` dan loss hisoblanadi."""
    out = (
        "Reply from 8.8.8.8: bytes=32 time=10ms TTL=117\n"
        "Reply from 8.8.8.8: bytes=32 time=10ms TTL=117\n"
        "    Packets: Sent = 4, Received = 2, Lost = 2\n"  # foizsiz
    )
    alive, rtts, loss = parse_windows_ping(out, expected_count=4)
    assert alive is True
    assert rtts == [10.0, 10.0]
    assert loss == pytest.approx(0.5)


def test_parse_ping_no_stats_estimates_from_rtt_count():
    """Statistika bloki yo'q -> RTT soni va expected_count dan loss taxminlanadi."""
    out = (
        "Reply from 8.8.8.8: bytes=32 time=10ms TTL=117\n"
        "Reply from 8.8.8.8: bytes=32 time=11ms TTL=117\n"
    )
    alive, rtts, loss = parse_windows_ping(out, expected_count=4)
    assert alive is True
    assert rtts == [10.0, 11.0]
    # 2 javob / 4 yuborilgan -> 50% loss (taxminiy).
    assert loss == pytest.approx(0.5)


# --- parse_windows_tracert --------------------------------------------------

# Tipik `tracert -d 8.8.8.8` chiqishi (en-US).
_TRACERT_OK = """
Tracing route to 8.8.8.8 over a maximum of 30 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     8 ms     9 ms     7 ms  10.0.0.1
  3     *        *        *     Request timed out.
  4    12 ms    11 ms    13 ms  8.8.8.8

Trace complete.
"""

# Submilliyenniy birinchi hop ("<1 ms").
_TRACERT_SUBMS = """
Tracing route to 1.1.1.1 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2    10 ms    11 ms    10 ms  1.1.1.1

Trace complete.
"""


def test_parse_tracert_maps_hops():
    hops = parse_windows_tracert(_TRACERT_OK)
    assert [h[0] for h in hops] == [1, 2, 3, 4]
    # hop 1: 192.168.1.1, avg(1,1,1)=1.0, alive
    assert hops[0] == (1, "192.168.1.1", pytest.approx(1.0), True)
    # hop 2: 10.0.0.1, avg(8,9,7)=8.0
    assert hops[1] == (2, "10.0.0.1", pytest.approx(8.0), True)
    # hop 3: timeout -> None manzil, rtt 0, alive False
    assert hops[2] == (3, None, pytest.approx(0.0), False)
    # hop 4: maqsad
    assert hops[3] == (4, "8.8.8.8", pytest.approx(12.0), True)


def test_parse_tracert_submillisecond_first_hop():
    hops = parse_windows_tracert(_TRACERT_SUBMS)
    # "<1 ms" x3 -> avg 0.5
    assert hops[0] == (1, "192.168.1.1", pytest.approx(0.5), True)
    assert hops[1] == (2, "1.1.1.1", pytest.approx(10.0 + 1 / 3), True)


def test_parse_tracert_ip_octets_not_counted_as_rtt():
    """Maqsad IP raqamlari (masalan 8.8.8.8) RTT sifatida hisoblanmasligi kerak."""
    line = "  4    12 ms    11 ms    13 ms  8.8.8.8\n"
    hops = parse_windows_tracert(line)
    assert len(hops) == 1
    idx, addr, rtt, alive = hops[0]
    assert addr == "8.8.8.8"
    # Faqat 12,11,13 -> avg 12.0; 8'lar kirmasligi shart.
    assert rtt == pytest.approx(12.0)


def test_parse_tracert_empty():
    assert parse_windows_tracert("") == []


def test_parse_tracert_ignores_header_lines():
    out = "Tracing route to 8.8.8.8 over a maximum of 30 hops\n\nTrace complete.\n"
    assert parse_windows_tracert(out) == []


# --- parse_windows_route_print ----------------------------------------------

# `route print -4` ning IPv4 Route Table qismi.
_ROUTE_PRINT = """
===========================================================================
Interface List
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     35
      192.168.1.0    255.255.255.0         On-link      192.168.1.50    291
===========================================================================
"""

# On-link default (gateway yo'q, faqat "On-link") -> None.
_ROUTE_PRINT_ONLINK_DEFAULT = """
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link      10.0.0.5     35
"""


def test_parse_route_print_default_gateway():
    assert parse_windows_route_print(_ROUTE_PRINT) == "192.168.1.1"


def test_parse_route_print_onlink_default_returns_none():
    # Default qatorida gateway IP emas "On-link" bo'lsa, gateway topilmaydi.
    assert parse_windows_route_print(_ROUTE_PRINT_ONLINK_DEFAULT) is None


def test_parse_route_print_no_default_returns_none():
    out = (
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "      192.168.1.0    255.255.255.0         On-link      192.168.1.50    291\n"
    )
    assert parse_windows_route_print(out) is None


def test_parse_route_print_empty():
    assert parse_windows_route_print("") is None


# --- platforma konstantalari mavjudligi -------------------------------------


def test_platform_constants_exist():
    # Aniq bittasi True (host platformasi) — lekin offline'da faqat mavjudligini
    # va boolean ekanini tekshiramiz (host turini emas).
    assert isinstance(_platform.IS_WINDOWS, bool)
    assert isinstance(_platform.IS_MACOS, bool)
    assert isinstance(_platform.IS_LINUX, bool)


# --- TIL-MUSTAQIL parse: RUS (cp866) + DE (cp850) namunalar -----------------
#
# Bu Unicode satrlar dekodlangan (decode_console natijasi) ko'rinishida. Byte
# darajadagi cp866 dekodlash alohida (decode_console) testlarda sinaladi.

# RUS `ping 8.8.8.8` (codepage 866, ru-RU) chiqishi shaklida.
# Diqqat: RTT "время=84мс" (kirill 'мс'), "время<1мс" submilliyenniy, statistika
# "Пакетов: отправлено = 4, получено = 4 ... (0% потерь)".
_PING_RU = (
    "Обмен пакетами с 8.8.8.8 по с 32 байтами данных:\n"
    "Ответ от 8.8.8.8: число байт=32 время=84мс TTL=107\n"
    "Ответ от 8.8.8.8: число байт=32 время=85мс TTL=107\n"
    "Ответ от 8.8.8.8: число байт=32 время<1мс TTL=107\n"
    "Ответ от 8.8.8.8: число байт=32 время=83мс TTL=107\n"
    "\n"
    "Статистика Ping для 8.8.8.8:\n"
    "    Пакетов: отправлено = 4, получено = 4, потеряно = 0 (0% потерь),\n"
)

# RUS — barcha paket yo'qolgan (host o'lik): "(100% потерь)".
_PING_RU_DEAD = (
    "Обмен пакетами с 10.255.255.1 по с 32 байтами данных:\n"
    "Превышен интервал ожидания для запроса.\n"
    "Превышен интервал ожидания для запроса.\n"
    "\n"
    "Статистика Ping для 10.255.255.1:\n"
    "    Пакетов: отправлено = 2, получено = 0, потеряно = 2 (100% потерь),\n"
)

# Nemis `ping 8.8.8.8` (codepage 850, de-DE) — RTT "Zeit=12ms", qisman yo'qotish.
_PING_DE = (
    "Ping wird ausgeführt für 8.8.8.8 mit 32 Bytes Daten:\n"
    "Antwort von 8.8.8.8: Bytes=32 Zeit=12ms TTL=117\n"
    "Antwort von 8.8.8.8: Bytes=32 Zeit=11ms TTL=117\n"
    "\n"
    "Ping-Statistik für 8.8.8.8:\n"
    "    Pakete: Gesendet = 4, Empfangen = 2, Verloren = 2 (50% Verlust),\n"
)


def test_parse_ping_russian_cp866_text():
    """RUS chiqish: kirill 'мс' RTT va '(0% потерь)' loss to'g'ri o'qiladi."""
    alive, rtts, loss = parse_windows_ping(_PING_RU, expected_count=4)
    assert alive is True
    # 84, 85, <1мс->0.5, 83
    assert rtts == [84.0, 85.0, 0.5, 83.0]
    assert loss == pytest.approx(0.0)


def test_parse_ping_russian_dead_host():
    """RUS '(100% потерь)' -> alive=False, loss=1.0."""
    alive, rtts, loss = parse_windows_ping(_PING_RU_DEAD, expected_count=2)
    assert alive is False
    assert rtts == []
    assert loss == pytest.approx(1.0)


def test_parse_ping_german_cp850_text():
    """DE chiqish: 'Zeit=12ms' RTT va '(50% Verlust)' loss to'g'ri o'qiladi."""
    alive, rtts, loss = parse_windows_ping(_PING_DE, expected_count=4)
    assert alive is True
    assert rtts == [12.0, 11.0]
    assert loss == pytest.approx(0.5)


def test_parse_ping_russian_loss_from_sent_recv_without_pct():
    """RUS, foizsiz: 'отправлено = 4, получено = 1' dan loss hisoblanadi."""
    out = (
        "Ответ от 8.8.8.8: число байт=32 время=10мс TTL=117\n"
        "    Пакетов: отправлено = 4, получено = 1, потеряно = 3\n"  # foizsiz
    )
    alive, rtts, loss = parse_windows_ping(out, expected_count=4)
    assert alive is True
    assert rtts == [10.0]
    assert loss == pytest.approx(0.75)


def test_parse_ping_decimal_comma_rtt():
    """O'nlik vergul (RUS/DE) RTT: 'время=1,5мс' -> 1.5."""
    out = "Ответ от 1.1.1.1: число байт=32 время=1,5мс TTL=64\n"
    alive, rtts, _loss = parse_windows_ping(out, expected_count=1)
    assert alive is True
    assert rtts == [1.5]


# RUS `tracert -d 8.8.8.8` (codepage 866).
_TRACERT_RU = (
    "Трассировка маршрута к 8.8.8.8 с максимальным числом прыжков 30\n"
    "\n"
    "  1     1 мс     1 мс     1 мс  192.168.1.1\n"
    "  2     8 мс     9 мс     7 мс  10.0.0.1\n"
    "  3     *        *        *     Превышен интервал ожидания для запроса.\n"
    "  4    12 мс    11 мс    13 мс  8.8.8.8\n"
    "\n"
    "Трассировка завершена.\n"
)


def test_parse_tracert_russian_cp866_text():
    """RUS tracert: kirill 'мс' RTT, '* * *' timeout hop."""
    hops = parse_windows_tracert(_TRACERT_RU)
    assert [h[0] for h in hops] == [1, 2, 3, 4]
    assert hops[0] == (1, "192.168.1.1", pytest.approx(1.0), True)
    assert hops[1] == (2, "10.0.0.1", pytest.approx(8.0), True)
    assert hops[2] == (3, None, pytest.approx(0.0), False)
    assert hops[3] == (4, "8.8.8.8", pytest.approx(12.0), True)


# --- decode_console: BYTE darajada cp866 / cp850 dekodlash ------------------


def test_decode_console_passthrough_str():
    """Allaqachon str kelsa — o'zgartirmasdan qaytaradi (text=True/fixture)."""
    assert _platform.decode_console("hello мир") == "hello мир"


def test_decode_console_non_windows_uses_utf8(monkeypatch):
    """Windows EMAS bo'lganda UTF-8 dekodlanadi (macOS/Linux)."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", False)
    data = "Ответ от 8.8.8.8".encode()
    assert _platform.decode_console(data) == "Ответ от 8.8.8.8"


def test_decode_console_windows_cp866(monkeypatch):
    """Windows cp866 baytlari kirill matnga to'g'ri dekodlanishi kerak.

    UTF-8 dekodlash bu baytlarni mojibake qilardi — `decode_console`
    GetConsoleOutputCP -> 866 ni o'qib cp866 bilan dekodlaydi.
    """
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 866)
    text = "Ответ от 8.8.8.8: число байт=32 время=84мс TTL=107"
    data = text.encode("cp866")
    decoded = _platform.decode_console(data)
    assert decoded == text
    # UTF-8 bilan dekodlash boshqacha (mojibake) bo'lardi — farqni tasdiqlaymiz.
    assert decoded != data.decode("utf-8", errors="replace")


def test_decode_console_windows_cp850(monkeypatch):
    """Nemis Windows: cp850 baytlari to'g'ri dekodlanadi."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 850)
    text = "Ping wird ausgeführt für 8.8.8.8"
    data = text.encode("cp850")
    assert _platform.decode_console(data) == text


def test_decode_console_full_ru_ping_bytes(monkeypatch):
    """To'liq RUS ping chiqishi cp866 baytlardan dekodlanib parse qilinadi."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 866)
    raw = _PING_RU.encode("cp866")
    decoded = _platform.decode_console(raw)
    alive, rtts, loss = parse_windows_ping(decoded, expected_count=4)
    assert alive is True
    assert rtts == [84.0, 85.0, 0.5, 83.0]
    assert loss == pytest.approx(0.0)


def test_decode_console_unknown_codepage_falls_back_utf8(monkeypatch):
    """Noma'lum codepage (LookupError) -> UTF-8 zaxirasi (istisno yo'q)."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 999999)
    data = b"hello"
    assert _platform.decode_console(data) == "hello"


def test_decode_console_cp_zero_uses_utf8(monkeypatch):
    """GetConsoleOutputCP 0 (aniqlanmadi) -> UTF-8."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 0)
    assert _platform.decode_console(b"ascii") == "ascii"


# --- init_console / unicode_ok / subprocess_flags ---------------------------


def test_init_console_noop_on_non_windows(monkeypatch):
    """init_console Windows bo'lmaganda hech narsa qilmaydi (xato yo'q)."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", False)
    # Hech qanday istisno ko'tarmasligi kerak.
    assert _platform.init_console() is None


def test_unicode_ok_true_on_non_windows(monkeypatch):
    monkeypatch.setattr(_platform, "IS_WINDOWS", False)
    assert _platform.unicode_ok() is True


def test_unicode_ok_windows_terminal_session(monkeypatch):
    """Windows Terminal (WT_SESSION) ostida Unicode OK."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.setenv("WT_SESSION", "abc-123")
    assert _platform.unicode_ok() is True


def test_unicode_ok_windows_utf8_codepage(monkeypatch):
    """Legacy konsol, lekin codepage 65001 (UTF-8) -> Unicode OK."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.delenv("WT_SESSION", raising=False)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 65001)
    assert _platform.unicode_ok() is True


def test_unicode_ok_windows_legacy_cp866_false(monkeypatch):
    """Legacy cmd.exe (cp866, WT yo'q) -> Unicode raster ko'rsata olmaydi -> False."""
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    monkeypatch.delenv("WT_SESSION", raising=False)
    monkeypatch.setattr(_platform, "_console_output_cp", lambda: 866)
    assert _platform.unicode_ok() is False


def test_subprocess_flags_zero_on_non_windows(monkeypatch):
    monkeypatch.setattr(_platform, "IS_WINDOWS", False)
    assert _platform.subprocess_flags() == 0


def test_subprocess_flags_create_no_window_on_windows(monkeypatch):
    monkeypatch.setattr(_platform, "IS_WINDOWS", True)
    # win32'da CREATE_NO_WINDOW (0x08000000); test hostida getattr fallback 0
    # bo'lishi mumkin — shuning uchun _CREATE_NO_WINDOW konstantasiga tenglashtiramiz.
    assert _platform.subprocess_flags() == _platform._CREATE_NO_WINDOW


# --- Win32 IcmpSendEcho yo'li (ctypes monkeypatch bilan) --------------------


def test_win_icmp_ping_success(monkeypatch):
    """IcmpSendEcho SUCCESS javoblari -> alive, RTT yig'iladi, loss=0."""
    # iphlpapi "mavjud" deb ko'rsatamiz (None emas).
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: "8.8.8.8")

    rtts_seq = [84.0, 85.0, 83.0]
    calls = {"n": 0}

    def fake_icmp(ipv4, timeout_ms, ttl=None):
        i = calls["n"]
        calls["n"] += 1
        return _platform.IP_SUCCESS, rtts_seq[i], "8.8.8.8"

    monkeypatch.setattr(_platform, "icmp_ping_ipv4", fake_icmp)

    result = _platform.win_icmp_ping("8.8.8.8", count=3, timeout=2.0)
    assert result is not None
    alive, rtts, loss = result
    assert alive is True
    assert rtts == [84.0, 85.0, 83.0]
    assert loss == pytest.approx(0.0)


def test_win_icmp_ping_partial_loss(monkeypatch):
    """Ba'zi probe'lar TIMED_OUT -> loss hisoblanadi (alive baribir True)."""
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: "1.1.1.1")

    seq = [
        (_platform.IP_SUCCESS, 20.0, "1.1.1.1"),
        (_platform.IP_REQ_TIMED_OUT, 0.0, None),
        (_platform.IP_SUCCESS, 22.0, "1.1.1.1"),
        (_platform.IP_REQ_TIMED_OUT, 0.0, None),
    ]
    calls = {"n": 0}

    def fake_icmp(ipv4, timeout_ms, ttl=None):
        out = seq[calls["n"]]
        calls["n"] += 1
        return out

    monkeypatch.setattr(_platform, "icmp_ping_ipv4", fake_icmp)
    alive, rtts, loss = _platform.win_icmp_ping("1.1.1.1", count=4, timeout=2.0)
    assert alive is True
    assert rtts == [20.0, 22.0]
    assert loss == pytest.approx(0.5)


def test_win_icmp_ping_all_timeout_dead(monkeypatch):
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: "10.255.255.1")
    monkeypatch.setattr(
        _platform,
        "icmp_ping_ipv4",
        lambda ipv4, timeout_ms, ttl=None: (_platform.IP_REQ_TIMED_OUT, 0.0, None),
    )
    alive, rtts, loss = _platform.win_icmp_ping("10.255.255.1", count=4, timeout=1.0)
    assert alive is False
    assert rtts == []
    assert loss == pytest.approx(1.0)


def test_win_icmp_ping_none_when_no_dll(monkeypatch):
    """iphlpapi yo'q -> None (chaqiruvchi ping.exe zaxirasiga o'tadi)."""
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: None)
    assert _platform.win_icmp_ping("8.8.8.8", count=4, timeout=2.0) is None


def test_win_icmp_ping_none_when_unresolvable(monkeypatch):
    """IPv4'ga resolve bo'lmasa -> None (IPv6/nom zaxirasiga o'tadi)."""
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: None)
    assert _platform.win_icmp_ping("ipv6.example", count=2, timeout=1.0) is None


def test_win_icmp_traceroute_reaches_target(monkeypatch):
    """TTL_EXPIRED oraliq hoplar + SUCCESS oxirgi hop; SUCCESS'da to'xtaydi."""
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: "8.8.8.8")

    # ttl=1 -> router, ttl=2 -> router, ttl=3 -> manzil (SUCCESS).
    by_ttl = {
        1: (_platform.IP_TTL_EXPIRED_TRANSIT, 1.0, "192.168.1.1"),
        2: (_platform.IP_TTL_EXPIRED_TRANSIT, 8.0, "10.0.0.1"),
        3: (_platform.IP_SUCCESS, 12.0, "8.8.8.8"),
    }

    def fake_icmp(ipv4, timeout_ms, ttl=None):
        return by_ttl[ttl]

    monkeypatch.setattr(_platform, "icmp_ping_ipv4", fake_icmp)
    hops = _platform.win_icmp_traceroute("8.8.8.8", max_hops=30, timeout=2.0)
    assert hops is not None
    assert hops == [
        (1, "192.168.1.1", 1.0, True),
        (2, "10.0.0.1", 8.0, True),
        (3, "8.8.8.8", 12.0, True),
    ]


def test_win_icmp_traceroute_timeout_hop(monkeypatch):
    """Javobsiz TTL -> (ttl, None, 0.0, False) hop; manzilga yetguncha davom."""
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: "8.8.8.8")

    by_ttl = {
        1: (_platform.IP_TTL_EXPIRED_TRANSIT, 1.0, "192.168.1.1"),
        2: (_platform.IP_REQ_TIMED_OUT, 0.0, None),  # `* * *`
        3: (_platform.IP_SUCCESS, 12.0, "8.8.8.8"),
    }
    monkeypatch.setattr(_platform, "icmp_ping_ipv4", lambda ipv4, timeout_ms, ttl=None: by_ttl[ttl])
    hops = _platform.win_icmp_traceroute("8.8.8.8", max_hops=30, timeout=2.0)
    assert hops == [
        (1, "192.168.1.1", 1.0, True),
        (2, None, 0.0, False),
        (3, "8.8.8.8", 12.0, True),
    ]


def test_win_icmp_traceroute_none_when_no_dll(monkeypatch):
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: None)
    assert _platform.win_icmp_traceroute("8.8.8.8", max_hops=30, timeout=2.0) is None


def test_win_icmp_traceroute_none_when_unresolvable(monkeypatch):
    monkeypatch.setattr(_platform, "_iphlpapi", lambda: object())
    monkeypatch.setattr(_platform, "_resolve_ipv4", lambda a: None)
    assert _platform.win_icmp_traceroute("bad.host", max_hops=10, timeout=1.0) is None


def test_addr_dword_roundtrip():
    """IPv4 <-> DWORD aylantirish ikki tomonlama mos."""
    for ip in ("8.8.8.8", "192.168.1.1", "1.1.1.1", "255.255.255.255", "0.0.0.0"):
        dword = _platform._addr_to_dword(ip)
        assert dword is not None
        assert _platform._dword_to_addr(dword) == ip


def test_addr_to_dword_invalid_returns_none():
    assert _platform._addr_to_dword("not-an-ip") is None


# --------------------------------------------------------------------------- #
# PATH qattiqlashtirish — cron/systemd ssenariysi
# --------------------------------------------------------------------------- #

from systop.core._platform import resolve_binary  # noqa: E402


def test_yol_berilgan_buyruq_tegilmaydi():
    """To'liq yo'l berilgan bo'lsa qidiruv qilinmasligi kerak."""
    assert resolve_binary("/usr/bin/env") == "/usr/bin/env"


def test_path_dagi_buyruq_topiladi():
    got = resolve_binary("sh")
    assert got.endswith("/sh")
    assert got.startswith("/")


def test_nomalum_buyruq_ozgarishsiz_qaytadi():
    """Topilmasa nom qaytadi — `run_command` mavjud xatti-harakatini saqlaydi.

    (`create_subprocess_exec` FileNotFoundError beradi, u bo'sh satrga aylanadi.)
    """
    assert resolve_binary("bunday_buyruq_yoq_12345") == "bunday_buyruq_yoq_12345"


def test_sbin_dagi_buyruq_path_da_bolmasa_ham_topiladi(monkeypatch):
    """ASOSIY REGRESSIYA.

    `cron` va `systemd` odatda `PATH=/usr/bin:/bin` beradi, ya'ni `/usr/sbin`
    yo'q. `system_profiler`, `ndp`, `arp`, `route`, `ifconfig` esa aynan
    o'sha yerda. O'lchab ko'rildi: bunday PATH bilan `doctor` link turini
    "wifi" o'rniga "wired" deb aniqlab, chegaralarni noto'g'ri tanlagan edi.
    """
    import os
    import shutil

    resolve_binary.cache_clear()
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    # /usr/sbin da chindan ham mavjud bo'lgan buyruqni tanlaymiz.
    nomzod = next(
        (n for n in ("arp", "ifconfig", "route") if os.access(f"/usr/sbin/{n}", os.X_OK)),
        None,
    )
    if nomzod is None:
        return  # bu platformada /usr/sbin yo'q — tekshiradigan narsa yo'q
    assert shutil.which(nomzod) is None, "test sharti buzildi: buyruq PATH'da"
    assert resolve_binary(nomzod) == f"/usr/sbin/{nomzod}"
    resolve_binary.cache_clear()
