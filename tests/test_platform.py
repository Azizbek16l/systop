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
