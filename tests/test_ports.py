"""ports testlari — OFFLINE.

``parse_ports`` (spec parsing — diapazon, ro'yxat, chekka holatlar),
``default_ports``, ``PortResult``/``ScanResult`` xossalari. Sof mantiq, tarmoq yo'q.
"""

from __future__ import annotations

from systop.core.ports import (
    COMMON_PORTS,
    STATE_CLOSED,
    STATE_FILTERED,
    STATE_OPEN,
    PortResult,
    ScanResult,
    default_ports,
    parse_ports,
)

# --- parse_ports ------------------------------------------------------------


def test_parse_ports_comma_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("80-83") == [80, 81, 82, 83]


def test_parse_ports_mixed():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_dedup_and_sort():
    assert parse_ports("443,22,443,80,22") == [22, 80, 443]


def test_parse_ports_reversed_range_normalized():
    assert parse_ports("83-80") == [80, 81, 82, 83]


def test_parse_ports_whitespace_tolerant():
    assert parse_ports(" 22 , 80 , 443 ") == [22, 80, 443]


def test_parse_ports_ignores_garbage():
    assert parse_ports("22,abc,80,,443") == [22, 80, 443]


def test_parse_ports_ignores_garbage_range():
    assert parse_ports("22,foo-bar,80") == [22, 80]


def test_parse_ports_clamps_out_of_range():
    # 0 va 70000 -> chegaralangan; 1 va 65535 chegaralarini saqlaydi.
    assert parse_ports("0,1,65535,70000") == [1, 65535]


def test_parse_ports_range_clamps_to_valid_window():
    # 0-3 -> 1..3 (0 chiqarib tashlanadi).
    assert parse_ports("0-3") == [1, 2, 3]
    # 65534-70000 -> 65534, 65535.
    assert parse_ports("65534-70000") == [65534, 65535]


def test_parse_ports_empty_string():
    assert parse_ports("") == []


def test_parse_ports_only_commas():
    assert parse_ports(",,,") == []


def test_parse_ports_single_port():
    assert parse_ports("8080") == [8080]


def test_parse_ports_full_range_size():
    result = parse_ports("1-1024")
    assert result[0] == 1
    assert result[-1] == 1024
    assert len(result) == 1024


def test_parse_ports_negative_token_ignored():
    # "-5" -> partition("-") => lo_s="", hi_s="5" -> int("") ValueError -> skip.
    assert parse_ports("-5,80") == [80]


# --- default_ports ----------------------------------------------------------


def test_default_ports_sorted_and_complete():
    dp = default_ports()
    assert dp == sorted(COMMON_PORTS)
    assert 22 in dp and 443 in dp
    assert dp == sorted(set(dp))  # takrorsiz


# --- PortResult / ScanResult ------------------------------------------------


def test_port_result_is_open():
    assert PortResult(port=22, state=STATE_OPEN).is_open is True
    assert PortResult(port=22, state=STATE_CLOSED).is_open is False
    assert PortResult(port=22, state=STATE_FILTERED).is_open is False


def test_scan_result_open_ports_filter():
    sr = ScanResult(
        host="example.com",
        resolved_ip="93.184.216.34",
        ports=[
            PortResult(port=22, state=STATE_OPEN),
            PortResult(port=80, state=STATE_OPEN),
            PortResult(port=23, state=STATE_CLOSED),
            PortResult(port=3306, state=STATE_FILTERED),
        ],
    )
    open_ports = sr.open_ports
    assert [p.port for p in open_ports] == [22, 80]


def test_scan_result_error_defaults():
    sr = ScanResult(host="bad.host")
    assert sr.error is None
    assert sr.resolved_ip is None
    assert sr.ports == []
    assert sr.open_ports == []
