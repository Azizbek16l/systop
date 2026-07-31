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


# --------------------------------------------------------------------------- #
# IPv6 / manzil oilasi (family) — 0.4.0 da qo'shilgan
# --------------------------------------------------------------------------- #

from systop.core.ports import (  # noqa: E402
    FAMILY_AUTO,
    FAMILY_V4,
    FAMILY_V6,
    family_of,
)


def test_family_of_ipv4():
    assert family_of("192.168.1.1") == FAMILY_V4


def test_family_of_ipv6():
    assert family_of("2001:db8::1") == FAMILY_V6
    assert family_of("::1") == FAMILY_V6


def test_family_of_link_local_ipv6():
    assert family_of("fe80::1") == FAMILY_V6


def test_family_of_hostname_is_none():
    assert family_of("example.com") is None


def test_family_of_invalid_address_is_none():
    assert family_of("10.0.0.256") is None
    assert family_of("") is None


def test_scan_result_family_defaults_to_auto():
    assert ScanResult(host="x").family == FAMILY_AUTO
    assert ScanResult(host="x").resolved_family is None


def test_scan_result_records_resolved_family():
    r = ScanResult(host="x", resolved_ip="::1", family=FAMILY_V6, resolved_family=FAMILY_V6)
    assert r.resolved_family == FAMILY_V6


# --------------------------------------------------------------------------- #
# LAN sweep + banner (nmap -sT / -sV yengil) — 0.5.0
# --------------------------------------------------------------------------- #

from systop.core.ports import (  # noqa: E402
    TOP_PORTS,
    SweepResult,
    parse_banner,
    parse_targets,
    top_ports,
)

# --- parse_targets ---------------------------------------------------------- #


def test_parse_targets_single_ip():
    assert parse_targets("192.168.1.10") == ["192.168.1.10"]


def test_parse_targets_cidr_excludes_network_and_broadcast():
    r = parse_targets("192.168.1.0/29")
    assert r[0] == "192.168.1.1"
    assert "192.168.1.0" not in r
    assert "192.168.1.7" not in r  # broadcast
    assert len(r) == 6


def test_parse_targets_last_octet_range():
    assert parse_targets("10.0.0.5-8") == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]


def test_parse_targets_full_address_range():
    assert parse_targets("10.0.0.254-10.0.1.1") == [
        "10.0.0.254",
        "10.0.0.255",
        "10.0.1.0",
        "10.0.1.1",
    ]


def test_parse_targets_reversed_range_is_normalised():
    assert parse_targets("10.0.0.8-5") == parse_targets("10.0.0.5-8")


def test_parse_targets_comma_mixed():
    r = parse_targets("10.0.0.1,10.0.0.5-6,example.com")
    assert r == ["10.0.0.1", "10.0.0.5", "10.0.0.6", "example.com"]


def test_parse_targets_hostname_passthrough():
    assert parse_targets("example.com") == ["example.com"]


def test_parse_targets_hostname_with_dash_not_treated_as_range():
    """`my-host` diapazon emas — nom sifatida o'tishi kerak."""
    assert parse_targets("my-host") == ["my-host"]


def test_parse_targets_ipv6_single_accepted():
    assert parse_targets("2001:db8::1") == ["2001:db8::1"]


def test_parse_targets_ipv6_cidr_rejected():
    """/64 da 2^64 manzil — sweep imkonsiz, ataylab rad etiladi."""
    assert parse_targets("2001:db8::/64") == []


def test_parse_targets_respects_max_hosts():
    assert len(parse_targets("10.0.0.0/16", max_hosts=25)) == 25


def test_parse_targets_deduplicates_preserving_order():
    assert parse_targets("10.0.0.2,10.0.0.1,10.0.0.2") == ["10.0.0.2", "10.0.0.1"]


def test_parse_targets_empty_and_garbage():
    assert parse_targets("") == []
    assert parse_targets(",,") == []
    assert parse_targets("10.0.0.0/99") == []


# --- top_ports -------------------------------------------------------------- #


def test_top_ports_returns_sorted_subset():
    r = top_ports(5)
    assert len(r) == 5
    assert r == sorted(r)
    assert set(r) <= set(TOP_PORTS)


def test_top_ports_includes_80_and_443_in_top_3():
    assert 80 in top_ports(3)
    assert 443 in top_ports(3)


def test_top_ports_clamps_to_at_least_one():
    assert len(top_ports(0)) == 1


def test_top_ports_no_duplicates():
    assert len(set(TOP_PORTS)) == len(TOP_PORTS)


# --- parse_banner ----------------------------------------------------------- #


def test_parse_banner_ssh():
    assert parse_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n") == ("SSH", "OpenSSH_9.6p1 Ubuntu")


def test_parse_banner_smtp_postfix():
    svc, ver = parse_banner("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")
    assert svc == "SMTP"
    assert "Postfix" in ver


def test_parse_banner_ftp():
    svc, _ = parse_banner("220 ProFTPD 1.3.8 Server ready\r\n")
    assert svc == "FTP"


def test_parse_banner_pop3():
    assert parse_banner("+OK POP3 ready\r\n")[0] == "POP3"


def test_parse_banner_http_server_header():
    svc, ver = parse_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\n\r\n")
    assert svc == "HTTP"
    assert ver == "nginx/1.27.0"


def test_parse_banner_redis_noauth():
    svc, _ = parse_banner("-ERR NOAUTH Authentication required unauthenticated\r\n")
    assert "Redis" in svc


def test_parse_banner_unknown_returns_first_line():
    svc, ver = parse_banner("some random greeting\r\nsecond line\r\n")
    assert svc is None
    assert ver == "some random greeting"


def test_parse_banner_empty():
    assert parse_banner("") == (None, None)


def test_parse_banner_truncates_long_version():
    svc, ver = parse_banner("SSH-2.0-" + "x" * 500)
    assert len(ver) <= 120


# --- SweepResult ------------------------------------------------------------ #


def test_sweep_result_empty():
    s = SweepResult()
    assert s.responsive == []
    assert s.total_open == 0


def test_sweep_result_counts_open_across_hosts():
    from systop.core.ports import STATE_OPEN, PortResult

    h1 = ScanResult(host="a", ports=[PortResult(port=80, state=STATE_OPEN)])
    h2 = ScanResult(
        host="b",
        ports=[PortResult(port=22, state=STATE_OPEN), PortResult(port=443, state=STATE_OPEN)],
    )
    h3 = ScanResult(host="c", ports=[PortResult(port=80)])  # yopiq
    s = SweepResult(hosts=[h1, h2, h3], scanned_hosts=3, scanned_ports=3)
    assert len(s.responsive) == 2
    assert s.total_open == 3


def test_port_result_banner_defaults_none():
    from systop.core.ports import PortResult

    assert PortResult(port=22).banner is None


# --------------------------------------------------------------------------- #
# IPv6 zona + IPv4-mapped rad etish (0.9.0) — "IPv6 support" da'vosining asosi
# --------------------------------------------------------------------------- #

import asyncio  # noqa: E402
import socket  # noqa: E402

from systop.core.ports import _resolve  # noqa: E402


def test_resolve_preserves_ipv6_zone_id():
    """`fe80::1%en0` dagi zona SAQLANISHI shart.

    Zonasiz link-local manzilga ulanib bo'lmaydi — natijada har bir
    link-local port "YOPIQ" deb ko'rsatilardi.
    """
    addr, fam = asyncio.run(_resolve("fe80::1%lo0", "ipv6"))
    if addr is None:  # ba'zi CI muhitida link-local resolve bo'lmaydi
        return
    assert "%" in addr, addr
    assert fam == "ipv6"


def test_resolve_rejects_ipv4_mapped_when_ipv6_requested():
    """`-6` bilan `::ffff:1.2.3.4` QABUL QILINMASLIGI kerak.

    IPv4-mapped manzil IPv6 emas — trafik IPv4 ustidan ketadi. Uni qabul
    qilish `scan -6` ni jimgina IPv4'da ishlatardi.
    """

    async def fake_getaddrinfo(*_a, **_kw):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:1.2.3.4", 0, 0, 0))]

    loop = asyncio.new_event_loop()
    try:
        loop.getaddrinfo = fake_getaddrinfo  # type: ignore[method-assign]
        addr, fam = loop.run_until_complete(_resolve("example.com", "ipv6"))
    finally:
        loop.close()
    assert addr is None
    assert fam is None


def test_resolve_accepts_ipv4_mapped_in_auto_mode():
    """`auto` rejimida OS tanlovi hurmat qilinadi — faqat `-6` qat'iy."""

    async def fake_getaddrinfo(*_a, **_kw):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:1.2.3.4", 0, 0, 0))]

    loop = asyncio.new_event_loop()
    try:
        loop.getaddrinfo = fake_getaddrinfo  # type: ignore[method-assign]
        addr, _ = loop.run_until_complete(_resolve("example.com", "auto"))
    finally:
        loop.close()
    assert addr == "::ffff:1.2.3.4"
