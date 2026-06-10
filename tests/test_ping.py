"""ping testlari — OFFLINE.

``build_targets`` barcha shoxlari, ``PingResult.loss_pct``, ``_to_result``
(soxta host obyekti bilan), ``ping_once``/``ping_many`` (icmplib mock bilan).
Hech qanday ICMP soketi ochilmaydi.
"""

from __future__ import annotations

import pytest
from conftest import FakeHost

from systop.core import ping
from systop.core.ping import (
    DEFAULT_GLOBAL_TARGETS,
    DEFAULT_GLOBAL_TARGETS_V6,
    PingResult,
    _to_result,
    build_targets,
    ping_many,
    ping_once,
)

# --- build_targets ----------------------------------------------------------


def test_build_targets_gateway_plus_global():
    targets = build_targets("192.168.1.1")
    assert targets["Gateway (lokal)"] == "192.168.1.1"
    assert "Cloudflare" in targets
    assert len(targets) == len(DEFAULT_GLOBAL_TARGETS) + 1


def test_build_targets_gateway_only():
    targets = build_targets("192.168.1.1", include_global=False)
    assert targets == {"Gateway (lokal)": "192.168.1.1"}


def test_build_targets_global_only():
    targets = build_targets(None, include_global=True)
    assert "Gateway (lokal)" not in targets
    assert targets == DEFAULT_GLOBAL_TARGETS
    # Asl konstanta o'zgarmasligi kerak (nusxa qaytarish).
    assert targets is not DEFAULT_GLOBAL_TARGETS


def test_build_targets_empty():
    assert build_targets(None, include_global=False) == {}


def test_build_targets_does_not_mutate_default_constant():
    """build_targets DEFAULT_GLOBAL_TARGETS'ni o'zgartirmasligini tasdiqlash."""
    before = dict(DEFAULT_GLOBAL_TARGETS)
    t = build_targets("10.0.0.1")
    t["yangi"] = "1.2.3.4"
    assert DEFAULT_GLOBAL_TARGETS == before


# --- PingResult.loss_pct ----------------------------------------------------


@pytest.mark.parametrize(
    "loss, pct",
    [(0.0, 0.0), (0.25, 25.0), (0.5, 50.0), (1.0, 100.0)],
)
def test_loss_pct(loss, pct):
    r = PingResult(label="x", address="1.1.1.1", packet_loss=loss)
    assert r.loss_pct == pytest.approx(pct)


def test_ping_result_defaults():
    r = PingResult(label="x", address="1.1.1.1")
    assert r.alive is False
    assert r.packet_loss == 1.0
    assert r.loss_pct == 100.0
    assert r.rtts == []


# --- _to_result -------------------------------------------------------------


def test_to_result_maps_host_fields():
    host = FakeHost(
        address="8.8.8.8",
        is_alive=True,
        min_rtt=1.0,
        avg_rtt=2.0,
        max_rtt=3.0,
        jitter=0.5,
        packet_loss=0.0,
        rtts=[1.0, 2.0, 3.0],
    )
    r = _to_result(host, "Google DNS")
    assert r.label == "Google DNS"
    assert r.address == "8.8.8.8"
    assert r.alive is True
    assert (r.min_rtt, r.avg_rtt, r.max_rtt) == (1.0, 2.0, 3.0)
    assert r.jitter == 0.5
    assert r.packet_loss == 0.0
    assert r.rtts == [1.0, 2.0, 3.0]


def test_to_result_copies_rtts_list():
    """_to_result host.rtts'ni nusxalashi kerak (alias bo'lmasligi uchun)."""
    original = [1.0, 2.0]
    host = FakeHost(address="1.1.1.1", is_alive=True, rtts=original)
    r = _to_result(host, "x")
    r.rtts.append(99.0)
    assert original == [1.0, 2.0]  # asl ro'yxat o'zgarmadi


def test_to_result_dead_host():
    host = FakeHost(address="10.0.0.99", is_alive=False, packet_loss=1.0)
    r = _to_result(host, "o'lik")
    assert r.alive is False
    assert r.loss_pct == 100.0


# --- ping_once / ping_many (icmplib mock) -----------------------------------


async def test_ping_once_uses_label(monkeypatch):
    async def fake_async_ping(address, **kwargs):
        return FakeHost(address=address, is_alive=True, avg_rtt=5.0, packet_loss=0.0)

    monkeypatch.setattr(ping, "async_ping", fake_async_ping)
    r = await ping_once("8.8.8.8", label="Google")
    assert r.label == "Google"
    assert r.address == "8.8.8.8"
    assert r.alive is True
    assert r.avg_rtt == 5.0


async def test_ping_once_label_defaults_to_address(monkeypatch):
    async def fake_async_ping(address, **kwargs):
        return FakeHost(address=address, is_alive=True)

    monkeypatch.setattr(ping, "async_ping", fake_async_ping)
    r = await ping_once("1.1.1.1")
    assert r.label == "1.1.1.1"


async def test_ping_once_passes_privileged_false(monkeypatch):
    """privileged=False uzatilishini tasdiqlash (root talab qilmaslik uchun)."""
    captured = {}

    async def fake_async_ping(address, **kwargs):
        captured.update(kwargs)
        return FakeHost(address=address, is_alive=True)

    monkeypatch.setattr(ping, "async_ping", fake_async_ping)
    await ping_once("1.1.1.1")
    assert captured["privileged"] is False


async def test_ping_many_preserves_label_order(monkeypatch):
    targets = {"Gateway": "192.168.1.1", "Google": "8.8.8.8", "CF": "1.1.1.1"}

    async def fake_multiping(addresses, **kwargs):
        # icmplib kirish tartibida qaytaradi -> zip(strict) bilan moslanadi.
        return [FakeHost(address=a, is_alive=True, avg_rtt=1.0) for a in addresses]

    monkeypatch.setattr(ping, "async_multiping", fake_multiping)
    results = await ping_many(targets)
    assert [r.label for r in results] == ["Gateway", "Google", "CF"]
    assert [r.address for r in results] == ["192.168.1.1", "8.8.8.8", "1.1.1.1"]


async def test_ping_many_empty_targets(monkeypatch):
    captured = {}

    async def fake_multiping(addresses, **kwargs):
        captured["addresses"] = addresses
        return []

    monkeypatch.setattr(ping, "async_multiping", fake_multiping)
    results = await ping_many({})
    assert results == []
    assert captured["addresses"] == []


# --- Windows shoxi: _win_ping / _win_result / platforma branching -----------

# Real `ping -n 4 8.8.8.8` chiqishi (en-US).
_WIN_PING_OUT = (
    "Pinging 8.8.8.8 with 32 bytes of data:\n"
    "Reply from 8.8.8.8: bytes=32 time=12ms TTL=117\n"
    "Reply from 8.8.8.8: bytes=32 time=10ms TTL=117\n"
    "Reply from 8.8.8.8: bytes=32 time=14ms TTL=117\n"
    "Reply from 8.8.8.8: bytes=32 time=12ms TTL=117\n"
    "\n"
    "Ping statistics for 8.8.8.8:\n"
    "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n"
)

_WIN_PING_DEAD_OUT = (
    "Pinging 10.255.255.1 with 32 bytes of data:\n"
    "Request timed out.\n"
    "Request timed out.\n"
    "\n"
    "Ping statistics for 10.255.255.1:\n"
    "    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),\n"
)


def _force_windows(monkeypatch, ping_output: str):
    """Platformani Windows qilib, ping.exe PARSE yo'lini sinash uchun sozlaydi.

    IcmpSendEcho'ni o'chiramiz (None) — shunda bu testlar deterministik ravishda
    `ping.exe` + parse zaxira yo'lini sinaydi (real Windows'da ham, macOS'da ham).
    """
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)
    monkeypatch.setattr(ping._platform, "win_icmp_ping", lambda *a, **k: None)

    async def fake_run_command(cmd, timeout):
        # Buyruq haqiqatan tizim `ping` ekanini tasdiqlaymiz.
        assert cmd[0] == "ping"
        return ping_output

    monkeypatch.setattr(ping._platform, "run_command", fake_run_command)


async def test_win_ping_parses_alive(monkeypatch):
    _force_windows(monkeypatch, _WIN_PING_OUT)
    alive, rtts, loss = await ping._win_ping("8.8.8.8", count=4, timeout=2.0)
    assert alive is True
    assert rtts == [12.0, 10.0, 14.0, 12.0]
    assert loss == 0.0


async def test_win_ping_dead_host(monkeypatch):
    _force_windows(monkeypatch, _WIN_PING_DEAD_OUT)
    alive, rtts, loss = await ping._win_ping("10.255.255.1", count=2, timeout=1.0)
    assert alive is False
    assert rtts == []
    assert loss == 1.0


async def test_win_ping_empty_output_returns_dead(monkeypatch):
    _force_windows(monkeypatch, "")
    alive, rtts, loss = await ping._win_ping("1.1.1.1", count=4, timeout=1.0)
    assert alive is False
    assert rtts == []
    assert loss == 1.0


async def test_win_ping_ipv6_adds_dash6(monkeypatch):
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)
    captured = {}

    async def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        return _WIN_PING_OUT.replace("8.8.8.8", "2001:4860:4860::8888")

    monkeypatch.setattr(ping._platform, "run_command", fake_run_command)
    await ping._win_ping("2001:4860:4860::8888", count=1, timeout=1.0)
    assert "-6" in captured["cmd"]


async def test_win_result_computes_stats():
    r = ping._win_result("Google", "8.8.8.8", alive=True, rtts=[10.0, 20.0, 30.0], loss=0.0)
    assert r.label == "Google"
    assert r.address == "8.8.8.8"
    assert r.alive is True
    assert r.min_rtt == 10.0
    assert r.avg_rtt == pytest.approx(20.0)
    assert r.max_rtt == 30.0
    assert r.packet_loss == 0.0
    assert r.rtts == [10.0, 20.0, 30.0]


async def test_win_result_no_rtts_keeps_loss():
    r = ping._win_result("dead", "10.0.0.99", alive=False, rtts=[], loss=1.0)
    assert r.alive is False
    assert r.packet_loss == 1.0
    assert r.avg_rtt == 0.0
    assert r.rtts == []


async def test_ping_once_windows_branch(monkeypatch):
    """ping_once Windows'da icmplib EMAS, _win_ping ishlatishini tasdiqlash."""
    _force_windows(monkeypatch, _WIN_PING_OUT)

    async def boom(*a, **k):
        raise AssertionError("icmplib async_ping Windows'da chaqirilmasligi kerak")

    monkeypatch.setattr(ping, "async_ping", boom)
    r = await ping_once("8.8.8.8", label="Google")
    assert r.label == "Google"
    assert r.alive is True
    assert r.avg_rtt == pytest.approx(12.0)


async def test_ping_many_windows_parallel(monkeypatch):
    """ping_many Windows'da har nishonni alohida `ping` bilan parallel ishlaydi."""
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)
    # ping.exe parse yo'lini deterministik sinash uchun IcmpSendEcho'ni o'chiramiz.
    monkeypatch.setattr(ping._platform, "win_icmp_ping", lambda *a, **k: None)

    async def boom(*a, **k):
        raise AssertionError("icmplib async_multiping Windows'da chaqirilmasligi kerak")

    monkeypatch.setattr(ping, "async_multiping", boom)

    async def fake_run_command(cmd, timeout):
        # Manzil cmd oxirida; uni chiqishga joylab, har nishon alive bo'lsin.
        addr = cmd[-1]
        return _WIN_PING_OUT.replace("8.8.8.8", addr)

    monkeypatch.setattr(ping._platform, "run_command", fake_run_command)

    targets = {"Gateway": "192.168.1.1", "Google": "8.8.8.8", "CF": "1.1.1.1"}
    results = await ping_many(targets)
    # Label tartibi saqlanishi kerak.
    assert [r.label for r in results] == ["Gateway", "Google", "CF"]
    assert [r.address for r in results] == ["192.168.1.1", "8.8.8.8", "1.1.1.1"]
    assert all(r.alive for r in results)


async def test_ping_many_windows_empty(monkeypatch):
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)
    results = await ping_many({})
    assert results == []


# --- Windows ILDIZ yo'l: IcmpSendEcho (_platform.win_icmp_ping) --------------


async def test_win_ping_uses_icmpsendecho_when_available(monkeypatch):
    """IPv4 nishon uchun _win_ping IcmpSendEcho'ni (run_command EMAS) ishlatadi."""
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)

    # win_icmp_ping mavjud natija qaytaradi -> ping.exe chaqirilmasligi kerak.
    def fake_icmp(address, count, timeout):
        assert address == "8.8.8.8"
        assert count == 4
        return True, [84.0, 85.0, 83.0, 84.0], 0.0

    monkeypatch.setattr(ping._platform, "win_icmp_ping", fake_icmp)

    async def boom(cmd, timeout):
        raise AssertionError("IcmpSendEcho mavjud bo'lsa ping.exe chaqirilmasligi kerak")

    monkeypatch.setattr(ping._platform, "run_command", boom)

    alive, rtts, loss = await ping._win_ping("8.8.8.8", count=4, timeout=2.0)
    assert alive is True
    assert rtts == [84.0, 85.0, 83.0, 84.0]
    assert loss == 0.0


async def test_win_ping_falls_back_to_parse_when_icmp_none(monkeypatch):
    """IcmpSendEcho None (DLL yo'q/resolve yo'q) -> ping.exe parse zaxirasi."""
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)
    monkeypatch.setattr(ping._platform, "win_icmp_ping", lambda *a, **k: None)

    async def fake_run_command(cmd, timeout):
        assert cmd[0] == "ping"
        return _WIN_PING_OUT

    monkeypatch.setattr(ping._platform, "run_command", fake_run_command)
    alive, rtts, loss = await ping._win_ping("8.8.8.8", count=4, timeout=2.0)
    assert alive is True
    assert rtts == [12.0, 10.0, 14.0, 12.0]
    assert loss == 0.0


async def test_win_ping_ipv6_skips_icmpsendecho(monkeypatch):
    """IPv6 nishon IcmpSendEcho (IPv4-only) ni o'tkazib, ping.exe -6 ga tushadi."""
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)

    def boom(*a, **k):
        raise AssertionError("IPv6 uchun win_icmp_ping (IPv4) chaqirilmasligi kerak")

    monkeypatch.setattr(ping._platform, "win_icmp_ping", boom)

    captured = {}

    async def fake_run_command(cmd, timeout):
        captured["cmd"] = cmd
        return _WIN_PING_OUT.replace("8.8.8.8", "2001:4860:4860::8888")

    monkeypatch.setattr(ping._platform, "run_command", fake_run_command)
    await ping._win_ping("2001:4860:4860::8888", count=1, timeout=1.0)
    assert "-6" in captured["cmd"]


async def test_ping_once_windows_icmpsendecho_branch(monkeypatch):
    """ping_once Windows'da IcmpSendEcho natijasidan PingResult yig'adi."""
    monkeypatch.setattr(ping._platform, "IS_WINDOWS", True)
    monkeypatch.setattr(
        ping._platform, "win_icmp_ping", lambda *a, **k: (True, [10.0, 20.0, 30.0], 0.0)
    )

    async def boom(*a, **k):
        raise AssertionError("icmplib async_ping Windows'da chaqirilmasligi kerak")

    monkeypatch.setattr(ping, "async_ping", boom)
    r = await ping_once("8.8.8.8", label="Google")
    assert r.label == "Google"
    assert r.alive is True
    assert r.min_rtt == 10.0
    assert r.avg_rtt == pytest.approx(20.0)
    assert r.max_rtt == 30.0


# --- konstantalar -----------------------------------------------------------


def test_default_targets_are_valid_ipv4():
    import ipaddress

    for addr in DEFAULT_GLOBAL_TARGETS.values():
        ipaddress.IPv4Address(addr)  # noto'g'ri bo'lsa ValueError


def test_default_targets_v6_are_valid_ipv6():
    import ipaddress

    for addr in DEFAULT_GLOBAL_TARGETS_V6.values():
        ipaddress.IPv6Address(addr)
