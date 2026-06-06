"""topology testlari — OFFLINE.

``_ARP_RE`` / ``_NEIGH_RE`` regexlari real-dunyo qatorlari bilan, ``_parse_arp_table``
``subprocess`` monkeypatch bilan, ``discover_lan`` esa ``async_multiping`` mock
qilinib sinaladi. Hech qanday tarmoq chaqiruvi bo'lmaydi.
"""

from __future__ import annotations

import pytest
from conftest import FakeCompletedProcess, FakeHost, FakeRawHop

from systop.core import topology
from systop.core.topology import (
    _ARP_RE,
    _ARP_WIN_RE,
    _NEIGH_RE,
    Hop,
    HopStat,
    LanHost,
    _parse_arp_table,
    discover_lan,
    trace_path,
    trace_stream,
    traceroute,
)

# --- _ARP_RE: macOS / BSD `arp -a` ------------------------------------------


@pytest.mark.parametrize(
    "line, ip, mac",
    [
        (
            "? (192.168.1.1) at a4:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]",
            "192.168.1.1",
            "a4:b1:c2:d3:e4:f5",
        ),
        (
            "router.lan (10.0.0.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]",
            "10.0.0.1",
            "0:11:22:33:44:55",
        ),
        (
            "? (192.168.0.254) at ff:ee:dd:cc:bb:aa on en1 [ethernet]",
            "192.168.0.254",
            "ff:ee:dd:cc:bb:aa",
        ),
    ],
)
def test_arp_re_macos_lines(line, ip, mac):
    m = _ARP_RE.search(line)
    assert m is not None
    assert m.group(1) == ip
    assert m.group(2) == mac


def test_arp_re_linux_arp_n():
    # Linux `arp -n` chiqishi ham qavs ichidagi IP bermaydi -> _ARP_RE mos kelmaydi.
    # Lekin `arp -a` Linux'da: "host (10.0.0.5) at 11:22:33:44:55:66 [ether] on eth0"
    line = "? (10.0.0.5) at 11:22:33:44:55:66 [ether] on eth0"
    m = _ARP_RE.search(line)
    assert m is not None
    assert m.group(1) == "10.0.0.5"
    assert m.group(2) == "11:22:33:44:55:66"


def test_arp_re_incomplete_entry_no_match():
    # `arp -a` da javob bermagan host: MAC o'rnida "(incomplete)".
    line = "? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]"
    assert _ARP_RE.search(line) is None


# --- _NEIGH_RE: Linux `ip neigh` --------------------------------------------


@pytest.mark.parametrize(
    "line, ip, mac",
    [
        (
            "192.168.1.1 dev eth0 lladdr a4:b1:c2:d3:e4:f5 REACHABLE",
            "192.168.1.1",
            "a4:b1:c2:d3:e4:f5",
        ),
        ("10.0.0.5 dev wlan0 lladdr 11:22:33:44:55:66 STALE", "10.0.0.5", "11:22:33:44:55:66"),
        ("172.16.0.9 dev eth1 lladdr aa:bb:cc:dd:ee:ff DELAY", "172.16.0.9", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_neigh_re_states(line, ip, mac):
    m = _NEIGH_RE.search(line)
    assert m is not None
    assert m.group(1) == ip
    assert m.group(2) == mac


def test_neigh_re_failed_or_incomplete_no_match():
    # lladdr bo'lmagan yozuvlar (FAILED / INCOMPLETE) mos kelmasligi kerak.
    assert _NEIGH_RE.search("192.168.1.50 dev eth0  FAILED") is None
    assert _NEIGH_RE.search("192.168.1.51 dev eth0  INCOMPLETE") is None


# --- _parse_arp_table: subprocess monkeypatch -------------------------------


def test_parse_arp_table_macos(monkeypatch):
    arp_out = (
        "? (192.168.1.1) at a4:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]\n"
        "? (192.168.1.42) at AA:BB:CC:DD:EE:FF on en0 ifscope [ethernet]\n"
        "? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]\n"
    )

    def fake_run(cmd, **kwargs):
        if cmd[:1] == ["arp"]:
            return FakeCompletedProcess(stdout=arp_out)
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    table = _parse_arp_table()
    assert table == {
        "192.168.1.1": "a4:b1:c2:d3:e4:f5",
        # MAC lowercase ga keltiriladi.
        "192.168.1.42": "aa:bb:cc:dd:ee:ff",
    }
    assert "192.168.1.99" not in table  # incomplete o'tkazib yuboriladi


def test_parse_arp_table_falls_back_to_ip_neigh(monkeypatch):
    neigh_out = (
        "192.168.1.1 dev eth0 lladdr a4:b1:c2:d3:e4:f5 REACHABLE\n"
        "192.168.1.7 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
        "192.168.1.250 dev eth0  FAILED\n"
    )

    def fake_run(cmd, **kwargs):
        if cmd[:1] == ["arp"]:
            # arp mavjud emas / bo'sh chiqish -> ip neigh ga o'tadi.
            return FakeCompletedProcess(stdout="")
        if cmd[:2] == ["ip", "neigh"]:
            return FakeCompletedProcess(stdout=neigh_out)
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    table = _parse_arp_table()
    assert table == {
        "192.168.1.1": "a4:b1:c2:d3:e4:f5",
        "192.168.1.7": "11:22:33:44:55:66",
    }


def test_parse_arp_table_arp_missing_raises_oserror(monkeypatch):
    """`arp` buyrug'i topilmasa (OSError) -> `ip neigh` ga o'tishi kerak."""
    neigh_out = "192.168.1.1 dev eth0 lladdr a4:b1:c2:d3:e4:f5 REACHABLE\n"

    def fake_run(cmd, **kwargs):
        if cmd[:1] == ["arp"]:
            raise FileNotFoundError("arp not found")
        return FakeCompletedProcess(stdout=neigh_out)

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    table = _parse_arp_table()
    assert table == {"192.168.1.1": "a4:b1:c2:d3:e4:f5"}


def test_parse_arp_table_both_fail_returns_empty(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise OSError("no such command")

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    assert _parse_arp_table() == {}


# --- discover_lan: async_multiping + ARP birlashtirish ----------------------


async def test_discover_lan_merges_ping_and_arp(monkeypatch):
    """Tirik hostlar ping'dan, MAC esa ARP jadvalidan kelishi kerak."""
    cidr = "192.168.1.0/30"  # hostlar: .1, .2

    async def fake_multiping(hosts, **kwargs):
        return [
            FakeHost(address="192.168.1.1", is_alive=True, avg_rtt=1.5),
            FakeHost(address="192.168.1.2", is_alive=False),
        ]

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: "192.168.1.1")

    hosts = await discover_lan(cidr=cidr)
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "192.168.1.1"
    assert h.mac == "aa:bb:cc:dd:ee:ff"
    assert h.rtt_ms == 1.5
    assert h.is_gateway is True


async def test_discover_lan_adds_arp_only_hosts(monkeypatch):
    """ARP'da bor, lekin ping'ga javob bermagan host ham qo'shilishi kerak."""
    cidr = "192.168.1.0/24"

    async def fake_multiping(hosts, **kwargs):
        return [FakeHost(address="192.168.1.10", is_alive=True, avg_rtt=2.0)]

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(
        topology,
        "_parse_arp_table",
        lambda: {
            "192.168.1.10": "aa:aa:aa:aa:aa:aa",
            "192.168.1.20": "bb:bb:bb:bb:bb:bb",  # faqat ARP'da
            "10.9.9.9": "cc:cc:cc:cc:cc:cc",  # tarmoqdan tashqarida -> tashlanadi
        },
    )
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: None)

    hosts = await discover_lan(cidr=cidr)
    ips = [h.ip for h in hosts]
    assert ips == ["192.168.1.10", "192.168.1.20"]  # IP bo'yicha tartiblangan
    # Tarmoqdan tashqaridagi ARP yozuvi qo'shilmaydi.
    assert "10.9.9.9" not in ips


async def test_discover_lan_sorts_by_ip(monkeypatch):
    cidr = "192.168.1.0/24"

    async def fake_multiping(hosts, **kwargs):
        return [
            FakeHost(address="192.168.1.100", is_alive=True),
            FakeHost(address="192.168.1.2", is_alive=True),
            FakeHost(address="192.168.1.50", is_alive=True),
        ]

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {})
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: None)

    hosts = await discover_lan(cidr=cidr)
    ips = [h.ip for h in hosts]
    # Leksikografik emas, sonli (ip_address) tartibda bo'lishi kerak.
    assert ips == ["192.168.1.2", "192.168.1.50", "192.168.1.100"]


async def test_discover_lan_marks_gateway(monkeypatch):
    cidr = "10.0.0.0/24"

    async def fake_multiping(hosts, **kwargs):
        return [
            FakeHost(address="10.0.0.1", is_alive=True),
            FakeHost(address="10.0.0.2", is_alive=True),
        ]

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {})
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: "10.0.0.1")

    hosts = await discover_lan(cidr=cidr)
    by_ip = {h.ip: h for h in hosts}
    assert by_ip["10.0.0.1"].is_gateway is True
    assert by_ip["10.0.0.2"].is_gateway is False


async def test_discover_lan_no_cidr_no_interface_returns_empty(monkeypatch):
    monkeypatch.setattr(topology.netinfo, "primary_interface", lambda: None)
    result = await discover_lan(cidr=None)
    assert result == []


async def test_discover_lan_uses_primary_interface_cidr(monkeypatch):
    from systop.core.netinfo import Interface

    iface = Interface(name="en0", ipv4="192.168.5.10", netmask="255.255.255.0")
    monkeypatch.setattr(topology.netinfo, "primary_interface", lambda: iface)
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: None)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {})

    captured = {}

    async def fake_multiping(hosts, **kwargs):
        captured["hosts"] = hosts
        return []

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    await discover_lan(cidr=None)
    # primary_interface CIDR'idan hostlar yaratilgan bo'lishi kerak.
    assert "192.168.5.1" in captured["hosts"]
    assert "192.168.5.254" in captured["hosts"]


async def test_discover_lan_respects_max_hosts(monkeypatch):
    cidr = "10.0.0.0/24"  # 254 host, lekin max_hosts=5 cheklaydi

    captured = {}

    async def fake_multiping(hosts, **kwargs):
        captured["count"] = len(hosts)
        return []

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {})
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: None)

    await discover_lan(cidr=cidr, max_hosts=5)
    assert captured["count"] == 5


async def test_discover_lan_slash31_no_usable_hosts(monkeypatch):
    """/31 tarmoq -> ``network.hosts()`` ikkita manzilni beradi (RFC 3021).

    ``ipaddress`` /31 va /32 ni maxsus ishlaydi: /31 ikkala manzilni host deb
    qaytaradi, shuning uchun multiping CHAQIRILADI. Bu xatti-harakatni hujjatlaymiz.
    """
    captured = {}

    async def fake_multiping(hosts, **kwargs):
        captured["hosts"] = list(hosts)
        return []

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {})
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: None)

    result = await discover_lan(cidr="192.168.1.4/31")
    assert result == []
    # /31 -> .4 va .5 host sifatida qaytariladi.
    assert captured["hosts"] == ["192.168.1.4", "192.168.1.5"]


# --- traceroute: sync icmplib mock ------------------------------------------


async def test_traceroute_maps_hops(monkeypatch):
    raw = [
        FakeRawHop(distance=1, address="192.168.1.1", avg_rtt=1.2, is_alive=True),
        FakeRawHop(distance=2, address="10.0.0.1", avg_rtt=5.5, is_alive=True),
        FakeRawHop(distance=3, address="8.8.8.8", avg_rtt=12.0, is_alive=True),
    ]

    def fake_sync_traceroute(address, **kwargs):
        return raw

    monkeypatch.setattr(topology, "_sync_traceroute", fake_sync_traceroute)

    async def fake_reverse(addr, timeout=1.0):
        return f"host-{addr}"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)

    hops = await traceroute("8.8.8.8", resolve=True)
    assert [h.index for h in hops] == [1, 2, 3]
    assert hops[0].address == "192.168.1.1"
    assert hops[0].rtt_ms == 1.2
    assert hops[0].alive is True
    assert hops[2].hostname == "host-8.8.8.8"


async def test_traceroute_skips_dns_when_resolve_false(monkeypatch):
    raw = [FakeRawHop(distance=1, address="192.168.1.1", avg_rtt=1.0, is_alive=True)]
    monkeypatch.setattr(topology, "_sync_traceroute", lambda address, **k: raw)

    called = {"dns": False}

    async def fake_reverse(addr, timeout=1.0):
        called["dns"] = True
        return "should-not-be-called"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)
    hops = await traceroute("8.8.8.8", resolve=False)
    assert hops[0].hostname is None
    assert called["dns"] is False


async def test_traceroute_handles_missing_hop_address(monkeypatch):
    """Hop manzili None bo'lsa (* * *), reverse DNS chaqirilmaydi va xato bo'lmaydi."""
    raw = [FakeRawHop(distance=1, address=None, avg_rtt=0.0, is_alive=False)]
    monkeypatch.setattr(topology, "_sync_traceroute", lambda address, **k: raw)

    called = {"dns": False}

    async def fake_reverse(addr, timeout=1.0):
        called["dns"] = True
        return None

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)
    hops = await traceroute("8.8.8.8", resolve=True)
    assert hops[0].address is None
    assert hops[0].hostname is None
    assert called["dns"] is False


# --- Windows: _ARP_WIN_RE ---------------------------------------------------


@pytest.mark.parametrize(
    "line, ip, mac",
    [
        ("  192.168.1.1    00-11-22-33-44-55  dynamic", "192.168.1.1", "00-11-22-33-44-55"),
        ("  192.168.1.42   a4-b1-c2-d3-e4-f5  dynamic", "192.168.1.42", "a4-b1-c2-d3-e4-f5"),
        ("  10.0.0.254     ff-ee-dd-cc-bb-aa  static", "10.0.0.254", "ff-ee-dd-cc-bb-aa"),
    ],
)
def test_arp_win_re_lines(line, ip, mac):
    m = _ARP_WIN_RE.search(line)
    assert m is not None
    assert m.group(1) == ip
    assert m.group(2) == mac


def test_arp_win_re_header_no_match():
    # Sarlavha qatori mos kelmasligi kerak.
    assert _ARP_WIN_RE.search("  Internet Address      Physical Address      Type") is None


def test_arp_win_re_interface_line_no_match():
    # "Interface: 192.168.1.50 --- 0xN" qatori — MAC yo'q, mos kelmaydi.
    assert _ARP_WIN_RE.search("Interface: 192.168.1.50 --- 0xc") is None


# --- Windows: _parse_arp_table ----------------------------------------------

_WIN_ARP_OUT = (
    "\n"
    "Interface: 192.168.1.50 --- 0xc\n"
    "  Internet Address      Physical Address      Type\n"
    "  192.168.1.1           00-11-22-33-44-55     dynamic\n"
    "  192.168.1.42          A4-B1-C2-D3-E4-F5     dynamic\n"
    "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
    "  224.0.0.22            01-00-5e-00-00-16     static\n"
)


def test_parse_arp_table_windows(monkeypatch):
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    def fake_run(cmd, **kwargs):
        assert cmd == ["arp", "-a"]
        return FakeCompletedProcess(stdout=_WIN_ARP_OUT)

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    table = _parse_arp_table()
    # MAC tiredan ':' ga, kichik harfga normallashtiriladi.
    assert table["192.168.1.1"] == "00:11:22:33:44:55"
    assert table["192.168.1.42"] == "a4:b1:c2:d3:e4:f5"
    # Broadcast/multicast yozuvlar ham regex'ga tushadi (filtrlash discover_lan'da
    # tarmoq a'zoligi bo'yicha bo'ladi) — lekin sarlavha tushmaydi.
    assert "Physical" not in table


def test_parse_arp_table_windows_command_missing(monkeypatch):
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("arp not found")

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    assert _parse_arp_table() == {}


def test_win_arp_mac_lookup_vendor_accepts_dash():
    """oui.lookup_vendor tire-formatli MAC'ni ham qabul qilishini tasdiqlash."""
    from systop.core import oui

    # Apple OUI (jadvalda bor deb hisoblamaymiz — normalize ikkala formatda bir xil).
    colon = oui.normalize_oui("a4:b1:c2:d3:e4:f5")
    dashed = oui.normalize_oui("a4-b1-c2-d3-e4-f5")
    assert colon == dashed


# --- Windows: _win_traceroute + trace_path branch ---------------------------

_WIN_TRACERT_OUT = (
    "\n"
    "Tracing route to 8.8.8.8 over a maximum of 30 hops\n"
    "\n"
    "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
    "  2     8 ms     9 ms     7 ms  10.0.0.1\n"
    "  3     *        *        *     Request timed out.\n"
    "  4    12 ms    11 ms    13 ms  8.8.8.8\n"
    "\n"
    "Trace complete.\n"
)


async def test_win_traceroute_maps_hops(monkeypatch):
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    async def fake_run_command(cmd, timeout):
        assert cmd[0] == "tracert"
        assert "-d" in cmd  # raqamli (resolve'siz) rejim
        return _WIN_TRACERT_OUT

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)

    raw = await topology._win_traceroute("8.8.8.8")
    assert [h.distance for h in raw] == [1, 2, 3, 4]
    assert raw[0].address == "192.168.1.1"
    assert raw[0].avg_rtt == pytest.approx(1.0)
    assert raw[0].is_alive is True
    assert raw[2].address is None  # timeout hop
    assert raw[2].is_alive is False


async def test_traceroute_windows_branch(monkeypatch):
    """traceroute() Windows'da icmplib EMAS, tracert ishlatishini tasdiqlash."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    def boom(*a, **k):
        raise AssertionError("icmplib traceroute Windows'da chaqirilmasligi kerak")

    monkeypatch.setattr(topology, "_sync_traceroute", boom)

    async def fake_run_command(cmd, timeout):
        return _WIN_TRACERT_OUT

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)

    async def fake_reverse(addr, timeout=1.0):
        return f"host-{addr}"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)

    hops = await traceroute("8.8.8.8", resolve=True)
    assert [h.index for h in hops] == [1, 2, 3, 4]
    assert hops[0].address == "192.168.1.1"
    assert hops[0].hostname == "host-192.168.1.1"
    # timeout hop'da reverse DNS chaqirilmaydi.
    assert hops[2].address is None
    assert hops[2].hostname is None


async def test_trace_path_windows_empty_sets_error(monkeypatch):
    """Windows tracert bo'sh chiqsa -> TraceResult.error to'ldiriladi (o'zbekcha)."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    async def fake_run_command(cmd, timeout):
        return ""  # buyruq yo'q / timeout

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)
    result = await trace_path("8.8.8.8", resolve=False)
    assert result.hops == []
    assert result.error is not None


async def test_trace_stream_windows_branch(monkeypatch):
    """trace_stream Windows'da _win_traceroute orqali probe qilishini tasdiqlash."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    def boom(*a, **k):
        raise AssertionError("icmplib Windows'da chaqirilmasligi kerak")

    monkeypatch.setattr(topology, "_sync_traceroute", boom)

    async def fake_run_command(cmd, timeout):
        return (
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n  2    10 ms    10 ms    10 ms  8.8.8.8\n"
        )

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)

    snapshots = []
    async for stats in trace_stream("8.8.8.8", cycles=2, interval=0.0, resolve=False):
        snapshots.append([(s.index, s.sent, s.recv) for s in stats])
    assert snapshots[0] == [(1, 1, 1), (2, 1, 1)]
    assert snapshots[1] == [(1, 2, 2), (2, 2, 2)]


# --- Windows: discover_lan sweep --------------------------------------------


async def test_discover_lan_windows_uses_win_sweep(monkeypatch):
    """Windows'da discover_lan async_multiping EMAS, `ping` sweep ishlatadi."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)
    cidr = "192.168.1.0/30"  # hostlar: .1, .2

    async def boom(*a, **k):
        raise AssertionError("async_multiping Windows'da chaqirilmasligi kerak")

    monkeypatch.setattr(topology, "async_multiping", boom)

    # `ping` sweep: faqat .1 javob beradi.
    async def fake_run_command(cmd, timeout):
        addr = cmd[-1]
        if addr == "192.168.1.1":
            return (
                f"Reply from {addr}: bytes=32 time=2ms TTL=64\n"
                "    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\n"
            )
        return "Request timed out.\n    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),\n"

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)
    monkeypatch.setattr(topology, "_parse_arp_table", lambda: {"192.168.1.1": "aa:bb:cc:dd:ee:ff"})
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: "192.168.1.1")

    hosts = await discover_lan(cidr=cidr)
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "192.168.1.1"
    assert h.mac == "aa:bb:cc:dd:ee:ff"
    assert h.is_gateway is True
    assert h.rtt_ms == pytest.approx(2.0)


# --- dataclass defaultlari --------------------------------------------------


def test_hop_defaults():
    h = Hop(index=1, address="1.1.1.1")
    assert h.hostname is None
    assert h.rtt_ms == 0.0
    assert h.alive is False


def test_lanhost_defaults():
    h = LanHost(ip="192.168.1.1")
    assert h.mac is None
    assert h.is_gateway is False
    assert h.rtt_ms == 0.0
    assert h.vendor is None


# --- HopStat: update() / loss_pct matematikasi ------------------------------


def test_hopstat_loss_pct_no_probes():
    # Hech narsa yuborilmagan -> 0% (0/0 division'siz).
    assert HopStat(index=1).loss_pct == 0.0


def test_hopstat_update_alive_accumulates_stats():
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=10.0)
    s.update("10.0.0.1", alive=True, rtt=20.0)
    s.update("10.0.0.1", alive=True, rtt=6.0)
    assert s.sent == 3
    assert s.recv == 3
    assert s.address == "10.0.0.1"
    assert s.last_rtt == 6.0
    assert s.avg_rtt == pytest.approx(12.0)  # (10+20+6)/3
    assert s.best_rtt == 6.0
    assert s.worst_rtt == 20.0
    assert s.loss_pct == 0.0


def test_hopstat_update_counts_loss():
    s = HopStat(index=2)
    s.update("10.0.0.2", alive=True, rtt=5.0)
    s.update(None, alive=False, rtt=0.0)  # javobsiz probe
    s.update("10.0.0.2", alive=True, rtt=7.0)
    s.update(None, alive=False, rtt=0.0)
    assert s.sent == 4
    assert s.recv == 2
    assert s.loss_pct == pytest.approx(50.0)
    # Javobsiz probe'lar rtt statistikasiga ta'sir qilmaydi.
    assert s.best_rtt == 5.0
    assert s.worst_rtt == 7.0
    assert s.avg_rtt == pytest.approx(6.0)


def test_hopstat_update_dead_probe_only_increments_sent():
    s = HopStat(index=3)
    s.update(None, alive=False, rtt=0.0)
    assert s.sent == 1
    assert s.recv == 0
    assert s.last_rtt == 0.0
    assert s.avg_rtt == 0.0
    assert s.loss_pct == pytest.approx(100.0)


def test_hopstat_update_zero_rtt_treated_as_no_response():
    """alive=True bo'lsa ham rtt<=0 -> javob hisoblanmaydi (timeout probe)."""
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=0.0)
    assert s.sent == 1
    assert s.recv == 0
    assert s.address == "10.0.0.1"  # manzil baribir yoziladi


def test_hopstat_update_sets_address_once():
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=5.0)
    s.update("10.0.0.99", alive=True, rtt=6.0)  # boshqa manzil — e'tiborsiz
    assert s.address == "10.0.0.1"


def test_hopstat_best_rtt_initial_from_zero():
    """best_rtt boshlang'ich 0.0 — birinchi haqiqiy rtt uni o'rnatishi kerak."""
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=15.0)
    assert s.best_rtt == 15.0  # 0.0 emas


# --- trace_stream: mock _sync_traceroute, cheklangan sikllar ----------------


async def test_trace_stream_two_cycles_accumulates(monkeypatch):
    """Ikki sikl -> sent=2, recv=2 har hop uchun; ro'yxat index bo'yicha tartibli."""
    raw = [
        FakeRawHop(distance=1, address="192.168.1.1", avg_rtt=1.0, is_alive=True),
        FakeRawHop(distance=2, address="8.8.8.8", avg_rtt=10.0, is_alive=True),
    ]
    monkeypatch.setattr(topology, "_sync_traceroute", lambda address, **k: raw)

    async def fake_reverse(addr, timeout=1.0):
        return f"host-{addr}"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)

    snapshots = []
    async for stats in trace_stream("8.8.8.8", cycles=2, interval=0.0, resolve=True):
        snapshots.append([(s.index, s.sent, s.recv, s.hostname) for s in stats])

    assert len(snapshots) == 2
    # Birinchi sikldan keyin har hop 1 marta probe qilingan.
    assert snapshots[0] == [(1, 1, 1, "host-192.168.1.1"), (2, 1, 1, "host-8.8.8.8")]
    # Ikkinchi sikldan keyin jamlanma 2 ga yetadi (statistika to'planadi).
    assert snapshots[1] == [(1, 2, 2, "host-192.168.1.1"), (2, 2, 2, "host-8.8.8.8")]


async def test_trace_stream_resolve_once_per_address(monkeypatch):
    """Reverse DNS faqat birinchi marta ko'rilgan manzil uchun chaqiriladi."""
    raw = [FakeRawHop(distance=1, address="192.168.1.1", avg_rtt=1.0, is_alive=True)]
    monkeypatch.setattr(topology, "_sync_traceroute", lambda address, **k: raw)

    dns_calls = {"n": 0}

    async def fake_reverse(addr, timeout=1.0):
        dns_calls["n"] += 1
        return "router"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)

    async for _ in trace_stream("192.168.1.1", cycles=3, interval=0.0, resolve=True):
        pass
    # 3 sikl bo'lsa ham manzil o'zgarmagani uchun reverse DNS bir marta.
    assert dns_calls["n"] == 1


async def test_trace_stream_no_resolve_skips_dns(monkeypatch):
    raw = [FakeRawHop(distance=1, address="192.168.1.1", avg_rtt=1.0, is_alive=True)]
    monkeypatch.setattr(topology, "_sync_traceroute", lambda address, **k: raw)

    called = {"dns": False}

    async def fake_reverse(addr, timeout=1.0):
        called["dns"] = True
        return "nope"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)

    async for stats in trace_stream("8.8.8.8", cycles=1, interval=0.0, resolve=False):
        assert stats[0].hostname is None
    assert called["dns"] is False


async def test_trace_stream_probe_error_yields_empty(monkeypatch):
    """Probe xato bersa (ICMP/OS) -> bo'sh ro'yxat yield qilinadi, oqim uzilmaydi."""
    from icmplib.exceptions import ICMPLibError

    def boom(address, **kwargs):
        raise ICMPLibError("no socket")

    monkeypatch.setattr(topology, "_sync_traceroute", boom)

    snapshots = []
    async for stats in trace_stream("8.8.8.8", cycles=2, interval=0.0, resolve=False):
        snapshots.append(stats)
    # Ikki sikl ham ishladi, har biri bo'sh (hop topilmadi).
    assert len(snapshots) == 2
    assert snapshots == [[], []]


async def test_trace_stream_tracks_loss_across_cycles(monkeypatch):
    """Bir sikl javob beradi, ikkinchisi yo'q -> loss_pct hisoblanadi."""
    seq = [
        [FakeRawHop(distance=1, address="10.0.0.1", avg_rtt=5.0, is_alive=True)],
        [FakeRawHop(distance=1, address="10.0.0.1", avg_rtt=0.0, is_alive=False)],
    ]
    calls = {"n": 0}

    def fake_sync(address, **kwargs):
        out = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        return out

    monkeypatch.setattr(topology, "_sync_traceroute", fake_sync)

    last = None
    async for stats in trace_stream("10.0.0.1", cycles=2, interval=0.0, resolve=False):
        last = stats
    assert last is not None
    s = last[0]
    assert s.sent == 2
    assert s.recv == 1
    assert s.loss_pct == pytest.approx(50.0)
