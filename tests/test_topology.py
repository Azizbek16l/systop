"""topology tests — OFFLINE.

The ``_ARP_RE`` / ``_NEIGH_RE`` regexes are exercised against real-world lines,
``_parse_arp_table`` with a ``subprocess`` monkeypatch, and ``discover_lan``
with ``async_multiping`` mocked out. No network call is ever made.
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
    # Linux `arp -n` output does not put the IP in brackets either -> _ARP_RE
    # does not match. But `arp -a` on Linux does:
    #   "host (10.0.0.5) at 11:22:33:44:55:66 [ether] on eth0"
    line = "? (10.0.0.5) at 11:22:33:44:55:66 [ether] on eth0"
    m = _ARP_RE.search(line)
    assert m is not None
    assert m.group(1) == "10.0.0.5"
    assert m.group(2) == "11:22:33:44:55:66"


def test_arp_re_incomplete_entry_no_match():
    # A host in `arp -a` that never answered: "(incomplete)" instead of a MAC.
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
    # Entries without an lladdr (FAILED / INCOMPLETE) must not match.
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
        # The MAC is lower-cased.
        "192.168.1.42": "aa:bb:cc:dd:ee:ff",
    }
    assert "192.168.1.99" not in table  # incomplete is skipped


def test_parse_arp_table_falls_back_to_ip_neigh(monkeypatch):
    neigh_out = (
        "192.168.1.1 dev eth0 lladdr a4:b1:c2:d3:e4:f5 REACHABLE\n"
        "192.168.1.7 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
        "192.168.1.250 dev eth0  FAILED\n"
    )

    def fake_run(cmd, **kwargs):
        if cmd[:1] == ["arp"]:
            # arp missing / empty output -> falls through to `ip -4 neigh`.
            return FakeCompletedProcess(stdout="")
        if cmd[:1] == ["ip"]:
            return FakeCompletedProcess(stdout=neigh_out)
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    table = _parse_arp_table()
    assert table == {
        "192.168.1.1": "a4:b1:c2:d3:e4:f5",
        "192.168.1.7": "11:22:33:44:55:66",
    }


def test_parse_arp_table_arp_missing_raises_oserror(monkeypatch):
    """If the `arp` command is missing (OSError) -> it has to fall back to `ip -4 neigh`."""
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


# --- discover_lan: merging async_multiping + ARP ----------------------------


async def test_discover_lan_merges_ping_and_arp(monkeypatch):
    """The alive hosts have to come from the ping, and the MAC from the ARP table."""
    cidr = "192.168.1.0/30"  # hosts: .1, .2

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
    """A host that is in ARP but did not answer the ping must be added too."""
    cidr = "192.168.1.0/24"

    async def fake_multiping(hosts, **kwargs):
        return [FakeHost(address="192.168.1.10", is_alive=True, avg_rtt=2.0)]

    monkeypatch.setattr(topology, "async_multiping", fake_multiping)
    monkeypatch.setattr(
        topology,
        "_parse_arp_table",
        lambda: {
            "192.168.1.10": "aa:aa:aa:aa:aa:aa",
            "192.168.1.20": "bb:bb:bb:bb:bb:bb",  # only in ARP
            "10.9.9.9": "cc:cc:cc:cc:cc:cc",  # outside the network -> dropped
        },
    )
    monkeypatch.setattr(topology.netinfo, "default_gateway", lambda: None)

    hosts = await discover_lan(cidr=cidr)
    ips = [h.ip for h in hosts]
    assert ips == ["192.168.1.10", "192.168.1.20"]  # sorted by IP
    # An ARP entry from outside the network is not added.
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
    # The order has to be numeric (ip_address), not lexicographic.
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
    # The hosts have to have been built from the primary_interface CIDR.
    assert "192.168.5.1" in captured["hosts"]
    assert "192.168.5.254" in captured["hosts"]


async def test_discover_lan_respects_max_hosts(monkeypatch):
    cidr = "10.0.0.0/24"  # 254 hosts, but max_hosts=5 caps it

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
    """A /31 network -> ``network.hosts()`` gives two addresses (RFC 3021).

    ``ipaddress`` treats /31 and /32 specially: for a /31 it returns both
    addresses as hosts, so multiping IS called. We document that behaviour here.
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
    # /31 -> .4 and .5 are returned as hosts.
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
    """When the hop address is None (* * *), reverse DNS is not called and nothing errors."""
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
    # The header line must not match.
    assert _ARP_WIN_RE.search("  Internet Address      Physical Address      Type") is None


def test_arp_win_re_interface_line_no_match():
    # The "Interface: 192.168.1.50 --- 0xN" line — no MAC, so no match.
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
    # The MAC is normalised from dashes to ':' and to lower case.
    assert table["192.168.1.1"] == "00:11:22:33:44:55"
    assert table["192.168.1.42"] == "a4:b1:c2:d3:e4:f5"
    # Broadcast/multicast entries match the regex too (they are filtered in
    # discover_lan by network membership) — but the header does not.
    assert "Physical" not in table


def test_parse_arp_table_windows_command_missing(monkeypatch):
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("arp not found")

    monkeypatch.setattr(topology.subprocess, "run", fake_run)
    assert _parse_arp_table() == {}


def test_win_arp_mac_lookup_vendor_accepts_dash():
    """Asserting that oui.lookup_vendor also accepts a dash-formatted MAC."""
    from systop.core import oui

    # An Apple OUI (we do not assume it is in the table — normalize is the same
    # for both formats).
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
    # Switch IcmpSendEcho off so the tracert.exe parse path is tested deterministically.
    monkeypatch.setattr(topology._platform, "win_icmp_traceroute", lambda *a, **k: None)

    async def fake_run_command(cmd, timeout):
        assert cmd[0] == "tracert"
        assert "-d" in cmd  # numeric mode (no resolution)
        return _WIN_TRACERT_OUT

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)

    raw = await topology._win_traceroute("8.8.8.8")
    assert [h.distance for h in raw] == [1, 2, 3, 4]
    assert raw[0].address == "192.168.1.1"
    assert raw[0].avg_rtt == pytest.approx(1.0)
    assert raw[0].is_alive is True
    assert raw[2].address is None  # a timeout hop
    assert raw[2].is_alive is False


async def test_win_traceroute_uses_icmpsendecho_when_available(monkeypatch):
    """The PRIMARY path: _win_traceroute takes the IcmpSendEcho result, NOT tracert.exe."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)

    def fake_icmp_trace(address, max_hops, timeout):
        assert address == "8.8.8.8"
        return [
            (1, "192.168.1.1", 1.0, True),
            (2, None, 0.0, False),
            (3, "8.8.8.8", 12.0, True),
        ]

    monkeypatch.setattr(topology._platform, "win_icmp_traceroute", fake_icmp_trace)

    async def boom(cmd, timeout):
        raise AssertionError("when IcmpSendEcho is available tracert.exe must not be called")

    monkeypatch.setattr(topology._platform, "run_command", boom)

    raw = await topology._win_traceroute("8.8.8.8")
    assert [h.distance for h in raw] == [1, 2, 3]
    assert raw[0].address == "192.168.1.1"
    assert raw[0].avg_rtt == pytest.approx(1.0)
    assert raw[1].address is None  # a timeout hop
    assert raw[1].is_alive is False
    assert raw[2].address == "8.8.8.8"


async def test_win_traceroute_falls_back_to_parse_when_icmp_none(monkeypatch):
    """IcmpSendEcho None -> falls back to the tracert.exe parse path."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)
    monkeypatch.setattr(topology._platform, "win_icmp_traceroute", lambda *a, **k: None)

    async def fake_run_command(cmd, timeout):
        assert cmd[0] == "tracert"
        return _WIN_TRACERT_OUT

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)
    raw = await topology._win_traceroute("8.8.8.8")
    assert [h.distance for h in raw] == [1, 2, 3, 4]
    assert raw[0].address == "192.168.1.1"
    assert raw[2].address is None


async def test_traceroute_windows_branch(monkeypatch):
    """Asserting that on Windows traceroute() uses tracert, NOT icmplib."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)
    # This test checks the ping.exe/tracert.exe parse path -> switch IcmpSendEcho off.
    monkeypatch.setattr(topology._platform, "win_icmp_traceroute", lambda *a, **k: None)

    def boom(*a, **k):
        raise AssertionError("icmplib traceroute must not be called on Windows")

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
    # Reverse DNS is not called for a timeout hop.
    assert hops[2].address is None
    assert hops[2].hostname is None


async def test_trace_path_windows_empty_sets_error(monkeypatch):
    """When Windows tracert comes back empty -> TraceResult.error is filled in."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)
    # No IcmpSendEcho either -> tracert.exe is empty too -> the error is filled in.
    monkeypatch.setattr(topology._platform, "win_icmp_traceroute", lambda *a, **k: None)

    async def fake_run_command(cmd, timeout):
        return ""  # command missing / timeout

    monkeypatch.setattr(topology._platform, "run_command", fake_run_command)
    result = await trace_path("8.8.8.8", resolve=False)
    assert result.hops == []
    assert result.error is not None


async def test_trace_stream_windows_branch(monkeypatch):
    """Asserting that on Windows trace_stream probes through _win_traceroute."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)
    # We are testing the tracert.exe parse path -> switch IcmpSendEcho off.
    monkeypatch.setattr(topology._platform, "win_icmp_traceroute", lambda *a, **k: None)

    def boom(*a, **k):
        raise AssertionError("icmplib must not be called on Windows")

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
    """On Windows discover_lan uses a `ping` sweep, NOT async_multiping."""
    monkeypatch.setattr(topology._platform, "IS_WINDOWS", True)
    cidr = "192.168.1.0/30"  # hosts: .1, .2

    async def boom(*a, **k):
        raise AssertionError("async_multiping must not be called on Windows")

    monkeypatch.setattr(topology, "async_multiping", boom)
    # The sweep tests the ping.exe parse path -> switch IcmpSendEcho off.
    monkeypatch.setattr(topology._platform, "win_icmp_ping", lambda *a, **k: None)

    # The `ping` sweep: only .1 answers.
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


# --- dataclass defaults -----------------------------------------------------


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


# --- HopStat: the update() / loss_pct arithmetic ----------------------------


def test_hopstat_loss_pct_no_probes():
    # Nothing was sent -> 0% (with no 0/0 division).
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
    s.update(None, alive=False, rtt=0.0)  # an unanswered probe
    s.update("10.0.0.2", alive=True, rtt=7.0)
    s.update(None, alive=False, rtt=0.0)
    assert s.sent == 4
    assert s.recv == 2
    assert s.loss_pct == pytest.approx(50.0)
    # Unanswered probes have no effect on the rtt statistics.
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
    """Even with alive=True, rtt<=0 -> it does not count as an answer (a timeout probe)."""
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=0.0)
    assert s.sent == 1
    assert s.recv == 0
    assert s.address == "10.0.0.1"  # the address is recorded anyway


def test_hopstat_update_sets_address_once():
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=5.0)
    s.update("10.0.0.99", alive=True, rtt=6.0)  # a different address — ignored
    assert s.address == "10.0.0.1"


def test_hopstat_best_rtt_initial_from_zero():
    """best_rtt starts at 0.0 — the first real rtt has to set it."""
    s = HopStat(index=1)
    s.update("10.0.0.1", alive=True, rtt=15.0)
    assert s.best_rtt == 15.0  # not 0.0


# --- trace_stream: a mocked _sync_traceroute, a bounded number of cycles ----


async def test_trace_stream_two_cycles_accumulates(monkeypatch):
    """Two cycles -> sent=2, recv=2 for every hop; the list is ordered by index."""
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
    # After the first cycle every hop has been probed once.
    assert snapshots[0] == [(1, 1, 1, "host-192.168.1.1"), (2, 1, 1, "host-8.8.8.8")]
    # After the second cycle the totals reach 2 (the statistics accumulate).
    assert snapshots[1] == [(1, 2, 2, "host-192.168.1.1"), (2, 2, 2, "host-8.8.8.8")]


async def test_trace_stream_resolve_once_per_address(monkeypatch):
    """Reverse DNS is only called for an address the first time it is seen."""
    raw = [FakeRawHop(distance=1, address="192.168.1.1", avg_rtt=1.0, is_alive=True)]
    monkeypatch.setattr(topology, "_sync_traceroute", lambda address, **k: raw)

    dns_calls = {"n": 0}

    async def fake_reverse(addr, timeout=1.0):
        dns_calls["n"] += 1
        return "router"

    monkeypatch.setattr(topology, "_reverse_dns", fake_reverse)

    async for _ in trace_stream("192.168.1.1", cycles=3, interval=0.0, resolve=True):
        pass
    # Even with 3 cycles the address never changed, so reverse DNS runs once.
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
    """When both probe paths error -> an empty list, and the stream is not broken.

    Since 0.5.1, if `icmplib` is refused permission we fall back to the system
    `traceroute` binary, so the test MUST mock the second path as well —
    otherwise an offline test would reach out to the real network.
    """
    from icmplib.exceptions import ICMPLibError

    def boom(address, **kwargs):
        raise ICMPLibError("no socket")

    async def no_fallback(address, **kwargs):
        return []

    monkeypatch.setattr(topology, "_sync_traceroute", boom)
    monkeypatch.setattr(topology, "_posix_traceroute", no_fallback)

    snapshots = []
    async for stats in trace_stream("8.8.8.8", cycles=2, interval=0.0, resolve=False):
        snapshots.append(stats)
    # Both cycles ran, each of them empty (no hop was found).
    assert len(snapshots) == 2
    assert snapshots == [[], []]


async def test_trace_stream_tracks_loss_across_cycles(monkeypatch):
    """One cycle answers and the other does not -> loss_pct is computed."""
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


# --------------------------------------------------------------------------- #
# The IPv6 neighbour (NDP) table — added in 0.4.0
# --------------------------------------------------------------------------- #

from systop.core.topology import ALL_NODES_MULTICAST, parse_ndp_output  # noqa: E402

_MACOS_NDP = """Neighbor                             Linklayer Address  Netif Expire    St Flgs
fe80::1%en0                          a4:83:e7:1b:2c:3d  en0   23h59m58s S  R
2001:db8:1::10                       aa:bb:cc:dd:ee:ff  en0   permanent R
fe80::c0a:1234%en0                   0:1c:42:3:4:5      en0   1m20s     S
"""

_LINUX_NEIGH = """fe80::1 dev eth0 lladdr a4:83:e7:1b:2c:3d router STALE
2001:db8:1::10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
fe80::dead dev eth0  INCOMPLETE
"""

_WIN_NEIGH = """Interface 12: Ethernet
Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::1                                       a4-83-e7-1b-2c-3d  Stale
2001:db8:1::10                                aa-bb-cc-dd-ee-ff  Reachable
"""


def test_parse_ndp_macos():
    t = parse_ndp_output(_MACOS_NDP)
    assert t["fe80::1%en0"] == "a4:83:e7:1b:2c:3d"
    assert t["2001:db8:1::10"] == "aa:bb:cc:dd:ee:ff"


def test_parse_ndp_macos_zero_pads_short_octets():
    """macOS gives short octets ("0:1c:42:3:4:5") — they have to be normalised."""
    t = parse_ndp_output(_MACOS_NDP)
    assert t["fe80::c0a:1234%en0"] == "00:1c:42:03:04:05"


def test_parse_ndp_preserves_zone():
    """The zone (%en0) MUST be preserved — a link-local address is unusable without it."""
    assert any("%en0" in ip for ip in parse_ndp_output(_MACOS_NDP))


def test_parse_ndp_linux():
    t = parse_ndp_output(_LINUX_NEIGH)
    assert t["fe80::1"] == "a4:83:e7:1b:2c:3d"


def test_parse_ndp_linux_skips_incomplete():
    """An entry with no MAC (INCOMPLETE) is dropped."""
    assert "fe80::dead" not in parse_ndp_output(_LINUX_NEIGH)


def test_parse_ndp_windows():
    t = parse_ndp_output(_WIN_NEIGH, windows=True)
    assert t["fe80::1"] == "a4:83:e7:1b:2c:3d"
    assert len(t) == 2


def test_parse_ndp_windows_skips_header():
    t = parse_ndp_output(_WIN_NEIGH, windows=True)
    assert not any("Internet" in ip for ip in t)


def test_parse_ndp_empty_input():
    assert parse_ndp_output("") == {}


def test_parse_ndp_ignores_ipv4_lines():
    """IPv4 ARP lines must not get through to the IPv6 parser."""
    assert parse_ndp_output("192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE") == {}


def test_all_nodes_multicast_constant():
    assert ALL_NODES_MULTICAST == "ff02::1"


def test_lan_host_is_link_local():
    assert LanHost(ip="fe80::1%en0", family="ipv6").is_link_local
    assert not LanHost(ip="2001:db8::1", family="ipv6").is_link_local
    assert not LanHost(ip="192.168.1.1").is_link_local


def test_lan_host_defaults_to_ipv4():
    h = LanHost(ip="192.168.1.1")
    assert h.family == "ipv4"
    assert h.source == "ping"


# --------------------------------------------------------------------------- #
# An ARP parsing regression (0.4.0) — the bug where MAC/vendor came out empty
# --------------------------------------------------------------------------- #

from systop.core.oui import lookup_vendor  # noqa: E402
from systop.core.topology import _normalize_mac  # noqa: E402


def test_normalize_mac_zero_pads_macos_short_octets():
    """macOS `arp` gives short octets — without padding the OUI is never found."""
    assert _normalize_mac("0:15:5d:27:40:3") == "00:15:5d:27:40:03"
    assert _normalize_mac("c0:6:c3:2:63:55") == "c0:06:c3:02:63:55"


def test_normalize_mac_lowercases():
    assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_leaves_full_form_unchanged():
    assert _normalize_mac("00:15:5d:27:40:03") == "00:15:5d:27:40:03"


def test_short_mac_resolves_vendor_after_normalization():
    """The bug: a short MAC found no vendor. After normalisation it has to be found."""
    assert lookup_vendor(_normalize_mac("c0:6:c3:2:63:55")) == "TP-Link"


def test_arp_regex_skips_incomplete_entries():
    """An `(incomplete)` entry has no MAC — it must not match."""
    line = "? (192.168.10.3) at (incomplete) on en0 ifscope [ethernet]"
    assert _ARP_RE.search(line) is None


def test_arp_regex_matches_macos_numeric_output():
    """`arp -an` output (the code uses that command — `arp -a` is slow)."""
    line = "? (192.168.10.2) at c0:6:c3:2:63:55 on en0 ifscope [ethernet]"
    m = _ARP_RE.search(line)
    assert m is not None
    assert m.group(1) == "192.168.10.2"
    assert _normalize_mac(m.group(2)) == "c0:06:c3:02:63:55"


def test_arp_regex_matches_named_host_line():
    line = "control (192.168.10.1) at 0:15:5d:27:40:3 on en0 ifscope [ethernet]"
    m = _ARP_RE.search(line)
    assert m.group(1) == "192.168.10.1"


def test_hyperv_oui_detected():
    """The Hyper-V VM prefix — the one seen most often in infrastructure."""
    assert "Hyper-V" in lookup_vendor("00:15:5d:38:01:02")


def test_virtual_nic_ouis_present():
    for mac, expect in [
        ("08:00:27:11:22:33", "VirtualBox"),
        ("52:54:00:11:22:33", "QEMU"),
        ("00:16:3e:11:22:33", "Xen"),
    ]:
        assert expect in (lookup_vendor(mac) or ""), mac


# --------------------------------------------------------------------------- #
# The POSIX traceroute fallback (0.5.1) — on macOS icmplib demands a raw socket
# --------------------------------------------------------------------------- #

from systop.core.topology import parse_posix_traceroute  # noqa: E402

_MACOS_TR = """traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 40 byte packets
 1  192.168.10.1  3.590 ms
 2  185.203.238.161  6.582 ms
 3  * * *
 4  84.54.64.157  6.108 ms
"""

_LINUX_TR = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  10.0.0.1  1.234 ms  1.5 ms  1.4 ms
 2  * * *
 3  142.250.1.1  12.5 ms
"""


def test_parse_posix_traceroute_macos():
    hops = parse_posix_traceroute(_MACOS_TR)
    assert len(hops) == 4
    assert hops[0] == (1, "192.168.10.1", 3.590, True)


def test_parse_posix_traceroute_marks_unanswered_hop():
    hops = parse_posix_traceroute(_MACOS_TR)
    assert hops[2] == (3, None, 0.0, False)


def test_parse_posix_traceroute_linux_multiple_probes():
    """Linux prints 3 probes per hop — the first one is taken."""
    hops = parse_posix_traceroute(_LINUX_TR)
    assert hops[0] == (1, "10.0.0.1", 1.234, True)
    assert hops[1] == (2, None, 0.0, False)
    assert hops[2][1] == "142.250.1.1"


def test_parse_posix_traceroute_skips_header():
    hops = parse_posix_traceroute(_MACOS_TR)
    assert all(h[0] > 0 for h in hops)


def test_parse_posix_traceroute_ipv6_address():
    out = " 1  2001:db8::1  5.5 ms\n"
    assert parse_posix_traceroute(out) == [(1, "2001:db8::1", 5.5, True)]


def test_parse_posix_traceroute_empty_and_garbage():
    assert parse_posix_traceroute("") == []
    assert parse_posix_traceroute("no hops at all here\n") == []
