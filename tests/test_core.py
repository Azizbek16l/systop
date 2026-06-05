"""Tarmoqsiz (offline) ishlaydigan birlik testlari."""

from systop.core.netinfo import Interface
from systop.core.ping import DEFAULT_GLOBAL_TARGETS, PingResult, build_targets
from systop.core.topology import _ARP_RE, _NEIGH_RE


def test_interface_cidr():
    iface = Interface(name="en0", ipv4="192.168.1.42", netmask="255.255.255.0")
    assert iface.cidr == "192.168.1.0/24"


def test_interface_cidr_none_without_ip():
    assert Interface(name="en0").cidr is None


def test_build_targets_with_gateway():
    targets = build_targets("192.168.1.1")
    assert targets["Gateway (lokal)"] == "192.168.1.1"
    assert "Cloudflare" in targets
    assert len(targets) == len(DEFAULT_GLOBAL_TARGETS) + 1


def test_build_targets_no_gateway_no_global():
    assert build_targets(None, include_global=False) == {}


def test_ping_result_loss_pct():
    assert PingResult(label="x", address="1.1.1.1", packet_loss=0.25).loss_pct == 25.0


def test_arp_regex_macos():
    line = "? (192.168.1.1) at a4:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]"
    m = _ARP_RE.search(line)
    assert m and m.group(1) == "192.168.1.1"
    assert m.group(2) == "a4:b1:c2:d3:e4:f5"


def test_neigh_regex_linux():
    line = "192.168.1.1 dev eth0 lladdr a4:b1:c2:d3:e4:f5 REACHABLE"
    m = _NEIGH_RE.search(line)
    assert m and m.group(1) == "192.168.1.1"
    assert m.group(2) == "a4:b1:c2:d3:e4:f5"
