"""netinfo tests — OFFLINE.

``default_gateway`` (the Linux/macOS/netstat branches), the edge cases of
``Interface.cidr`` and ``list_interfaces`` (with psutil monkeypatched) are
exercised. It never touches the network: every ``subprocess.run`` and ``psutil``
call is faked.
"""

from __future__ import annotations

import socket

import psutil
import pytest
from conftest import FakeCompletedProcess, FakeSnicaddr, FakeSnicstats

from systop.core import netinfo
from systop.core.netinfo import Interface, list_interfaces, primary_interface

# --- Interface.cidr edge cases ----------------------------------------------


def test_interface_cidr_basic():
    iface = Interface(name="en0", ipv4="192.168.1.42", netmask="255.255.255.0")
    assert iface.cidr == "192.168.1.0/24"


def test_interface_cidr_slash_16():
    iface = Interface(name="en0", ipv4="10.5.6.7", netmask="255.255.0.0")
    assert iface.cidr == "10.5.0.0/16"


def test_interface_cidr_none_when_no_ipv4():
    assert Interface(name="en0", netmask="255.255.255.0").cidr is None


def test_interface_cidr_none_when_no_netmask():
    assert Interface(name="en0", ipv4="192.168.1.42").cidr is None


def test_interface_cidr_invalid_netmask_returns_none():
    # "255.255.255.7" — a non-contiguous mask -> ValueError.
    iface = Interface(name="en0", ipv4="192.168.1.42", netmask="255.255.255.7")
    assert iface.cidr is None


def test_interface_cidr_garbage_netmask_returns_none():
    iface = Interface(name="en0", ipv4="192.168.1.42", netmask="not-a-mask")
    assert iface.cidr is None


def test_interface_cidr_garbage_ipv4_returns_none():
    iface = Interface(name="en0", ipv4="999.1.1.1", netmask="255.255.255.0")
    assert iface.cidr is None


# --- default_gateway: Linux `ip route show default` -------------------------


def _patch_platform(monkeypatch, system: str):
    monkeypatch.setattr(netinfo.platform, "system", lambda: system)


# --- default_gateway: Windows `route print -4` ------------------------------

# Real `route print -4` output (the IPv4 Route Table part).
_WIN_ROUTE_OUT = (
    "===========================================================================\n"
    "IPv4 Route Table\n"
    "===========================================================================\n"
    "Active Routes:\n"
    "Network Destination        Netmask          Gateway       Interface  Metric\n"
    "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     35\n"
    "      192.168.1.0    255.255.255.0         On-link      192.168.1.50    291\n"
    "===========================================================================\n"
)


def test_default_gateway_windows_route_print(monkeypatch):
    _patch_platform(monkeypatch, "Windows")

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["route", "print"]
        return FakeCompletedProcess(stdout=_WIN_ROUTE_OUT)

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() == "192.168.1.1"


def test_default_gateway_windows_falls_back_to_powershell(monkeypatch):
    """If `route print` gives no gateway, the PowerShell `Get-NetRoute` fallback works."""
    _patch_platform(monkeypatch, "Windows")
    # Get-NetRoute -ExpandProperty NextHop prints the IP line only.
    ps_out = "10.0.0.1\n"

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["route", "print"]:
            # output without a default line -> the parse returns None -> it moves on to PowerShell.
            return FakeCompletedProcess(stdout="Active Routes:\n(no default)\n")
        if cmd[:1] == ["powershell"]:
            return FakeCompletedProcess(stdout=ps_out)
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() == "10.0.0.1"
    assert any(c[:1] == ["powershell"] for c in calls)


def test_default_gateway_windows_both_fail_returns_none(monkeypatch):
    _patch_platform(monkeypatch, "Windows")

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("command not found")

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() is None


def test_default_gateway_linux_ip_route(monkeypatch):
    _patch_platform(monkeypatch, "Linux")
    out = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100\n"

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["ip", "route"]
        return FakeCompletedProcess(stdout=out)

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() == "192.168.1.1"


def test_default_gateway_linux_no_default(monkeypatch):
    _patch_platform(monkeypatch, "Linux")
    monkeypatch.setattr(netinfo.subprocess, "run", lambda *a, **k: FakeCompletedProcess(stdout=""))
    assert netinfo.default_gateway() is None


# --- default_gateway: macOS `route -n get default` --------------------------


def test_default_gateway_macos_route_get(monkeypatch):
    _patch_platform(monkeypatch, "Darwin")
    route_out = (
        "   route to: default\n"
        "destination: default\n"
        "       mask: default\n"
        "    gateway: 10.0.0.1\n"
        "  interface: en0\n"
    )

    def fake_run(cmd, **kwargs):
        assert cmd[:1] == ["route"]
        return FakeCompletedProcess(stdout=route_out)

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() == "10.0.0.1"


# --- default_gateway: netstat -rn zaxira varianti ---------------------------


def test_default_gateway_macos_falls_back_to_netstat(monkeypatch):
    """If `route -n get default` gives no gateway, netstat -rn takes over."""
    _patch_platform(monkeypatch, "Darwin")
    netstat_out = (
        "Routing tables\n"
        "\n"
        "Internet:\n"
        "Destination        Gateway            Flags        Netif Expire\n"
        "default            172.20.10.1        UGScg          en0\n"
        "127.0.0.1          127.0.0.1          UH             lo0\n"
    )

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:1] == ["route"]:
            # output without a gateway line -> the regex finds nothing -> it moves on to netstat
            return FakeCompletedProcess(stdout="   route to: default\n  interface: en0\n")
        if cmd[:1] == ["netstat"]:
            return FakeCompletedProcess(stdout=netstat_out)
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() == "172.20.10.1"
    # We confirm that it really did fall through to the netstat fallback.
    assert any(c[:1] == ["netstat"] for c in calls)


def test_default_gateway_netstat_link_gateway_skipped(monkeypatch):
    """When the netstat default line holds a link instead of a gateway IP (`link#1`, say).

    In that case the second column is not an IP — the function must return None
    and must not take the value by mistake.
    """
    _patch_platform(monkeypatch, "Darwin")
    netstat_out = (
        "Destination        Gateway            Flags        Netif Expire\n"
        "default            link#5             UCSg           en0\n"
    )

    def fake_run(cmd, **kwargs):
        if cmd[:1] == ["route"]:
            return FakeCompletedProcess(stdout="route to: default\n")
        return FakeCompletedProcess(stdout=netstat_out)

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() is None


def test_default_gateway_subprocess_error_returns_none(monkeypatch):
    _patch_platform(monkeypatch, "Linux")

    def boom(*a, **k):
        raise OSError("command not found")

    monkeypatch.setattr(netinfo.subprocess, "run", boom)
    assert netinfo.default_gateway() is None


def test_default_gateway_timeout_returns_none(monkeypatch):
    import subprocess as real_subprocess

    _patch_platform(monkeypatch, "Linux")

    def boom(*a, **k):
        raise real_subprocess.TimeoutExpired(cmd="ip", timeout=3)

    monkeypatch.setattr(netinfo.subprocess, "run", boom)
    assert netinfo.default_gateway() is None


# --- list_interfaces: psutil monkeypatch ------------------------------------


def test_list_interfaces_parses_ipv4_and_mac(monkeypatch):
    addrs = {
        "en0": [
            FakeSnicaddr(family=socket.AF_INET, address="192.168.1.50", netmask="255.255.255.0"),
            FakeSnicaddr(family=psutil.AF_LINK, address="a4:b1:c2:d3:e4:f5"),
        ],
    }
    stats = {"en0": FakeSnicstats(isup=True, speed=1000)}
    monkeypatch.setattr(netinfo.psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(netinfo.psutil, "net_if_stats", lambda: stats)

    ifaces = list_interfaces()
    assert len(ifaces) == 1
    en0 = ifaces[0]
    assert en0.name == "en0"
    assert en0.ipv4 == "192.168.1.50"
    assert en0.netmask == "255.255.255.0"
    assert en0.mac == "a4:b1:c2:d3:e4:f5"
    assert en0.is_up is True
    assert en0.speed_mbps == 1000
    assert en0.cidr == "192.168.1.0/24"


def test_list_interfaces_skips_loopback_by_default(monkeypatch):
    addrs = {
        "lo0": [FakeSnicaddr(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0")],
        "en0": [FakeSnicaddr(family=socket.AF_INET, address="10.0.0.2", netmask="255.255.255.0")],
    }
    monkeypatch.setattr(netinfo.psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(netinfo.psutil, "net_if_stats", lambda: {})

    names = {i.name for i in list_interfaces()}
    assert names == {"en0"}


def test_list_interfaces_include_loopback(monkeypatch):
    addrs = {
        "lo0": [FakeSnicaddr(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0")],
    }
    monkeypatch.setattr(netinfo.psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(netinfo.psutil, "net_if_stats", lambda: {})

    names = {i.name for i in list_interfaces(include_loopback=True)}
    assert "lo0" in names


def test_list_interfaces_skips_interface_without_ipv4(monkeypatch):
    addrs = {
        # Only a MAC, no IPv4 — a virtual interface, it must be skipped.
        "utun0": [FakeSnicaddr(family=psutil.AF_LINK, address="aa:bb:cc:dd:ee:ff")],
        "en0": [FakeSnicaddr(family=socket.AF_INET, address="10.0.0.2", netmask="255.255.255.0")],
    }
    monkeypatch.setattr(netinfo.psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(netinfo.psutil, "net_if_stats", lambda: {})

    names = {i.name for i in list_interfaces()}
    assert names == {"en0"}


def test_list_interfaces_missing_stats_keeps_defaults(monkeypatch):
    """With no stats for an interface, is_up=False and speed=0 remain (no KeyError)."""
    addrs = {
        "en0": [FakeSnicaddr(family=socket.AF_INET, address="10.0.0.2", netmask="255.255.255.0")],
    }
    monkeypatch.setattr(netinfo.psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(netinfo.psutil, "net_if_stats", lambda: {})

    en0 = list_interfaces()[0]
    assert en0.is_up is False
    assert en0.speed_mbps == 0


# --- primary_interface ------------------------------------------------------


def test_primary_interface_matches_gateway_network(monkeypatch):
    ifaces = [
        Interface(name="en0", ipv4="192.168.1.50", netmask="255.255.255.0"),
        Interface(name="en1", ipv4="10.0.0.2", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "10.0.0.1")
    chosen = primary_interface()
    assert chosen is not None and chosen.name == "en1"


def test_primary_interface_falls_back_to_first_when_no_gateway(monkeypatch):
    ifaces = [
        Interface(name="en0", ipv4="192.168.1.50", netmask="255.255.255.0"),
        Interface(name="en1", ipv4="10.0.0.2", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: None)
    chosen = primary_interface()
    assert chosen is not None and chosen.name == "en0"


def test_primary_interface_none_when_no_interfaces(monkeypatch):
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: [])
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "10.0.0.1")
    assert primary_interface() is None


def test_primary_interface_gateway_not_in_any_network_falls_back(monkeypatch):
    ifaces = [Interface(name="en0", ipv4="192.168.1.50", netmask="255.255.255.0")]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "8.8.8.8")
    chosen = primary_interface()
    # The gateway belongs to none of the networks -> it falls back to the first interface.
    assert chosen is not None and chosen.name == "en0"


@pytest.mark.parametrize(
    "gw",
    ["", "not-an-ip", "999.999.999.999"],
)
def test_primary_interface_invalid_gateway_string(monkeypatch, gw):
    """If the gateway is an invalid/broken string — it falls back to the first interface, no crash.

    (Previously ``ipaddress.ip_address(gw)`` had no try around it and raised
    ValueError; after the fix the error is swallowed and the first interface is
    returned.)
    """
    ifaces = [Interface(name="en0", ipv4="192.168.1.50", netmask="255.255.255.0")]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: gw)
    assert primary_interface().name == "en0"


# --- primary_interface: the APIPA (169.254.x) / link-local filter -----------


def test_primary_interface_skips_apipa_when_no_gateway(monkeypatch):
    """No gateway: the APIPA (169.254.x) interface is skipped and a normal one is picked.

    Windows assigns an APIPA address when DHCP does not answer (a disconnected
    adapter, a Hyper-V vEthernet for instance). Such an interface cannot be the
    primary one.
    """
    ifaces = [
        Interface(name="vEthernet", ipv4="169.254.10.20", netmask="255.255.0.0"),
        Interface(name="Ethernet", ipv4="192.168.1.50", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: None)
    chosen = primary_interface()
    assert chosen is not None and chosen.name == "Ethernet"


def test_primary_interface_apipa_first_real_second(monkeypatch):
    """Even if the first interface is APIPA — the next NON-APIPA one is chosen."""
    ifaces = [
        Interface(name="APIPA0", ipv4="169.254.1.1", netmask="255.255.0.0"),
        Interface(name="APIPA1", ipv4="169.254.99.99", netmask="255.255.0.0"),
        Interface(name="Real", ipv4="10.0.0.5", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: None)
    assert primary_interface().name == "Real"


def test_primary_interface_gateway_match_wins_over_apipa(monkeypatch):
    """The interface matching the gateway wins over the APIPA filter (rule 1)."""
    ifaces = [
        Interface(name="APIPA", ipv4="169.254.5.5", netmask="255.255.0.0"),
        Interface(name="LAN", ipv4="192.168.1.50", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "192.168.1.1")
    assert primary_interface().name == "LAN"


def test_primary_interface_all_apipa_falls_back_to_first(monkeypatch):
    """If every interface is APIPA — the last resort is the first one (not None)."""
    ifaces = [
        Interface(name="A", ipv4="169.254.1.1", netmask="255.255.0.0"),
        Interface(name="B", ipv4="169.254.2.2", netmask="255.255.0.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: None)
    chosen = primary_interface()
    assert chosen is not None and chosen.name == "A"


def test_primary_interface_gateway_outside_network_skips_apipa(monkeypatch):
    """If the gateway belongs to no network, APIPA is skipped and a normal one is chosen."""
    ifaces = [
        Interface(name="APIPA", ipv4="169.254.7.7", netmask="255.255.0.0"),
        Interface(name="Real", ipv4="192.168.1.50", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "8.8.8.8")
    assert primary_interface().name == "Real"


@pytest.mark.parametrize(
    "ipv4, expected",
    [
        ("169.254.0.1", True),
        ("169.254.255.254", True),
        ("192.168.1.1", False),
        ("10.0.0.1", False),
        ("8.8.8.8", False),
        (None, True),
        ("not-an-ip", True),
    ],
)
def test_is_apipa(ipv4, expected):
    assert netinfo._is_apipa(ipv4) is expected


# --------------------------------------------------------------------------- #
# prefixlen / host_count (0.6.1) — for showing `/24` next to the gateway
# --------------------------------------------------------------------------- #


def test_prefixlen_from_netmask():
    assert Interface(name="en0", ipv4="10.0.0.5", netmask="255.255.255.0").prefixlen == 24


def test_prefixlen_slash_23():
    assert Interface(name="en0", ipv4="192.168.11.43", netmask="255.255.254.0").prefixlen == 23


def test_prefixlen_slash_16():
    assert Interface(name="en0", ipv4="172.16.0.5", netmask="255.255.0.0").prefixlen == 16


def test_prefixlen_none_without_netmask():
    assert Interface(name="en0", ipv4="10.0.0.5").prefixlen is None


def test_prefixlen_none_without_ipv4():
    assert Interface(name="en0", netmask="255.255.255.0").prefixlen is None


def test_prefixlen_invalid_netmask_is_none():
    assert Interface(name="en0", ipv4="10.0.0.5", netmask="nonsense").prefixlen is None


def test_host_count_slash_24():
    """/24 -> 254 (the network and the broadcast are excluded)."""
    assert Interface(name="en0", ipv4="10.0.0.5", netmask="255.255.255.0").host_count == 254


def test_host_count_slash_23():
    assert Interface(name="en0", ipv4="10.0.0.5", netmask="255.255.254.0").host_count == 510


def test_host_count_slash_31_is_zero():
    """A /31 leaves no usable host (and must not go negative)."""
    assert Interface(name="en0", ipv4="10.0.0.5", netmask="255.255.255.254").host_count == 0


def test_host_count_none_without_prefix():
    assert Interface(name="en0").host_count is None
