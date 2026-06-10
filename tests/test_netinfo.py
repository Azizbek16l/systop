"""netinfo testlari — OFFLINE.

``default_gateway`` (Linux/macOS/netstat shoxlari), ``Interface.cidr`` chekka
holatlari, ``list_interfaces`` (psutil monkeypatch bilan) sinaladi. Tarmoqqa
chiqmaydi: barcha ``subprocess.run`` va ``psutil`` chaqiruvlari soxtalashtiriladi.
"""

from __future__ import annotations

import socket

import psutil
import pytest
from conftest import FakeCompletedProcess, FakeSnicaddr, FakeSnicstats

from systop.core import netinfo
from systop.core.netinfo import Interface, list_interfaces, primary_interface

# --- Interface.cidr chekka holatlar -----------------------------------------


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
    # "255.255.255.7" — uzluksiz bo'lmagan (non-contiguous) maska -> ValueError.
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

# Real `route print -4` chiqishi (IPv4 Route Table qismi).
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
    """`route print` gateway bermasa, PowerShell `Get-NetRoute` zaxirasi ishlaydi."""
    _patch_platform(monkeypatch, "Windows")
    # Get-NetRoute -ExpandProperty NextHop faqat IP qatorini chiqaradi.
    ps_out = "10.0.0.1\n"

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["route", "print"]:
            # default qatorisiz chiqish -> parse None qaytaradi -> PowerShell'ga o'tadi.
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
    """`route -n get default` gateway bermasa, netstat -rn ishlaydi."""
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
            # gateway qatorisiz chiqish -> regex topa olmaydi -> netstat'ga o'tadi
            return FakeCompletedProcess(stdout="   route to: default\n  interface: en0\n")
        if cmd[:1] == ["netstat"]:
            return FakeCompletedProcess(stdout=netstat_out)
        return FakeCompletedProcess(stdout="")

    monkeypatch.setattr(netinfo.subprocess, "run", fake_run)
    assert netinfo.default_gateway() == "172.20.10.1"
    # Haqiqatan ham netstat zaxirasiga tushganini tasdiqlaymiz.
    assert any(c[:1] == ["netstat"] for c in calls)


def test_default_gateway_netstat_link_gateway_skipped(monkeypatch):
    """netstat default qatorida gateway IP emas, link bo'lsa (masalan, `link#1`).

    Bunday holda ikkinchi ustun IP emas — funksiya None qaytarishi kerak,
    qiymatni noto'g'ri olmasligi shart.
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
        # Faqat MAC bor, IPv4 yo'q — virtual interfeys, o'tkazib yuborilishi kerak.
        "utun0": [FakeSnicaddr(family=psutil.AF_LINK, address="aa:bb:cc:dd:ee:ff")],
        "en0": [FakeSnicaddr(family=socket.AF_INET, address="10.0.0.2", netmask="255.255.255.0")],
    }
    monkeypatch.setattr(netinfo.psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(netinfo.psutil, "net_if_stats", lambda: {})

    names = {i.name for i in list_interfaces()}
    assert names == {"en0"}


def test_list_interfaces_missing_stats_keeps_defaults(monkeypatch):
    """Interfeys uchun stats bo'lmasa, is_up=False va speed=0 qoladi (KeyError yo'q)."""
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
    # Gateway hech qaysi tarmoqqa kirmaydi -> birinchi interfeysga tushadi.
    assert chosen is not None and chosen.name == "en0"


@pytest.mark.parametrize(
    "gw",
    ["", "not-an-ip", "999.999.999.999"],
)
def test_primary_interface_invalid_gateway_string(monkeypatch, gw):
    """Gateway noto'g'ri/buzuq satr bo'lsa — yiqilmasdan birinchi interfeysga tushadi.

    (Avval ``ipaddress.ip_address(gw)`` try'siz edi va ValueError ko'tarardi;
    tuzatilgandan keyin xato yutilib, birinchi interfeys qaytariladi.)
    """
    ifaces = [Interface(name="en0", ipv4="192.168.1.50", netmask="255.255.255.0")]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: gw)
    assert primary_interface().name == "en0"


# --- primary_interface: APIPA (169.254.x) / link-local filtri ---------------


def test_primary_interface_skips_apipa_when_no_gateway(monkeypatch):
    """Gateway yo'q: APIPA (169.254.x) interfeys o'tkazib, normalini tanlaydi.

    Windows DHCP javob bermaganda APIPA tayinlaydi (ulanmagan adapter, masalan
    Hyper-V vEthernet). Bunday interfeys primary bo'la olmaydi.
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
    """Birinchi interfeys APIPA bo'lsa ham — keyingi NON-APIPA tanlanadi."""
    ifaces = [
        Interface(name="APIPA0", ipv4="169.254.1.1", netmask="255.255.0.0"),
        Interface(name="APIPA1", ipv4="169.254.99.99", netmask="255.255.0.0"),
        Interface(name="Real", ipv4="10.0.0.5", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: None)
    assert primary_interface().name == "Real"


def test_primary_interface_gateway_match_wins_over_apipa(monkeypatch):
    """Gateway mos kelgan interfeys APIPA filtridan oldin afzal (1-qoida)."""
    ifaces = [
        Interface(name="APIPA", ipv4="169.254.5.5", netmask="255.255.0.0"),
        Interface(name="LAN", ipv4="192.168.1.50", netmask="255.255.255.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: "192.168.1.1")
    assert primary_interface().name == "LAN"


def test_primary_interface_all_apipa_falls_back_to_first(monkeypatch):
    """Hamma interfeys APIPA bo'lsa — oxirgi zaxira birinchi (None emas)."""
    ifaces = [
        Interface(name="A", ipv4="169.254.1.1", netmask="255.255.0.0"),
        Interface(name="B", ipv4="169.254.2.2", netmask="255.255.0.0"),
    ]
    monkeypatch.setattr(netinfo, "list_interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_gateway", lambda: None)
    chosen = primary_interface()
    assert chosen is not None and chosen.name == "A"


def test_primary_interface_gateway_outside_network_skips_apipa(monkeypatch):
    """Gateway hech qaysi tarmoqqa kirmasa, APIPA o'tkazilib normal tanlanadi."""
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
