"""Lokal tarmoq haqida ma'lumot: interfeyslar, default gateway, public IP.

`psutil` interfeyslarni beradi; gateway uchun OS marshrutlash jadvalini
o'qiymiz (psutil'da gateway yo'q). Public IP HTTP orqali aniqlanadi.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass, field

import httpx
import psutil


@dataclass(slots=True)
class Interface:
    """Bitta tarmoq interfeysi."""

    name: str
    ipv4: str | None = None
    netmask: str | None = None
    mac: str | None = None
    is_up: bool = False
    speed_mbps: int = 0  # 0 => noma'lum

    @property
    def cidr(self) -> str | None:
        """`192.168.1.0/24` ko'rinishidagi tarmoq (ipv4 + netmask bo'lsa)."""
        if not self.ipv4 or not self.netmask:
            return None
        try:
            net = ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False)
            return str(net)
        except ValueError:
            return None


def list_interfaces(include_loopback: bool = False) -> list[Interface]:
    """Tizimdagi tarmoq interfeyslarini IPv4 ma'lumoti bilan qaytaradi."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    result: list[Interface] = []

    for name, addr_list in addrs.items():
        if not include_loopback and (name.startswith("lo") or name == "lo0"):
            continue

        iface = Interface(name=name)
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                iface.ipv4 = addr.address
                iface.netmask = addr.netmask
            elif addr.family == psutil.AF_LINK:
                iface.mac = addr.address

        if name in stats:
            iface.is_up = stats[name].isup
            iface.speed_mbps = stats[name].speed

        # IPv4'siz "virtual" interfeyslarni o'tkazib yuboramiz.
        if iface.ipv4:
            result.append(iface)

    return result


def default_gateway() -> str | None:
    """Default gateway IP manzilini OS marshrut jadvalidan oladi."""
    system = platform.system()
    try:
        if system == "Linux":
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None

        # macOS / BSD
        out = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)

        # Universal zaxira: netstat marshrut jadvali
        out = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            if line.split()[:1] == ["default"]:
                parts = line.split()
                if len(parts) > 1 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[1]):
                    return parts[1]
    except (subprocess.SubprocessError, OSError, IndexError):
        return None
    return None


def primary_interface() -> Interface | None:
    """Default gateway bilan bir tarmoqda turgan asosiy interfeys."""
    gw = default_gateway()
    ifaces = list_interfaces()
    if gw:
        try:
            gw_addr = ipaddress.ip_address(gw)
        except ValueError:
            # Buzuq/kutilmagan gateway satri — birinchi interfeysga tushamiz.
            gw_addr = None
        if gw_addr is not None:
            for iface in ifaces:
                cidr = iface.cidr
                if cidr and gw_addr in ipaddress.ip_network(cidr):
                    return iface
    return ifaces[0] if ifaces else None


async def public_ip(timeout: float = 5.0) -> str | None:
    """Tashqi (public) IP manzilni HTTP orqali aniqlaydi."""
    services = (
        ("https://api.ipify.org", None),
        ("https://ifconfig.me/ip", None),
        ("https://www.cloudflare.com/cdn-cgi/trace", r"ip=(\d+\.\d+\.\d+\.\d+)"),
    )
    async with httpx.AsyncClient(timeout=timeout) as client:
        for url, pattern in services:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                text = resp.text.strip()
                if pattern:
                    m = re.search(pattern, text)
                    return m.group(1) if m else None
                return text
            except (httpx.HTTPError, OSError):
                continue
    return None


@dataclass(slots=True)
class NetSummary:
    """Lokal tarmoq holatining yig'ma ko'rinishi."""

    interfaces: list[Interface] = field(default_factory=list)
    gateway: str | None = None
    public_ip: str | None = None


async def gather_summary() -> NetSummary:
    """Interfeyslar, gateway va public IP'ni bitta obyektga yig'adi."""
    return NetSummary(
        interfaces=list_interfaces(),
        gateway=default_gateway(),
        public_ip=await public_ip(),
    )
