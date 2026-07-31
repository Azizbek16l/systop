"""Information about the local network: interfaces, default gateway, public IP.

`psutil` gives us the interfaces; for the gateway we read the OS routing table
(psutil has no gateway). The public IP is determined over HTTP.
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

from systop.core import _platform

_IS_WINDOWS_NETINFO = platform.system() == "Windows"


@dataclass(slots=True)
class Interface:
    """A single network interface."""

    name: str
    ipv4: str | None = None
    netmask: str | None = None
    mac: str | None = None
    is_up: bool = False
    speed_mbps: int = 0  # 0 => unknown
    # IPv6: `(address, prefix_length)` pairs. A list, because it is perfectly
    # normal for one interface to hold a link-local + a global + a ULA +
    # temporary (privacy) address all at the same time.
    ipv6: list[tuple[str, int]] = field(default_factory=list)

    @property
    def cidr(self) -> str | None:
        """The IPv4 network in `192.168.1.0/24` form (if ipv4 + netmask exist)."""
        if not self.ipv4 or not self.netmask:
            return None
        try:
            net = ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False)
            return str(net)
        except ValueError:
            return None

    @property
    def prefixlen(self) -> int | None:
        """The IPv4 prefix length (`/24`). None if there is no mask.

        Needed for display next to the gateway: `10.0.0.1/24` tells you the size
        of the network at a glance (254 hosts), whereas `/23` means 510 — which
        immediately means something when sizing up a scan or a DHCP pool.
        """
        if not self.ipv4 or not self.netmask:
            return None
        try:
            return ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False).prefixlen
        except ValueError:
            return None

    @property
    def host_count(self) -> int | None:
        """The maximum number of hosts on the network (network/broadcast excluded)."""
        plen = self.prefixlen
        if plen is None:
            return None
        return max((1 << (32 - plen)) - 2, 0)

    @property
    def ipv6_global(self) -> list[str]:
        """Global/ULA IPv6 addresses (not link-local) — the ones that pass the router."""
        out: list[str] = []
        for addr, _plen in self.ipv6:
            try:
                obj = ipaddress.IPv6Address(addr.split("%")[0])
            except ValueError:
                continue
            if not obj.is_link_local:
                out.append(addr)
        return out

    @property
    def ipv6_link_local(self) -> list[str]:
        """fe80::/10 addresses — they only work within this segment."""
        glob = set(self.ipv6_global)
        return [a for a, _ in self.ipv6 if a not in glob]

    @property
    def ipv6_cidrs(self) -> list[str]:
        """Global IPv6 networks (`2001:db8:1::/64`) — link-local ones filtered out."""
        out: list[str] = []
        for addr, plen in self.ipv6:
            bare = addr.split("%")[0]
            try:
                obj = ipaddress.IPv6Address(bare)
                if obj.is_link_local:
                    continue
                net = str(ipaddress.ip_network(f"{bare}/{plen}", strict=False))
            except ValueError:
                continue
            if net not in out:
                out.append(net)
        return out

    @property
    def has_dual_stack(self) -> bool:
        """Are both IPv4 and a global IPv6 present (a full dual stack)?"""
        return bool(self.ipv4) and bool(self.ipv6_global)


def _v6_prefixlen(netmask: str | None) -> int:
    """Converts an IPv6 mask into a prefix length — a pure function.

    psutil gives it differently depending on the platform:
    `ffff:ffff:ffff:ffff::` (a mask) or `64` (a length) or `None`. If it cannot
    be determined, 64 is returned — that is the de facto standard segment size
    in IPv6.
    """
    if not netmask:
        return 64
    text = str(netmask).strip()
    if text.isdigit():
        return max(0, min(int(text), 128))
    try:
        packed = ipaddress.IPv6Address(text).packed
    except ValueError:
        return 64
    bits = 0
    for byte in packed:
        if byte == 0xFF:
            bits += 8
            continue
        while byte & 0x80:
            bits += 1
            byte = (byte << 1) & 0xFF
        break
    return bits


def list_interfaces(include_loopback: bool = False) -> list[Interface]:
    """Returns the system's network interfaces together with their IPv4 details."""
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
            elif addr.family == socket.AF_INET6:
                # psutil may give the IPv6 mask either as `ffff:ffff:...` or as
                # a prefix length — we accept both.
                iface.ipv6.append((addr.address, _v6_prefixlen(addr.netmask)))
            elif addr.family == psutil.AF_LINK:
                iface.mac = addr.address

        if name in stats:
            iface.is_up = stats[name].isup
            iface.speed_mbps = stats[name].speed

        # We accept an interface if it has an IPv4 OR an IPv6 address. Requiring
        # IPv4 made an IPv6-only network completely invisible.
        if iface.ipv4 or iface.ipv6:
            result.append(iface)

    return result


def default_gateway() -> str | None:
    """Takes the default gateway IP address from the OS routing table."""
    system = platform.system()
    try:
        if system == "Windows":
            return _default_gateway_windows()

        if system == "Linux":
            raw = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                timeout=3,
            ).stdout
            out = _platform.decode_console(raw)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None

        # macOS / BSD
        raw = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            timeout=3,
        ).stdout
        out = _platform.decode_console(raw)
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)

        # A universal fallback: the netstat routing table
        raw = subprocess.run(["netstat", "-rn"], capture_output=True, timeout=3).stdout
        out = _platform.decode_console(raw)
        for line in out.splitlines():
            if line.split()[:1] == ["default"]:
                parts = line.split()
                if len(parts) > 1 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[1]):
                    return parts[1]
    except (subprocess.SubprocessError, OSError, IndexError):
        return None
    return None


def _default_gateway_windows() -> str | None:
    """The Windows default gateway: with several fallbacks (route print -> netsh).

    1) The `0.0.0.0 0.0.0.0 <gw>` line in the IPv4 routing table of
       `route print -4` — the most reliable and the least dependent on the
       system locale.
    2) Fallback: the NextHop of `Get-NetRoute -DestinationPrefix 0.0.0.0/0`
       (PowerShell).

    An error at any step (command missing / timeout) moves on to the next one;
    if nothing is found, None.
    """
    # 1) route print -4
    try:
        raw = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            timeout=3,
            creationflags=_platform.subprocess_flags(),
        ).stdout
        out = _platform.decode_console(raw)
        gw = _platform.parse_windows_route_print(out)
        if gw:
            return gw
    except (subprocess.SubprocessError, OSError):
        pass

    # 2) Fallback: PowerShell Get-NetRoute (we print the NextHop column only).
    try:
        raw = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                "| Sort-Object RouteMetric "
                "| Select-Object -First 1 -ExpandProperty NextHop)",
            ],
            capture_output=True,
            timeout=5,
            creationflags=_platform.subprocess_flags(),
        ).stdout
        out = _platform.decode_console(raw)
        m = _platform._WIN_NETROUTE_NEXTHOP_RE.search(out)
        if m and m.group(1) != "0.0.0.0":
            return m.group(1)
    except (subprocess.SubprocessError, OSError):
        pass

    return None


def _is_apipa(ipv4: str | None) -> bool:
    """True if the IPv4 address is APIPA/link-local (169.254.0.0/16) or invalid.

    APIPA is the "not connected" address Windows assigns itself when DHCP does
    not answer; such an interface cannot be the primary one. A `None`/broken IP
    is no good as a primary either (it returns True too).
    """
    if not ipv4:
        return True
    try:
        addr = ipaddress.ip_address(ipv4)
    except ValueError:
        return True
    return bool(addr.is_link_local)


def default_gateway_v6() -> str | None:
    """The IPv6 default gateway (with its zone if it is link-local). None if not found.

    It is needed separately from the IPv4 gateway: on a dual-stack network they
    may be different devices, and a broken IPv6 route is invisible while IPv4
    still works — that exact situation is the reason behind "some sites are
    slow".
    """
    try:
        out = subprocess.run(
            ["netstat", "-rn", "-f", "inet6"]
            if not _IS_WINDOWS_NETINFO
            else ["route", "print", "-6"],
            capture_output=True,
            timeout=6,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    text = out.decode("utf-8", errors="replace")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("default", "::/0"):
            gw = parts[1]
            if ":" in gw:
                return gw
    return None


def primary_interface() -> Interface | None:
    """The primary interface — the one on the same network as the default gateway.

    The selection order:
      1. The interface whose network contains the gateway IP (the most reliable);
      2. Otherwise — the first NON-APIPA interface (not 169.254.x, not
         link-local) (to avoid Hyper-V vEthernet APIPA / disconnected adapters);
      3. If nothing is found — the first interface (the last resort).

    `list_interfaces` is unchanged (it returns every interface) — the filter
    applies only here, when picking the primary one.
    """
    gw = default_gateway()
    ifaces = list_interfaces()
    if gw:
        try:
            gw_addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(gw)
        except ValueError:
            # A broken/unexpected gateway string — fall through to the
            # APIPA-filtered fallback.
            gw_addr = None
        if gw_addr is not None:
            for iface in ifaces:
                cidr = iface.cidr
                if cidr and gw_addr in ipaddress.ip_network(cidr):
                    return iface
    # The gateway did not match -> we prefer the first NON-APIPA interface.
    for iface in ifaces:
        if not _is_apipa(iface.ipv4):
            return iface
    # If everything is APIPA/broken — the first one, as a last resort.
    return ifaces[0] if ifaces else None


async def public_ip(timeout: float = 5.0) -> str | None:
    """Determines the external (public) IP address over HTTP."""
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
    """An aggregate view of the local network state."""

    interfaces: list[Interface] = field(default_factory=list)
    gateway: str | None = None
    public_ip: str | None = None


async def gather_summary() -> NetSummary:
    """Collects the interfaces, the gateway and the public IP into one object."""
    return NetSummary(
        interfaces=list_interfaces(),
        gateway=default_gateway(),
        public_ip=await public_ip(),
    )
