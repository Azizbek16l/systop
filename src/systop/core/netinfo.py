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

from systop.core import _platform

_IS_WINDOWS_NETINFO = platform.system() == "Windows"


@dataclass(slots=True)
class Interface:
    """Bitta tarmoq interfeysi."""

    name: str
    ipv4: str | None = None
    netmask: str | None = None
    mac: str | None = None
    is_up: bool = False
    speed_mbps: int = 0  # 0 => noma'lum
    # IPv6: `(manzil, prefiks_uzunligi)` juftliklari. Ro'yxat, chunki bitta
    # interfeysda bir vaqtda link-local + global + ULA + vaqtinchalik (privacy)
    # manzillar bo'lishi normal holat.
    ipv6: list[tuple[str, int]] = field(default_factory=list)

    @property
    def cidr(self) -> str | None:
        """`192.168.1.0/24` ko'rinishidagi IPv4 tarmoq (ipv4 + netmask bo'lsa)."""
        if not self.ipv4 or not self.netmask:
            return None
        try:
            net = ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False)
            return str(net)
        except ValueError:
            return None

    @property
    def prefixlen(self) -> int | None:
        """IPv4 prefiks uzunligi (`/24`). Maska bo'lmasa None.

        Gateway yonida ko'rsatish uchun kerak: `10.0.0.1/24` bir qarashda
        tarmoq hajmini aytadi (254 host), `/23` esa 510 — bu skan hajmini va
        DHCP pool kattaligini baholashda darhol ma'no beradi.
        """
        if not self.ipv4 or not self.netmask:
            return None
        try:
            return ipaddress.ip_network(f"{self.ipv4}/{self.netmask}", strict=False).prefixlen
        except ValueError:
            return None

    @property
    def host_count(self) -> int | None:
        """Tarmoqdagi maksimal host soni (tarmoq/broadcast chiqarilgan)."""
        plen = self.prefixlen
        if plen is None:
            return None
        return max((1 << (32 - plen)) - 2, 0)

    @property
    def ipv6_global(self) -> list[str]:
        """Global/ULA IPv6 manzillar (link-local emas) — routerdan o'tadiganlar."""
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
        """fe80::/10 manzillar — faqat shu segmentda ishlaydi."""
        glob = set(self.ipv6_global)
        return [a for a, _ in self.ipv6 if a not in glob]

    @property
    def ipv6_cidrs(self) -> list[str]:
        """Global IPv6 tarmoqlar (`2001:db8:1::/64`) — link-local chiqarib tashlangan."""
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
        """IPv4 va global IPv6 ikkalasi ham bormi (to'liq dual-stack)."""
        return bool(self.ipv4) and bool(self.ipv6_global)



def _v6_prefixlen(netmask: str | None) -> int:
    """IPv6 maskani prefiks uzunligiga aylantiradi — SOF funksiya.

    psutil platformaga qarab turlicha beradi: `ffff:ffff:ffff:ffff::` (mask)
    yoki `64` (uzunlik) yoki `None`. Aniqlanmasa 64 qaytadi — bu IPv6'da
    amaldagi standart segment o'lchami.
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
            elif addr.family == socket.AF_INET6:
                # psutil IPv6 maskani `ffff:ffff:...` yoki prefiks-uzunlik
                # sifatida berishi mumkin — ikkalasini ham qabul qilamiz.
                iface.ipv6.append((addr.address, _v6_prefixlen(addr.netmask)))
            elif addr.family == psutil.AF_LINK:
                iface.mac = addr.address

        if name in stats:
            iface.is_up = stats[name].isup
            iface.speed_mbps = stats[name].speed

        # IPv4 YOKI IPv6 manzili bo'lsa qabul qilamiz. Faqat IPv4 talab qilish
        # IPv6-only tarmoqni butunlay ko'rinmas qilardi.
        if iface.ipv4 or iface.ipv6:
            result.append(iface)

    return result


def default_gateway() -> str | None:
    """Default gateway IP manzilini OS marshrut jadvalidan oladi."""
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

        # Universal zaxira: netstat marshrut jadvali
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
    """Windows default gateway: bir nechta zaxira bilan (route print -> netsh).

    1) `route print -4` IPv4 marshrut jadvalidagi `0.0.0.0 0.0.0.0 <gw>` qatori
       — eng ishonchli va lokalizatsiyaga eng kam bog'liq.
    2) Zaxira: `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (PowerShell) NextHop.

    Har qadam xatosi (buyruq yo'q / timeout) keyingisiga o'tkazadi; hech narsa
    topilmasa None.
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

    # 2) Zaxira: PowerShell Get-NetRoute (faqat NextHop ustunini chiqaramiz).
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
    """IPv4 manzil APIPA/link-local (169.254.0.0/16) yoki noto'g'ri bo'lsa True.

    APIPA — DHCP javob bermaganda Windows o'zi tayinlaydigan "ulanmagan" manzil;
    bunday interfeys asosiy (primary) bo'la olmaydi. `None`/buzuq IP ham primary
    sifatida yaramaydi (True qaytaradi).
    """
    if not ipv4:
        return True
    try:
        addr = ipaddress.ip_address(ipv4)
    except ValueError:
        return True
    return bool(addr.is_link_local)



def default_gateway_v6() -> str | None:
    """IPv6 default gateway (link-local bo'lsa zonasi bilan). Topilmasa None.

    IPv4 gateway'dan alohida kerak: dual-stack tarmoqda ular boshqa qurilma
    bo'lishi mumkin, va IPv6 marshruti buzilgani IPv4 ishlab turganda
    ko'rinmaydi — aynan shu holat "ba'zi saytlar sekin" sababidir.
    """
    try:
        out = subprocess.run(
            ["netstat", "-rn", "-f", "inet6"] if not _IS_WINDOWS_NETINFO
            else ["route", "print", "-6"],
            capture_output=True, timeout=6,
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
    """Default gateway bilan bir tarmoqda turgan asosiy interfeys.

    Tanlash tartibi:
      1. Gateway IP'si kiradigan tarmoqdagi interfeys (eng ishonchli);
      2. Aks holda — birinchi NON-APIPA (169.254.x emas, link-local emas)
         interfeys (Hyper-V vEthernet APIPA / ulanmagan adapterlardan qochish);
      3. Hech narsa topilmasa — birinchi interfeys (oxirgi zaxira).

    `list_interfaces` o'zgarmaydi (u barcha interfeyslarni beradi) — filtr faqat
    shu yerda, primary tanlashda qo'llanadi.
    """
    gw = default_gateway()
    ifaces = list_interfaces()
    if gw:
        try:
            gw_addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(gw)
        except ValueError:
            # Buzuq/kutilmagan gateway satri — APIPA-filtrli fallback'ga tushamiz.
            gw_addr = None
        if gw_addr is not None:
            for iface in ifaces:
                cidr = iface.cidr
                if cidr and gw_addr in ipaddress.ip_network(cidr):
                    return iface
    # Gateway mos kelmadi -> birinchi NON-APIPA interfeysni afzal ko'ramiz.
    for iface in ifaces:
        if not _is_apipa(iface.ipv4):
            return iface
    # Hammasi APIPA/buzuq bo'lsa — oxirgi zaxira sifatida birinchisi.
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
