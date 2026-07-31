"""Marshrut jadvali va next-hop yetishuvi. Root kerak emas.

Nima uchun kerak: "internet ishlamayapti" shikoyatining bir qismi marshrut
muammosi bo'ladi va u ping/DNS bilan ko'rinmaydi —

  * **default marshrut yo'q** — hamma narsa lokal LAN'da qoladi;
  * **ikkita default marshrut** (masalan Wi-Fi + VPN yoki ikki NIC) — trafik
    gohida bir yo'ldan, gohida boshqasidan ketadi. Alomat chalg'ituvchi:
    "ba'zan ishlaydi, ba'zan yo'q";
  * **next-hop o'lik** — jadval to'g'ri, lekin gateway javob bermaydi;
  * **VPN hammasini o'ziga tortgan** (0.0.0.0/1 + 128.0.0.0/1 nayrangi) — LAN
    resurslari yo'qoladi.

Jadval OS buyrug'idan o'qiladi (`netstat -rn` / `ip route` / `route print`),
parse'lar sof funksiya — offline sinaladi.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from systop.core import _platform

# macOS/BSD `netstat -rn` ustunlari:
#   Destination  Gateway  Flags  Netif  [Expire]
# ATAYLAB regex EMAS, ustunlarga bo'lish: oxirgi "Expire" ustuni bo'sh, raqam
# yoki `!` bo'lishi mumkin va qat'iy regex uni sig'dira olmasdi — natijada
# 93 qatordan 75 tasi JIMGINA tashlanardi (marshrut jadvali deyarli bo'sh
# ko'rinardi). Ustunlarga bo'lish bunday nozikliklarga chidamli.

# Gateway ustunidagi link-qatlam yozuvlari (haqiqiy next-hop emas):
#   "link#11", "0:15:5d:27:40:3" (MAC), "52:73:db:7e:48:af"
_LINK_LAYER_RE = re.compile(r"^(link#\d+|[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})$")
# Linux `ip route`: "default via 10.0.0.1 dev eth0 proto dhcp metric 100"
#                   "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5"
_IPROUTE_RE = re.compile(
    r"^(default|[0-9a-fA-F.:/]+)"
    r"(?:\s+via\s+(\S+))?"
    r"\s+dev\s+(\S+)"
    r"(?:.*?\bmetric\s+(\d+))?"
)
# Windows `route print` IPv4 bo'limi:
#   "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25"
_ROUTE_WIN_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$"
)


@dataclass(slots=True)
class Route:
    """Marshrut jadvalining bitta yozuvi."""

    destination: str  # "default" yoki CIDR
    gateway: str | None = None  # next-hop (link-local marshrutda None)
    interface: str | None = None
    metric: int | None = None
    family: str = "ipv4"

    @property
    def is_default(self) -> bool:
        return self.destination in ("default", "0.0.0.0/0", "::/0", "0.0.0.0")

    @property
    def is_vpn_split_hack(self) -> bool:
        """`0.0.0.0/1` + `128.0.0.0/1` — VPN default'ni "engish" nayrangi.

        Bu ikki marshrut birgalikda butun IPv4 fazosini qoplaydi va default'dan
        aniqroq (uzunroq prefiks) bo'lgani uchun ustun keladi. Jadvalda default
        turgan bo'lsa ham trafik VPN'ga ketadi — shuning uchun alohida
        belgilanadi.
        """
        return self.destination in ("0.0.0.0/1", "128.0.0.0/1")


@dataclass(slots=True)
class RouteTable:
    """Marshrut jadvali + xulosalar."""

    routes: list[Route] = field(default_factory=list)
    error: str | None = None

    @property
    def defaults(self) -> list[Route]:
        return [r for r in self.routes if r.is_default]

    @property
    def default_gateways(self) -> list[str]:
        """Takrorsiz default next-hop manzillari (hammasi, link-local ham)."""
        out: list[str] = []
        for r in self.defaults:
            if r.gateway and r.gateway not in out:
                out.append(r.gateway)
        return out

    @property
    def routable_defaults(self) -> list[Route]:
        """Faqat MA'NOLI default marshrutlar — bo'sh placeholder'lar tashlanadi.

        macOS'da har doim bir nechta `utun*` interfeysi bo'ladi (VPN/relay
        xizmatlari uchun) va ularning IPv6 default'i **yalang'och**
        `fe80::%utunN` ko'rinishida turadi — ya'ni interfeys-ID qismi butunlay
        nol. Bu haqiqiy qo'shni emas, joy egallab turuvchi yozuv; ping'ga
        hech qachon javob bermaydi. Ularni "o'lik gateway" yoki "bir nechta
        default marshrut" deb hisoblash **soxta signal** beradi.

        MUHIM: ajratish **link-local ekanligi** bo'yicha EMAS, **interfeys-ID
        nol** ekanligi bo'yicha. Chunki normal IPv6 tarmoqda default gateway
        aynan link-local bo'ladi — router RA'da o'zining `fe80::1%en0`
        manzilini e'lon qiladi. Link-local'ning hammasini tashlash IPv6-only
        hostda "Default marshrut yo'q" degan CRITICAL soxta xulosani berardi
        va IPv6 uchun "bir nechta default" tekshiruvi umuman ishlamasdi.
        """
        out: list[Route] = []
        for r in self.defaults:
            if not r.gateway:
                continue
            bare = r.gateway.split("%")[0]
            try:
                ip = ipaddress.ip_address(bare)
            except ValueError:
                out.append(r)
                continue
            if ip.version == 6 and ip.packed[8:] == b"\x00" * 8:
                continue  # yalang'och fe80:: / :: — haqiqiy next-hop emas
            if ip.is_unspecified:
                continue
            out.append(r)
        return out

    @property
    def routable_default_gateways(self) -> list[str]:
        """Ping qilinadigan holatdagi next-hop manzillari.

        Link-local manzil **zonasiz ishlatib bo'lmaydi** — `ping6 fe80::1`
        "No route to host" beradi, chunki OS qaysi interfeysdan chiqishni
        bilmaydi. macOS `netstat` zonani o'zi qo'shib beradi (`fe80::1%en0`),
        Linux `ip -6 route` esa alohida `dev eth0` ustunida beradi. Shuning
        uchun zona yo'q bo'lsa interfeys nomidan yasab qo'shamiz — aks holda
        sog'lom IPv6 gateway "o'lik" deb belgilanardi.
        """
        out: list[str] = []
        for r in self.routable_defaults:
            gw = r.gateway
            if gw is None:
                continue
            if "%" not in gw and r.interface:
                try:
                    if ipaddress.ip_address(gw).is_link_local:
                        gw = f"{gw}%{r.interface}"
                except ValueError:
                    pass
            if gw not in out:
                out.append(gw)
        return out

    def routable_defaults_for(self, family: str) -> list[Route]:
        """Bitta oila (`ipv4`/`ipv6`) bo'yicha ma'noli default'lar."""
        return [r for r in self.routable_defaults if r.family == family]

    @property
    def has_vpn_split_hack(self) -> bool:
        return any(r.is_vpn_split_hack for r in self.routes)


def _norm_dest(dest: str) -> str:
    """macOS qisqartirilgan tarmoqni to'liq CIDR'ga keltiradi ("192.168.10/23")."""
    if dest == "default":
        return "default"
    if "/" not in dest:
        return dest
    net, _, prefix = dest.partition("/")
    parts = net.split(".")
    if len(parts) < 4 and parts[0].isdigit():
        net = ".".join(parts + ["0"] * (4 - len(parts)))
    return f"{net}/{prefix}"


def parse_netstat(text: str) -> list[Route]:
    """macOS/BSD `netstat -rn` chiqishini parse qiladi — SOF funksiya.

    Ustunlar: `Destination Gateway Flags Netif [Expire]`. Oxirgi ustun ixtiyoriy
    va turli shaklda bo'ladi (raqam, `!`, bo'sh) — shuning uchun qat'iy regex
    emas, ustunlarga bo'lish ishlatiladi.

    Gateway ustunida `link#11` yoki MAC turishi mumkin — bu next-hop EMAS,
    balki shu segmentdagi to'g'ridan-to'g'ri yetishuv belgisi. Bunday
    yozuvlarda `gateway=None` bo'ladi.
    """
    routes: list[Route] = []
    family = "ipv4"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("internet6"):
            family = "ipv6"
            continue
        if low.startswith("internet"):
            family = "ipv4"
            continue
        if low.startswith(("destination", "routing tables")):
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue
        dest, gw = parts[0], parts[1]

        # Netif — flags'dan keyingi ustun. Expire ustuni bo'lishi/bo'lmasligi
        # mumkin, shuning uchun 4-ustunni olamiz (bor bo'lsa).
        iface = parts[3] if len(parts) >= 4 else None

        gateway: str | None = None
        if not _LINK_LAYER_RE.match(gw) and ("." in gw or ":" in gw):
            gateway = gw

        is_v6 = family == "ipv6" or (":" in dest and not _LINK_LAYER_RE.match(dest))
        routes.append(
            Route(
                destination=_norm_dest(dest),
                gateway=gateway,
                interface=iface,
                family="ipv6" if is_v6 else "ipv4",
            )
        )
    return routes


def parse_ip_route(text: str, family: str = "ipv4") -> list[Route]:
    """Linux `ip route` / `ip -6 route` chiqishini parse qiladi — SOF funksiya."""
    routes: list[Route] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("broadcast", "local", "unreachable")):
            continue
        m = _IPROUTE_RE.match(stripped)
        if not m:
            continue
        routes.append(
            Route(
                destination=m.group(1),
                gateway=m.group(2),
                interface=m.group(3),
                metric=int(m.group(4)) if m.group(4) else None,
                family=family,
            )
        )
    return routes


def parse_route_print(text: str) -> list[Route]:
    """Windows `route print` IPv4 jadvalini parse qiladi — SOF funksiya."""
    routes: list[Route] = []
    for line in text.splitlines():
        m = _ROUTE_WIN_RE.match(line)
        if not m:
            continue
        dest, mask, gw, iface, metric = m.groups()
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        except ValueError:
            continue
        gateway = gw if gw.count(".") == 3 else None  # "On-link" -> None
        routes.append(
            Route(
                destination="default" if dest == "0.0.0.0" and prefix == 0 else f"{dest}/{prefix}",
                gateway=gateway,
                interface=iface,
                metric=int(metric),
            )
        )
    return routes


async def list_routes() -> RouteTable:
    """OS marshrut jadvalini o'qiydi (macOS/Linux/Windows). Istisno ko'tarmaydi."""
    if _platform.IS_WINDOWS:
        out = await _platform.run_command(["route", "print", "-4"], timeout=8.0)
        if not out:
            return RouteTable(error="`route print` natija bermadi")
        return RouteTable(routes=parse_route_print(out))

    # Linux: `ip route` aniqroq (metric/dev), bo'lmasa `netstat -rn`.
    out = await _platform.run_command(["ip", "route"], timeout=8.0)
    if out:
        routes = parse_ip_route(out, "ipv4")
        out6 = await _platform.run_command(["ip", "-6", "route"], timeout=8.0)
        if out6:
            routes += parse_ip_route(out6, "ipv6")
        if routes:
            return RouteTable(routes=routes)

    out = await _platform.run_command(["netstat", "-rn"], timeout=8.0)
    if not out:
        return RouteTable(error="marshrut jadvalini o'qib bo'lmadi")
    return RouteTable(routes=parse_netstat(out))


async def check_next_hops(table: RouteTable, timeout: float = 2.0) -> dict[str, bool]:
    """Default next-hop'larning yetishuvini ping bilan tekshiradi.

    Qaytaradi: {gateway_ip: tirikmi}. Jadval to'g'ri, lekin gateway o'lik
    bo'lishi mumkin — bu holat faqat shu tekshiruvda ko'rinadi.

    Faqat `routable_default_gateways` tekshiriladi (link-local `utun*`
    marshrutlari soxta "o'lik" natija bermasligi uchun).
    """
    gws = table.routable_default_gateways
    if not gws:
        return {}
    from systop.core.ping import ping_many

    results = await ping_many({gw: gw for gw in gws}, count=2, timeout=timeout)
    return {r.address: r.alive for r in results}
