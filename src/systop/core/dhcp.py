"""DHCP server aniqlash — "rogue DHCP" ni topish. Root kerak emas (chegarasi bilan).

Nima uchun sysadmin uchun muhim: tarmoqda **ikkinchi DHCP server** paydo
bo'lishi eng ko'p uchraydigan va eng chalg'ituvchi uzilish sabablaridan biri —

  * kimdir uy routerini LAN portiga ulab qo'yadi va u DHCP bera boshlaydi;
  * qurilmalar tasodifiy ravishda **noto'g'ri gateway/DNS** oladi;
  * alomat: "ba'zi kompyuterlarda internet bor, ba'zilarida yo'q", qayta
    ulanganda tuzalib qoladi — chunki qaysi server tezroq javob bergani
    tasodifiy;
  * ping/DNS diagnostikasi buni ko'rsatmaydi, chunki muammo **konfiguratsiya
    manbasida**, ulanishda emas.

## Halol chegara (root'siz)

To'g'ri DHCP mijozi 68-portga bog'lanadi, lekin 1024 dan kichik port root
talab qiladi. Shuning uchun bu modul **ephemeral portdan** `255.255.255.255:67`
ga DISCOVER yuboradi (`dhcping` shu usulni ishlatadi). Ko'p server (ISC dhcpd,
dnsmasq, Kerio, Windows DHCP) javobni **so'rov kelgan portga** qaytaradi va biz
uni ko'ramiz. Ammo qat'iy RFC 2131 xulqidagi server javobni faqat 68-portga
yuboradi — bunda javob ko'rinmaydi. Ya'ni: **javob kelsa ishonchli, kelmasa
"server yo'q" degani EMAS.** Natijada shu holat aniq ajratiladi
(`replies` bo'sh + `partial=True`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from systop.core import _platform

DHCP_SERVER_PORT = 67
BOOTP_REPLY = 2
MAGIC_COOKIE = b"\x63\x82\x53\x63"

# Bizga kerakli DHCP opsiyalari (RFC 2132).
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_DOMAIN = 15

MSG_DISCOVER = 1
MSG_OFFER = 2

_MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}


@dataclass(slots=True)
class DhcpOffer:
    """Bitta DHCP serverdan kelgan taklif."""

    server_ip: str  # paket kelgan manzil
    server_id: str | None = None  # option 54 (haqiqiy server identifikatori)
    offered_ip: str | None = None
    subnet_mask: str | None = None
    routers: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    domain: str | None = None
    lease_seconds: int | None = None
    msg_type: str | None = None
    elapsed_ms: float = 0.0

    @property
    def identity(self) -> str:
        """Serverni ajratish kaliti — server_id bo'lsa u, aks holda manba IP."""
        return self.server_id or self.server_ip


@dataclass(slots=True)
class DhcpReport:
    """Barcha javoblar + xulosa."""

    offers: list[DhcpOffer] = field(default_factory=list)
    listened_s: float = 0.0
    partial: bool = False  # javob kelmadi, lekin bu "server yo'q" degani emas
    error: str | None = None

    @property
    def servers(self) -> list[str]:
        """Takrorsiz server identifikatorlari."""
        out: list[str] = []
        for o in self.offers:
            if o.identity not in out:
                out.append(o.identity)
        return out

    @property
    def is_rogue_suspected(self) -> bool:
        """Bir nechta turli server javob bergan bo'lsa — rogue DHCP ehtimoli."""
        return len(self.servers) > 1


def build_discover(mac: bytes | None = None, xid: int | None = None) -> tuple[bytes, int]:
    """DHCPDISCOVER paketini yasaydi. Qaytaradi: `(paket, xid)` — SOF funksiya.

    `xid` — tranzaksiya identifikatori; javobni o'zimizniki ekanini tekshirish
    uchun kerak (boshqa mijozning broadcast javobini o'zimizga hisoblab
    qo'ymaslik uchun).
    """
    if mac is None:
        # Lokal-tayinlangan tasodifiy MAC (birinchi bayt: unicast + local bit).
        mac = bytes([0x02]) + bytes(random.randrange(256) for _ in range(5))
    if xid is None:
        xid = random.randrange(1, 0xFFFFFFFF)

    pkt = bytearray()
    pkt += struct.pack("!BBBB", 1, 1, 6, 0)  # op=BOOTREQUEST, htype=Ethernet, hlen=6, hops=0
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)  # secs=0, flags=BROADCAST
    pkt += b"\x00" * 16  # ciaddr, yiaddr, siaddr, giaddr
    pkt += mac + b"\x00" * (16 - len(mac))  # chaddr
    pkt += b"\x00" * 64  # sname
    pkt += b"\x00" * 128  # file
    pkt += MAGIC_COOKIE
    pkt += bytes([OPT_MSG_TYPE, 1, MSG_DISCOVER])
    # Qaysi opsiyalarni so'raymiz (option 55).
    pkt += bytes([55, 4, OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_DOMAIN])
    pkt += b"\xff"  # END
    return bytes(pkt), xid


def parse_offer(data: bytes, source_ip: str, expect_xid: int | None = None) -> DhcpOffer | None:
    """DHCP javob paketini parse qiladi — SOF funksiya (offline test).

    `expect_xid` berilsa va mos kelmasa `None` qaytadi (boshqa mijozning
    javobini o'zimizga hisoblab qo'ymaslik uchun).
    """
    if len(data) < 240 or data[0] != BOOTP_REPLY:
        return None
    xid = struct.unpack("!I", data[4:8])[0]
    if expect_xid is not None and xid != expect_xid:
        return None
    if data[236:240] != MAGIC_COOKIE:
        return None

    offer = DhcpOffer(server_ip=source_ip)
    yiaddr = data[16:20]
    if yiaddr != b"\x00\x00\x00\x00":
        offer.offered_ip = str(ipaddress.IPv4Address(yiaddr))

    i = 240
    while i < len(data):
        code = data[i]
        if code == 0xFF:  # END
            break
        if code == 0:  # PAD
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        val = data[i + 2 : i + 2 + length]
        if len(val) < length:
            break
        if code == OPT_MSG_TYPE and length == 1:
            offer.msg_type = _MSG_NAMES.get(val[0], str(val[0]))
        elif code == OPT_SERVER_ID and length == 4:
            offer.server_id = str(ipaddress.IPv4Address(val))
        elif code == OPT_SUBNET_MASK and length == 4:
            offer.subnet_mask = str(ipaddress.IPv4Address(val))
        elif code == OPT_ROUTER:
            offer.routers = [
                str(ipaddress.IPv4Address(val[j : j + 4])) for j in range(0, length - 3, 4)
            ]
        elif code == OPT_DNS:
            offer.dns = [
                str(ipaddress.IPv4Address(val[j : j + 4])) for j in range(0, length - 3, 4)
            ]
        elif code == OPT_DOMAIN:
            offer.domain = val.decode("utf-8", "replace").rstrip("\x00") or None
        elif code == OPT_LEASE_TIME and length == 4:
            offer.lease_seconds = struct.unpack("!I", val)[0]
        i += 2 + length
    return offer


async def discover_servers(listen_s: float = 4.0) -> DhcpReport:
    """DHCPDISCOVER yuborib, kelgan barcha javoblarni yig'adi.

    Bir nechta javob kelsa — tarmoqda bir nechta DHCP server bor (rogue
    ehtimoli). Javob kelmasa `partial=True` — modul docstring'idagi chegaraga
    qarang, bu "server yo'q" degani emas.
    """
    report = DhcpReport(listened_s=listen_s)
    loop = asyncio.get_running_loop()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))  # ephemeral port — 68 root talab qiladi
        sock.setblocking(False)

        packet, xid = build_discover()
        start = time.perf_counter()
        await loop.sock_sendto(sock, packet, ("255.255.255.255", DHCP_SERVER_PORT))

        deadline = start + listen_s
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), timeout=remaining
                )
            except TimeoutError:
                break
            offer = parse_offer(data, addr[0], expect_xid=xid)
            if offer is not None:
                offer.elapsed_ms = (time.perf_counter() - start) * 1000.0
                report.offers.append(offer)
    except OSError as exc:
        report.error = f"socket xatosi: {exc.strerror or exc}"
        return report
    finally:
        if sock is not None:
            sock.close()

    report.partial = not report.offers
    return report


# ===========================================================================
# Faol lease'ni o'qish — root'siz ISHONCHLI yo'l
# ===========================================================================
#
# Broadcast probe (yuqorida) qat'iy RFC 2131 serverida javob olmaydi. Ammo
# OS'ning O'ZI allaqachon DHCP'dan manzil olgan va **qaysi server** bergani
# lease ma'lumotida saqlangan. Uni o'qish root talab qilmaydi.
#
# Amaliy foyda: "men kutgan serverdan manzil oldimmi?" — rogue DHCP'ning eng
# muhim alomati aynan shu. Bu javob bermagan rogue serverni topmaydi, lekin
# manzilni ALLAQACHON noto'g'ri server berganini aniq ko'rsatadi.

_GETPACKET_RE = re.compile(r"^\s*(\w+)\s*(?:\([^)]*\))?\s*[:=]\s*(.+?)\s*$")


def parse_ipconfig_getpacket(text: str) -> DhcpOffer | None:
    """macOS `ipconfig getpacket <iface>` chiqishini parse qiladi — SOF funksiya."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        m = _GETPACKET_RE.match(line)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip()
    server = fields.get("server_identifier")
    if not server:
        return None

    def _ips(raw: str | None) -> list[str]:
        if not raw:
            return []
        return [p for p in re.findall(r"\d+\.\d+\.\d+\.\d+", raw)]

    lease_raw = fields.get("lease_time")
    lease: int | None = None
    if lease_raw:
        try:
            lease = int(lease_raw, 16) if lease_raw.lower().startswith("0x") else int(lease_raw)
        except ValueError:
            lease = None

    return DhcpOffer(
        server_ip=server,
        server_id=server,
        offered_ip=(_ips(fields.get("yiaddr")) or [None])[0],
        subnet_mask=(_ips(fields.get("subnet_mask")) or [None])[0],
        routers=_ips(fields.get("router")),
        dns=_ips(fields.get("domain_name_server")),
        domain=fields.get("domain_name") or None,
        lease_seconds=lease,
        msg_type="ACK (faol lease)",
    )


def parse_dhclient_lease(text: str) -> DhcpOffer | None:
    """Linux `dhclient.leases` faylidan ENG OXIRGI lease'ni oladi — SOF funksiya.

    Fayl lease bloklarini ketma-ket yozadi, oxirgisi joriy hisoblanadi.
    """
    blocks = re.findall(r"lease\s*\{(.*?)\}", text, re.DOTALL)
    if not blocks:
        return None
    body = blocks[-1]

    def opt(name: str) -> str | None:
        m = re.search(rf"option\s+{name}\s+([^;]+);", body)
        return m.group(1).strip() if m else None

    server = opt("dhcp-server-identifier")
    if not server:
        return None
    fixed = re.search(r"fixed-address\s+([^;]+);", body)
    lease_raw = opt("dhcp-lease-time")
    return DhcpOffer(
        server_ip=server,
        server_id=server,
        offered_ip=fixed.group(1).strip() if fixed else None,
        subnet_mask=opt("subnet-mask"),
        routers=re.findall(r"\d+\.\d+\.\d+\.\d+", opt("routers") or ""),
        dns=re.findall(r"\d+\.\d+\.\d+\.\d+", opt("domain-name-servers") or ""),
        domain=(opt("domain-name") or "").strip('"') or None,
        lease_seconds=int(lease_raw) if lease_raw and lease_raw.isdigit() else None,
        msg_type="ACK (faol lease)",
    )


async def current_lease(interface: str | None = None) -> DhcpOffer | None:
    """Bu host manzilni QAYSI DHCP serverdan olganini aytadi (root kerak emas).

    macOS: `ipconfig getpacket <iface>`. Linux: dhclient lease fayllari.
    Windows: `ipconfig /all` da "DHCP Server" qatori.
    Topilmasa None (statik IP yoki lease ma'lumoti yo'q).
    """
    if interface is None:
        from systop.core import netinfo

        iface = netinfo.primary_interface()
        interface = iface.name if iface else None
    if not interface:
        return None

    if _platform.IS_MACOS:
        out = await _platform.run_command(["ipconfig", "getpacket", interface], timeout=5.0)
        return parse_ipconfig_getpacket(out) if out else None

    if _platform.IS_WINDOWS:
        out = await _platform.run_command(["ipconfig", "/all"], timeout=8.0)
        if not out:
            return None
        m = re.search(r"DHCP Server[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
        return DhcpOffer(server_ip=m.group(1), server_id=m.group(1),
                         msg_type="ACK (faol lease)") if m else None

    # Linux — keng tarqalgan lease yo'llari.
    for path in (
        "/var/lib/dhcp/dhclient.leases",
        f"/var/lib/dhcp/dhclient.{interface}.leases",
        "/var/lib/dhclient/dhclient.leases",
    ):
        try:
            # Fayl o'qish bloklaydi — event loop'ni ushlab qolmaslik uchun
            # thread'da bajaramiz (lease fayllari kichik, lekin sekin diskda
            # ham loop to'xtamasligi kerak).
            text = await asyncio.to_thread(
                lambda p=path: Path(p).read_text(encoding="utf-8", errors="replace")
            )
            parsed = parse_dhclient_lease(text)
        except OSError:
            continue
        if parsed:
            return parsed
    return None
