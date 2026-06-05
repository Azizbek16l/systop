"""Tarmoq topologiyasi: global yo'l (traceroute) + lokal hostlar (LAN discovery).

traceroute  — `icmplib.traceroute` (sinxron) thread'da ishlatiladi; har bir
              "hop" — yo'ldagi marshrutizator.
discover_lan — lokal /24 tarmoqni ping sweep qilib, tirik hostlarni topadi,
              keyin OS ARP jadvalidan MAC manzillarni qo'shadi. Root kerak emas.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import subprocess
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from icmplib import async_multiping
from icmplib import traceroute as _sync_traceroute
from icmplib.exceptions import ICMPLibError, NameLookupError

from systop.core import netinfo, oui

_ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")
_NEIGH_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+)")


@runtime_checkable
class _HopLike(Protocol):
    """`icmplib.traceroute` qaytaradigan hop obyektining minimal interfeysi.

    Faqat shu modul o'qiydigan atributlar. Protocol typing'ni mypy-toza qiladi:
    `icmplib` aniq tiplarni eksport qilmaydi, biz esa duck-typing ishlatamiz
    (test'da `FakeRawHop` ham shu shaklga mos keladi).
    """

    @property
    def distance(self) -> int: ...

    @property
    def address(self) -> str | None: ...

    @property
    def avg_rtt(self) -> float: ...

    @property
    def is_alive(self) -> bool: ...


@dataclass(slots=True)
class Hop:
    """traceroute'dagi bitta hop (marshrutizator)."""

    index: int
    address: str | None
    hostname: str | None = None
    rtt_ms: float = 0.0
    alive: bool = False


@dataclass(slots=True)
class TraceResult:
    """traceroute natijasi: hop'lar + xato (agar bo'lsa, o'zbekcha)."""

    address: str
    hops: list[Hop]
    error: str | None = None


@dataclass(slots=True)
class LanHost:
    """Lokal tarmoqdagi bitta topilgan host."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    rtt_ms: float = 0.0
    is_gateway: bool = False
    vendor: str | None = None  # MAC OUI'dan aniqlangan ishlab chiqaruvchi


@dataclass(slots=True)
class HopStat:
    """`trace_stream` uchun bitta hop bo'yicha jamlanma statistika (mtr uslubi).

    Yo'l qayta-qayta probe qilinadi; har hop bo'yicha yuborilgan/qabul qilingan
    paketlar va RTT statistikasi (oxirgi/o'rtacha/eng yaxshi/eng yomon) jonli
    yangilanib boriladi.
    """

    index: int
    address: str | None = None
    hostname: str | None = None
    sent: int = 0
    recv: int = 0
    last_rtt: float = 0.0
    avg_rtt: float = 0.0
    best_rtt: float = 0.0
    worst_rtt: float = 0.0
    _rtt_sum: float = 0.0  # ichki: avg hisoblash uchun

    @property
    def loss_pct(self) -> float:
        """Paket yo'qotish foizi (0..100)."""
        if self.sent == 0:
            return 0.0
        return (self.sent - self.recv) / self.sent * 100.0

    def update(self, address: str | None, alive: bool, rtt: float) -> None:
        """Bitta probe natijasi bilan hop statistikasini yangilaydi."""
        self.sent += 1
        if address and self.address is None:
            self.address = address
        if not alive or rtt <= 0:
            return
        self.recv += 1
        self.last_rtt = rtt
        self._rtt_sum += rtt
        self.avg_rtt = self._rtt_sum / self.recv
        self.worst_rtt = max(self.worst_rtt, rtt)
        self.best_rtt = rtt if self.best_rtt == 0.0 else min(self.best_rtt, rtt)


async def traceroute(
    address: str,
    first_hop: int = 1,
    max_hops: int = 30,
    timeout: float = 2.0,
    privileged: bool = False,
    resolve: bool = True,
) -> list[Hop]:
    """Berilgan manzilgacha bo'lgan yo'lni (hop'larni) qaytaradi.

    `icmplib.traceroute` sinxron bo'lgani uchun thread'da ishlatamiz, shunda
    event loop bloklanmaydi. Xatolarga chidamli: resolve bo'lmasa yoki yo'lda
    uzilish bo'lsa, bo'sh yoki qisman ro'yxat qaytaradi (istisno ko'tarmaydi).
    """
    result = await trace_path(
        address,
        first_hop=first_hop,
        max_hops=max_hops,
        timeout=timeout,
        privileged=privileged,
        resolve=resolve,
    )
    return result.hops


async def trace_path(
    address: str,
    first_hop: int = 1,
    max_hops: int = 30,
    timeout: float = 2.0,
    privileged: bool = False,
    resolve: bool = True,
) -> TraceResult:
    """`traceroute` ning xato-xabarli varianti: TraceResult qaytaradi.

    Resolve bo'lmasa yoki ICMP xatosi bo'lsa, `error` maydoni o'zbekcha xabar
    bilan to'ldiriladi va `hops` bo'sh bo'ladi (CLI buni ko'rsata oladi).
    """
    try:
        raw_hops = await asyncio.to_thread(
            _sync_traceroute,
            address,
            first_hop=first_hop,
            max_hops=max_hops,
            timeout=timeout,
            privileged=privileged,
        )
    except NameLookupError:
        return TraceResult(
            address=address,
            hops=[],
            error=f"'{address}' nomini IP manzilga aylantirib bo'lmadi (DNS xato).",
        )
    except ICMPLibError as exc:
        return TraceResult(
            address=address,
            hops=[],
            error=f"Traceroute bajarilmadi: {exc}",
        )
    except OSError as exc:
        return TraceResult(address=address, hops=[], error=f"Tarmoq xatosi: {exc}")

    hops: list[Hop] = []
    for h in raw_hops:
        hop = Hop(
            index=h.distance,
            address=h.address,
            rtt_ms=h.avg_rtt,
            alive=h.is_alive,
        )
        if resolve and hop.address:
            hop.hostname = await _reverse_dns(hop.address)
        hops.append(hop)
    return TraceResult(address=address, hops=hops)


async def _probe_path(
    address: str,
    first_hop: int,
    max_hops: int,
    timeout: float,
    privileged: bool,
) -> list[_HopLike]:
    """Bitta probe: `icmplib.traceroute`ni thread'da chaqirib, xom hop'larni qaytaradi.

    Xato (DNS/ICMP/OS) bo'lsa bo'sh ro'yxat qaytaradi — istisno ko'tarmaydi,
    chunki `trace_stream` ni uzmasligi kerak (oqim davom etadi).
    """
    try:
        raw_hops = await asyncio.to_thread(
            _sync_traceroute,
            address,
            first_hop=first_hop,
            max_hops=max_hops,
            timeout=timeout,
            privileged=privileged,
        )
    except (ICMPLibError, OSError):
        return []
    return list(raw_hops)


async def trace_stream(
    address: str,
    first_hop: int = 1,
    max_hops: int = 30,
    timeout: float = 2.0,
    privileged: bool = False,
    resolve: bool = True,
    interval: float = 1.0,
    cycles: int | None = None,
) -> AsyncIterator[list[HopStat]]:
    """mtr/trippy uslubidagi jonli traceroute: yo'lni qayta-qayta probe qiladi.

    Har `interval` soniyada butun yo'lni qaytadan o'lchaydi va har hop bo'yicha
    jamlanma `HopStat` (sent, recv, loss%, last/avg/best/worst rtt) ni yangilab,
    ro'yxat ko'rinishida `yield` qiladi. Chaqiruvchi har iteratsiyada eng so'nggi
    holatni oladi.

    `cycles` — necha marta probe qilish (None bo'lsa cheksiz; to'xtatish
    chaqiruvchida CancelledError orqali). `index` (hop masofasi) bo'yicha
    barqaror kalitlangan — yo'l o'zgarsa ham statistika to'planib boradi.

    Eslatma: birinchi `yield`gacha bitta to'liq probe kutiladi (yo'l aniqlanishi
    uchun). Reverse DNS faqat birinchi marta ko'rilgan manzil uchun bajariladi.
    """
    stats: dict[int, HopStat] = {}
    cycle = 0
    while cycles is None or cycle < cycles:
        start = asyncio.get_running_loop().time()
        raw_hops = await _probe_path(address, first_hop, max_hops, timeout, privileged)
        for h in raw_hops:
            idx = h.distance
            stat = stats.get(idx)
            if stat is None:
                stat = HopStat(index=idx)
                stats[idx] = stat
            had_address = stat.address is not None
            stat.update(h.address, h.is_alive, h.avg_rtt)
            if resolve and stat.address and not had_address and stat.hostname is None:
                stat.hostname = await _reverse_dns(stat.address)
        ordered = [stats[i] for i in sorted(stats)]
        yield ordered

        cycle += 1
        if cycles is not None and cycle >= cycles:
            break
        elapsed = asyncio.get_running_loop().time() - start
        sleep_for = interval - elapsed
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


async def discover_lan(
    cidr: str | None = None,
    timeout: float = 1.0,
    max_hosts: int = 256,
    resolve: bool = False,
) -> list[LanHost]:
    """Lokal tarmoqdagi tirik hostlarni topadi (ping sweep + ARP jadval)."""
    if cidr is None:
        iface = netinfo.primary_interface()
        cidr = iface.cidr if iface else None
    if not cidr:
        return []

    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()][:max_hosts]
    if not hosts:
        return []

    gateway = netinfo.default_gateway()
    results = await async_multiping(hosts, count=1, timeout=timeout, privileged=False)
    arp_table = _parse_arp_table()

    found: list[LanHost] = []
    for host in results:
        if not host.is_alive:
            continue
        mac = arp_table.get(host.address)
        entry = LanHost(
            ip=host.address,
            mac=mac,
            rtt_ms=host.avg_rtt,
            is_gateway=(host.address == gateway),
            vendor=oui.lookup_vendor(mac),
        )
        if resolve:
            entry.hostname = await _reverse_dns(host.address)
        found.append(entry)

    # ARP jadvalida bor, lekin ping'ga javob bermagan hostlarni ham qo'shamiz.
    seen = {h.ip for h in found}
    for ip, mac in arp_table.items():
        if ip not in seen and ipaddress.ip_address(ip) in network:
            found.append(
                LanHost(
                    ip=ip,
                    mac=mac,
                    is_gateway=(ip == gateway),
                    vendor=oui.lookup_vendor(mac),
                )
            )

    found.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return found


def _parse_arp_table() -> dict[str, str]:
    """OS ARP jadvalidan {ip: mac} lug'atini o'qiydi (macOS/Linux)."""
    table: dict[str, str] = {}
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
        except (subprocess.SubprocessError, OSError):
            continue
        for line in out.splitlines():
            m = _ARP_RE.search(line) or _NEIGH_RE.search(line)
            if m:
                table[m.group(1)] = m.group(2).lower()
        if table:
            break
    return table


async def _reverse_dns(address: str, timeout: float = 1.0) -> str | None:
    """Best-effort reverse DNS (PTR) — xatolar yutiladi."""
    try:
        result = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, address), timeout)
        return result[0]
    except (TimeoutError, socket.herror, socket.gaierror, OSError):
        return None
