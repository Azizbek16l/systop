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

from systop.core import _platform, netinfo, oui

_ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")
_NEIGH_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+)")
# Windows `arp -a`: "  192.168.1.1    00-11-22-33-44-55     dynamic"
# MAC tire (-) bilan, 6 oktet; "static"/"dynamic" turi qatorda bo'ladi.
# Sarlavha ("Internet Address ... Physical Address") va invalid yozuvlar
# (MAC "ff-ff-ff-ff-ff-ff" broadcast yoki manzilsiz) mos kelmaydi.
_ARP_WIN_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
)


@runtime_checkable
class _HostLike(Protocol):
    """Ping host obyektining minimal interfeysi (`discover_lan` o'qiydigan).

    `icmplib` Host va Windows `_WinHost` ikkalasi ham shu shaklga mos keladi
    (duck typing) — shuning uchun `discover_lan` ikkala manbadan bir xil ishlaydi.
    """

    @property
    def address(self) -> str: ...

    @property
    def is_alive(self) -> bool: ...

    @property
    def avg_rtt(self) -> float: ...


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
    if _platform.IS_WINDOWS:
        raw_hops: list[_HopLike] = await _win_traceroute(
            address, max_hops=max_hops, timeout=timeout
        )
        if not raw_hops:
            return TraceResult(
                address=address,
                hops=[],
                error="Traceroute natija bermadi (host yetib bo'lmadi yoki nom resolve bo'lmadi).",
            )
        hops = await _map_hops(raw_hops, resolve=resolve)
        return TraceResult(address=address, hops=hops)

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

    hops = await _map_hops(raw_hops, resolve=resolve)
    return TraceResult(address=address, hops=hops)


async def _map_hops(raw_hops: list[_HopLike], resolve: bool) -> list[Hop]:
    """Xom hop obyektlarini (icmplib yoki Windows) `Hop` ro'yxatiga aylantiradi.

    `resolve` True bo'lsa, manzili bor hoplar uchun reverse DNS ham bajariladi.
    """
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
    return hops


async def _probe_path(
    address: str,
    first_hop: int,
    max_hops: int,
    timeout: float,
    privileged: bool,
) -> list[_HopLike]:
    """Bitta probe: `icmplib.traceroute`ni thread'da chaqirib, xom hop'larni qaytaradi.

    Xato (DNS/ICMP/OS) bo'lsa bo'sh ro'yxat qaytaradi — istisno ko'tarmaydi,
    chunki `trace_stream` ni uzmasligi kerak (oqim davom etadi). Windows'da
    `tracert` (admin shart emas) ishlatiladi; macOS/Linux'da `icmplib`.
    """
    if _platform.IS_WINDOWS:
        return await _win_traceroute(address, max_hops=max_hops, timeout=timeout)
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


@dataclass(slots=True)
class _WinRawHop:
    """Windows `tracert` hop'i — `_HopLike` (icmplib hop) bilan bir xil shakl.

    `_map_hops`/`trace_stream` faqat `distance`/`address`/`avg_rtt`/`is_alive`
    o'qiydi, shuning uchun shu to'rt atribut yetarli (duck typing).
    """

    distance: int
    address: str | None
    avg_rtt: float
    is_alive: bool


async def _win_traceroute(
    address: str,
    max_hops: int = 30,
    timeout: float = 2.0,
) -> list[_HopLike]:
    """Windows'da yo'lni o'lchaydi (admin shart emas).

    Ildiz yo'l: Win32 `IcmpSendEcho` + TTL (`_platform.win_icmp_traceroute`) —
    til/codepage'dan mustaqil, matn-parse'siz (IPv4).

    Zaxira yo'l: `IcmpSendEcho` yo'q yoki manzil IPv4'ga resolve bo'lmasa,
    `tracert -d -h <max_hops> -w <ms> <address>` chiqishini TIL-MUSTAQIL
    `parse_windows_tracert` bilan parse qilamiz. Har ikkala holatda `_WinRawHop`
    ro'yxati qaytadi (`_map_hops`/`trace_stream` shu shaklni o'qiydi). Hech narsa
    bo'lmasa — bo'sh ro'yxat.
    """
    # 1) Ildiz yo'l: IcmpSendEcho + TTL (IPv4, til/codepage'dan mustaqil).
    icmp = await asyncio.to_thread(_platform.win_icmp_traceroute, address, max_hops, timeout)
    if icmp is not None:
        return [
            _WinRawHop(distance=idx, address=addr, avg_rtt=rtt, is_alive=alive)
            for (idx, addr, rtt, alive) in icmp
        ]

    # 2) Zaxira yo'l: tizim `tracert.exe` + til-mustaqil parse.
    wait_ms = max(1, int(timeout * 1000))
    cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(wait_ms), address]
    # tracert har hop uchun `-w` kutishi mumkin -> umumiy timeout kengroq.
    overall = timeout * max_hops + 5.0
    out = await _platform.run_command(cmd, timeout=overall)
    if not out:
        return []
    parsed = _platform.parse_windows_tracert(out)
    return [
        _WinRawHop(distance=idx, address=addr, avg_rtt=rtt, is_alive=alive)
        for (idx, addr, rtt, alive) in parsed
    ]


@dataclass(slots=True)
class _WinHost:
    """Windows LAN sweep host natijasi — `_HostLike` shakliga mos (duck typing)."""

    address: str
    is_alive: bool
    avg_rtt: float = 0.0


# Windows LAN sweep'da parallel `ping` jarayonlari soni (resurs cheklash).
_WIN_SWEEP_CONCURRENCY = 64


async def _win_multiping(hosts: list[str], timeout: float) -> list[_HostLike]:
    """Windows'da /24 ping sweep: har host uchun bitta `ping -n 1` (concurrency cheklangan).

    `async_multiping`ning Windows o'rnini bosadi. `_win_ping` (ping.py) orqali
    har hostni alohida tekshiradi; semaphore bir vaqtdagi jarayonlar sonini
    cheklaydi (katta tarmoqda resurs portlashining oldini oladi).
    """
    # Kech import: ping <-> topology aylanma importining oldini oladi.
    from systop.core.ping import _win_ping

    sem = asyncio.Semaphore(_WIN_SWEEP_CONCURRENCY)

    async def probe(host: str) -> _WinHost:
        async with sem:
            alive, rtts, _loss = await _win_ping(host, count=1, timeout=timeout)
        avg = (sum(rtts) / len(rtts)) if rtts else 0.0
        return _WinHost(address=host, is_alive=alive, avg_rtt=avg)

    if not hosts:
        return []
    return await asyncio.gather(*(probe(h) for h in hosts))


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
    if _platform.IS_WINDOWS:
        results: list[_HostLike] = await _win_multiping(hosts, timeout=timeout)
    else:
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
    """OS ARP jadvalidan {ip: mac} lug'atini o'qiydi (Windows/macOS/Linux).

    macOS/Linux: `arp -a` (qavs ichida IP, ':' bilan MAC) yoki zaxira `ip neigh`.
    Windows: `arp -a` (tire bilan MAC, "dynamic/static" turi). MAC har holatda
    kichik harf + ':' separatorga normallashtiriladi (oui.lookup_vendor ikkala
    separatorni ham qabul qiladi, lekin saqlash bir xil bo'lsin).

    Buyruq topilmasa (`FileNotFoundError`) yoki xato bersa — toza yutiladi va
    keyingi buyruqqa o'tadi (har platformada graceful degrade).
    """
    if _platform.IS_WINDOWS:
        return _parse_arp_table_windows()

    table: dict[str, str] = {}
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            raw = subprocess.run(cmd, capture_output=True, timeout=3).stdout
        except (subprocess.SubprocessError, OSError):
            continue
        out = _platform.decode_console(raw)
        for line in out.splitlines():
            m = _ARP_RE.search(line) or _NEIGH_RE.search(line)
            if m:
                table[m.group(1)] = m.group(2).lower()
        if table:
            break
    return table


def _parse_arp_table_windows() -> dict[str, str]:
    """Windows `arp -a` chiqishidan {ip: mac} (MAC ':' bilan, kichik harf).

    Chiqish bayt sifatida olinib `decode_console` (OEM codepage) bilan
    dekodlanadi — RUS konsolida ham IP/MAC to'g'ri o'qiladi. Konsol oynasi
    miltillamasligi uchun CREATE_NO_WINDOW.
    """
    table: dict[str, str] = {}
    try:
        raw = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            timeout=3,
            creationflags=_platform.subprocess_flags(),
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return table
    out = _platform.decode_console(raw)
    for line in out.splitlines():
        m = _ARP_WIN_RE.search(line)
        if m:
            # "00-11-22-33-44-55" -> "00:11:22:33:44:55" (saqlash bir xil bo'lsin).
            table[m.group(1)] = m.group(2).replace("-", ":").lower()
    return table


async def _reverse_dns(address: str, timeout: float = 1.0) -> str | None:
    """Best-effort reverse DNS (PTR) — xatolar yutiladi."""
    try:
        result = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, address), timeout)
        return result[0]
    except (TimeoutError, socket.herror, socket.gaierror, OSError):
        return None
