"""ICMP ping — lokal gateway va global serverlar (cross-platform).

macOS va Linux'da `icmplib`'ning `privileged=False` rejimida ishlaymiz:
SOCK_DGRAM ICMP soketi root'siz ishlaydi. Agar tizim ruxsat bermasa,
`privileged=True` (sudo) kerak bo'ladi.

Windows'da `icmplib` unprivileged ICMP'ni qo'llamaydi (raw socket => admin
kerak). Shuning uchun Windows'da tizimning `ping.exe` buyrug'iga tushamiz —
u admin talab qilmaydi — va chiqishni parse qilamiz (`_platform`).
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from icmplib import async_multiping, async_ping

from systop.core import _platform


@runtime_checkable
class _HostLike(Protocol):
    """`icmplib`'ning Host obyektining minimal interfeysi (duck typing).

    `_to_result` faqat shu atributlarni o'qiydi. `icmplib` aniq tip eksport
    qilmaydi, shuning uchun Protocol typing mypy-toza qiladi va test'dagi
    `FakeHost` ham shu shaklga mos keladi.
    """

    @property
    def address(self) -> str: ...

    @property
    def is_alive(self) -> bool: ...

    @property
    def min_rtt(self) -> float: ...

    @property
    def avg_rtt(self) -> float: ...

    @property
    def max_rtt(self) -> float: ...

    @property
    def jitter(self) -> float: ...

    @property
    def packet_loss(self) -> float: ...

    @property
    def rtts(self) -> list[float]: ...


# Standart global ping nishonlari (DNS provayderlar — barqaror va tez javob).
DEFAULT_GLOBAL_TARGETS: dict[str, str] = {
    "Google DNS": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

# IPv6 global nishonlar (icmplib IPv6 ICMP'ni qo'llab-quvvatlaydi).
DEFAULT_GLOBAL_TARGETS_V6: dict[str, str] = {
    "Google DNS v6": "2001:4860:4860::8888",
    "Cloudflare v6": "2606:4700:4700::1111",
}


@dataclass(slots=True)
class PingResult:
    """Bitta nishon bo'yicha ping natijasi (ms larda)."""

    label: str
    address: str
    alive: bool = False
    min_rtt: float = 0.0
    avg_rtt: float = 0.0
    max_rtt: float = 0.0
    jitter: float = 0.0
    packet_loss: float = 1.0  # 0.0..1.0
    rtts: list[float] = field(default_factory=list)

    @property
    def loss_pct(self) -> float:
        return self.packet_loss * 100.0


async def ping_once(
    address: str,
    label: str | None = None,
    count: int = 4,
    timeout: float = 2.0,
    interval: float = 0.4,
    privileged: bool = False,
) -> PingResult:
    """Bitta manzilni ping qiladi va natijani qaytaradi.

    macOS/Linux'da `icmplib` (privileged=False); Windows'da tizim `ping`
    buyrug'i orqali (admin shart emas).
    """
    if _platform.IS_WINDOWS:
        alive, rtts, loss = await _win_ping(address, count=count, timeout=timeout)
        return _win_result(label or address, address, alive, rtts, loss)
    host = await async_ping(
        address,
        count=count,
        interval=interval,
        timeout=timeout,
        privileged=privileged,
    )
    return _to_result(host, label or address)


async def ping_many(
    targets: dict[str, str],
    count: int = 3,
    timeout: float = 2.0,
    interval: float = 0.3,
    privileged: bool = False,
) -> list[PingResult]:
    """Bir nechta nishonni parallel ping qiladi.

    targets: {label: address} ko'rinishidagi lug'at.

    Windows'da har nishon alohida `ping` jarayoni bilan parallel ishlanadi
    (asyncio.gather + semaphore concurrency'ni cheklaydi).
    """
    labels = list(targets.keys())
    addresses = [targets[label] for label in labels]

    if _platform.IS_WINDOWS:
        return await _win_ping_many(labels, addresses, count=count, timeout=timeout)

    hosts = await async_multiping(
        addresses,
        count=count,
        interval=interval,
        timeout=timeout,
        privileged=privileged,
    )
    return [_to_result(host, label) for host, label in zip(hosts, labels, strict=True)]


def build_targets(
    gateway: str | None,
    include_global: bool = True,
    include_ipv6: bool = False,
    extra_targets: dict[str, str] | None = None,
) -> dict[str, str]:
    """Ping nishonlari lug'atini yig'adi: lokal gateway + global serverlar.

    Argumentlar:
        gateway — lokal gateway IP (None bo'lsa qo'shilmaydi).
        include_global — standart global nishonlarni (DNS provayderlar) qo'shadi.
        include_ipv6 — True bo'lsa IPv6 global nishonlar ham qo'shiladi.
        extra_targets — {label: address} ko'rinishidagi qo'shimcha foydalanuvchi
            nishonlari (masalan config fayldan). Standart nishonlardan KEYIN
            qo'shiladi; bir xil label bo'lsa foydalanuvchi qiymati ustun keladi.
            (Config faylni o'qish — Layer 2 ishi; bu funksiya faqat tayyor
            lug'atni qabul qiladi.)
    """
    targets: dict[str, str] = {}
    if gateway:
        targets["Gateway (lokal)"] = gateway
    if include_global:
        targets.update(DEFAULT_GLOBAL_TARGETS)
    if include_ipv6:
        targets.update(DEFAULT_GLOBAL_TARGETS_V6)
    if extra_targets:
        targets.update(extra_targets)
    return targets


@dataclass(slots=True)
class WatchStats:
    """`ping --watch` uchun jamlanma statistika (bitta nishon bo'yicha)."""

    label: str
    address: str
    sent: int = 0
    received: int = 0
    last_rtt: float = 0.0
    min_rtt: float = 0.0
    avg_rtt: float = 0.0
    max_rtt: float = 0.0
    _rtt_sum: float = 0.0  # ichki: avg hisoblash uchun

    @property
    def loss_pct(self) -> float:
        if self.sent == 0:
            return 0.0
        return (self.sent - self.received) / self.sent * 100.0

    def update(self, alive: bool, rtt: float) -> None:
        """Bitta ping natijasi bilan statistikani yangilaydi."""
        self.sent += 1
        if not alive or rtt <= 0:
            return
        self.received += 1
        self.last_rtt = rtt
        self._rtt_sum += rtt
        self.avg_rtt = self._rtt_sum / self.received
        self.max_rtt = max(self.max_rtt, rtt)
        self.min_rtt = rtt if self.min_rtt == 0.0 else min(self.min_rtt, rtt)


async def ping_stream(
    address: str,
    label: str | None = None,
    interval: float = 1.0,
    timeout: float = 2.0,
    privileged: bool = False,
) -> AsyncIterator[WatchStats]:
    """Cheksiz ping oqimi: har `interval` soniyada bitta paket, yangilangan stats.

    `--watch` rejimi uchun. To'xtatish chaqiruvchi tomonida (CancelledError /
    KeyboardInterrupt) amalga oshiriladi. Har iteratsiyada yangilangan
    `WatchStats` qaytaradi.
    """
    stats = WatchStats(label=label or address, address=address)
    while True:
        start = asyncio.get_running_loop().time()
        try:
            if _platform.IS_WINDOWS:
                alive, rtts, _loss = await _win_ping(address, count=1, timeout=timeout)
                rtt = (sum(rtts) / len(rtts)) if rtts else 0.0
                stats.update(alive, rtt)
            else:
                host = await async_ping(
                    address,
                    count=1,
                    timeout=timeout,
                    privileged=privileged,
                )
                rtt = host.avg_rtt if host.is_alive else 0.0
                stats.update(host.is_alive, rtt)
        except OSError:
            stats.update(False, 0.0)
        yield stats
        # Interval'ni ping vaqtini hisobga olib kutamiz (drift kamayadi).
        elapsed = asyncio.get_running_loop().time() - start
        sleep_for = interval - elapsed
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


def _to_result(host: _HostLike, label: str) -> PingResult:
    return PingResult(
        label=label,
        address=host.address,
        alive=host.is_alive,
        min_rtt=host.min_rtt,
        avg_rtt=host.avg_rtt,
        max_rtt=host.max_rtt,
        jitter=host.jitter,
        packet_loss=host.packet_loss,
        rtts=list(host.rtts),
    )


# --- Windows shoxi (tizim `ping` buyrug'i, admin shart emas) -----------------

# Windows'da parallel `ping` jarayonlari sonini cheklaymiz (resurs tejash).
_WIN_PING_CONCURRENCY = 64


def _is_ipv6(address: str) -> bool:
    """Manzil IPv6 bo'lsa True (Windows `ping` uchun `-6` bayrog'i kerak)."""
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
    except ValueError:
        # Nom (hostname) — IPv4 deb hisoblaymiz; `ping` o'zi resolve qiladi.
        return ":" in address


async def _win_ping(
    address: str,
    count: int = 4,
    timeout: float = 2.0,
) -> tuple[bool, list[float], float]:
    """Windows tizim `ping` buyrug'i orqali ping (alive, rtts_ms, loss).

    `ping -n <count> -w <ms> [-6] <address>` ishga tushiriladi (admin shart
    emas). Chiqish `_platform.parse_windows_ping` bilan parse qilinadi.
    Buyruq topilmasa / timeout bo'lsa -> (False, [], 1.0).
    """
    count = max(1, count)
    wait_ms = max(1, int(timeout * 1000))
    cmd = ["ping", "-n", str(count), "-w", str(wait_ms)]
    if _is_ipv6(address):
        cmd.append("-6")
    cmd.append(address)

    # Butun jarayonga umumiy timeout: har paket `-w` kutadi, ortig'iga zaxira.
    overall = timeout * count + 2.0
    out = await _platform.run_command(cmd, timeout=overall)
    if not out:
        return False, [], 1.0
    return _platform.parse_windows_ping(out, expected_count=count)


def _win_result(
    label: str,
    address: str,
    alive: bool,
    rtts: list[float],
    loss: float,
) -> PingResult:
    """Windows `ping` parse natijasidan `PingResult` yig'adi (icmplib bilan bir xil shakl)."""
    if rtts:
        return PingResult(
            label=label,
            address=address,
            alive=alive,
            min_rtt=min(rtts),
            avg_rtt=sum(rtts) / len(rtts),
            max_rtt=max(rtts),
            jitter=_mean_abs_consecutive_diff(rtts),
            packet_loss=loss,
            rtts=list(rtts),
        )
    return PingResult(
        label=label,
        address=address,
        alive=alive,
        packet_loss=loss,
    )


def _mean_abs_consecutive_diff(values: list[float]) -> float:
    """Ketma-ket qiymatlar farqining o'rtacha moduli (icmplib jitter ta'rifiga mos)."""
    if len(values) < 2:
        return 0.0
    diffs = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
    return sum(diffs) / len(diffs)


async def _win_ping_many(
    labels: list[str],
    addresses: list[str],
    count: int,
    timeout: float,
) -> list[PingResult]:
    """Windows'da bir nechta nishonni parallel ping qiladi (semaphore bilan cheklab)."""
    sem = asyncio.Semaphore(_WIN_PING_CONCURRENCY)

    async def one(label: str, address: str) -> PingResult:
        async with sem:
            alive, rtts, loss = await _win_ping(address, count=count, timeout=timeout)
        return _win_result(label, address, alive, rtts, loss)

    if not addresses:
        return []
    tasks = [one(lbl, addr) for lbl, addr in zip(labels, addresses, strict=True)]
    return await asyncio.gather(*tasks)
