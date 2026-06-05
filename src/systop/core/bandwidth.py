"""Per-interfeys jonli bandwidth monitori — `bandwhich`/`nload` bo'shlig'i.

`psutil.net_io_counters(pernic=True)` davriy o'qiladi va ikki o'qish orasidagi
delta vaqtga bo'linib bit/sekund (bps) va paket/sekund (pps) hisoblanadi.
Root kerak emas — hisoblagichlar yadro tomonidan beriladi.

Faqat stdlib + psutil ishlatiladi; modul boshqa core modullarni import qilmaydi.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import psutil

# psutil.net_io_counters(pernic=True) qaytaradigan named-tuple turi.
# (snetio'ning bytes_recv/sent, packets_recv/sent maydonlari uchun Any.)
Counters = dict[str, Any]


@dataclass(slots=True)
class IfaceRate:
    """Bitta interfeysning jonli bandwidth tezligi (delta asosida).

    rx_bps/tx_bps — bit/sekund (qabul/yuborish); rx_pps/tx_pps — paket/sekund.
    """

    name: str
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    rx_pps: float = 0.0
    tx_pps: float = 0.0

    @property
    def total_bps(self) -> float:
        """Umumiy (rx+tx) bit/sekund."""
        return self.rx_bps + self.tx_bps


def _read_counters() -> Counters:
    """Har interfeys bo'yicha xom IO hisoblagichlarini o'qiydi."""
    return psutil.net_io_counters(pernic=True)


def _compute_rates(prev: Counters, curr: Counters, elapsed: float) -> list[IfaceRate]:
    """Ikki o'qish orasidagi delta'dan har interfeys tezligini hisoblaydi.

    elapsed — soniyalardagi haqiqiy vaqt farqi (>0 bo'lishi shart). Hisoblagich
    qayta yuklangan (yoki interfeys yangi paydo bo'lgan) holatda manfiy delta
    e'tiborsiz qoldiriladi (0 deb olinadi).
    """
    dt = elapsed if elapsed > 0 else 1e-9
    rates: list[IfaceRate] = []
    for name, c in curr.items():
        p = prev.get(name)
        if p is None:
            # Yangi interfeys — taqqoslash uchun avvalgi nuqta yo'q.
            rates.append(IfaceRate(name=name))
            continue

        rx_bytes = max(c.bytes_recv - p.bytes_recv, 0)
        tx_bytes = max(c.bytes_sent - p.bytes_sent, 0)
        rx_pkts = max(c.packets_recv - p.packets_recv, 0)
        tx_pkts = max(c.packets_sent - p.packets_sent, 0)

        rates.append(
            IfaceRate(
                name=name,
                rx_bps=rx_bytes * 8.0 / dt,
                tx_bps=tx_bytes * 8.0 / dt,
                rx_pps=rx_pkts / dt,
                tx_pps=tx_pkts / dt,
            )
        )
    rates.sort(key=lambda r: r.name)
    return rates


async def sample_bandwidth(interval: float = 1.0) -> list[IfaceRate]:
    """Ikki o'qish orasidagi delta'dan har interfeys bandwidth tezligini o'lchaydi.

    `interval` soniya kutib, ikkita hisoblagich nuqtasi orasidagi farqni
    bit/sekund va paket/sekundga aylantiradi. Bloklamaydi — `asyncio.sleep`
    ishlatadi. Natija interfeys nomi bo'yicha tartiblangan `IfaceRate` ro'yxati.
    """
    prev = _read_counters()
    t0 = time.monotonic()
    await asyncio.sleep(max(interval, 0.0))
    curr = _read_counters()
    elapsed = time.monotonic() - t0
    return _compute_rates(prev, curr, elapsed)


async def bandwidth_stream(interval: float = 1.0) -> AsyncIterator[list[IfaceRate]]:
    """Doimiy bandwidth oqimi — TUI panel yoki `--watch` rejimi uchun.

    Har `interval` soniyada yangi `IfaceRate` ro'yxati beradi. Birinchi natija
    ham bitta to'liq interval kutgandan keyin keladi (ya'ni har bir element
    haqiqiy delta'ga asoslangan). Iste'molchi `break` qilsa to'xtaydi.
    """
    prev = _read_counters()
    t0 = time.monotonic()
    while True:
        await asyncio.sleep(max(interval, 0.0))
        curr = _read_counters()
        now = time.monotonic()
        yield _compute_rates(prev, curr, now - t0)
        prev = curr
        t0 = now
