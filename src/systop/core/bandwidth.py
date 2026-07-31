"""Live per-interface bandwidth monitor — the `bandwhich`/`nload` gap.

`psutil.net_io_counters(pernic=True)` is read periodically and the delta between
two readings is divided by the time to get bits per second (bps) and packets per
second (pps). No root is required — the counters are provided by the kernel.

Only stdlib + psutil are used; the module imports no other core module.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import psutil

# The named-tuple type returned by psutil.net_io_counters(pernic=True).
# (Any, for snetio's bytes_recv/sent and packets_recv/sent fields.)
Counters = dict[str, Any]


@dataclass(slots=True)
class IfaceRate:
    """The live bandwidth rate of a single interface (based on the delta).

    rx_bps/tx_bps — bits per second (received/sent); rx_pps/tx_pps — packets per
    second.
    """

    name: str
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    rx_pps: float = 0.0
    tx_pps: float = 0.0

    @property
    def total_bps(self) -> float:
        """The total (rx+tx) bits per second."""
        return self.rx_bps + self.tx_bps


def _read_counters() -> Counters:
    """Reads the raw IO counters for every interface."""
    return psutil.net_io_counters(pernic=True)


def _compute_rates(prev: Counters, curr: Counters, elapsed: float) -> list[IfaceRate]:
    """Computes each interface's rate from the delta between two readings.

    elapsed — the real time difference in seconds (it must be > 0). If a counter
    has been reset (or the interface has just appeared), a negative delta is
    ignored (taken as 0).
    """
    dt = elapsed if elapsed > 0 else 1e-9
    rates: list[IfaceRate] = []
    for name, c in curr.items():
        p = prev.get(name)
        if p is None:
            # A new interface — there is no earlier point to compare against.
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
    """Measures each interface's bandwidth rate from the delta between two readings.

    It waits `interval` seconds and turns the difference between the two counter
    points into bits per second and packets per second. It does not block — it
    uses `asyncio.sleep`. The result is a list of `IfaceRate` sorted by
    interface name.
    """
    prev = _read_counters()
    t0 = time.monotonic()
    await asyncio.sleep(max(interval, 0.0))
    curr = _read_counters()
    elapsed = time.monotonic() - t0
    return _compute_rates(prev, curr, elapsed)


async def bandwidth_stream(interval: float = 1.0) -> AsyncIterator[list[IfaceRate]]:
    """A continuous bandwidth stream — for the TUI panel or `--watch` mode.

    It yields a fresh `IfaceRate` list every `interval` seconds. Even the first
    result arrives only after one full interval has passed (that is, every
    element is based on a real delta). It stops when the consumer `break`s.
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
