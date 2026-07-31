"""ICMP ping — the local gateway and global servers (cross-platform).

On macOS and Linux we work in `icmplib`'s `privileged=False` mode: a SOCK_DGRAM
ICMP socket works without root. If the system does not permit it,
`privileged=True` (sudo) becomes necessary.

On Windows `icmplib` does not support unprivileged ICMP (a raw socket => admin
required). So on Windows we fall back to the system's `ping.exe` command — which
demands no admin rights — and parse its output (`_platform`).
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
    """The minimal interface of `icmplib`'s Host object (duck typing).

    `_to_result` reads only these attributes. `icmplib` exports no concrete
    type, so the Protocol keeps the typing mypy-clean — and the tests' `FakeHost`
    fits the same shape.
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


# The default global ping targets (DNS providers — stable, fast to answer).
DEFAULT_GLOBAL_TARGETS: dict[str, str] = {
    "Google DNS": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

# The global IPv6 targets (icmplib supports ICMP over IPv6).
DEFAULT_GLOBAL_TARGETS_V6: dict[str, str] = {
    "Google DNS v6": "2001:4860:4860::8888",
    "Cloudflare v6": "2606:4700:4700::1111",
}


@dataclass(slots=True)
class PingResult:
    """The ping result for a single target (in milliseconds)."""

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
    """Pings a single address and returns the result.

    On macOS/Linux via `icmplib` (privileged=False); on Windows via the system
    `ping` command (no admin required).
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
    """Pings several targets in parallel.

    targets: a dict in `{label: address}` form.

    On Windows each target is handled in parallel by its own `ping` process
    (asyncio.gather + a semaphore caps the concurrency).
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
    """Builds the dict of ping targets: the local gateway + the global servers.

    Arguments:
        gateway — the local gateway IP (not added when None).
        include_global — adds the default global targets (the DNS providers).
        include_ipv6 — when True the global IPv6 targets are added as well.
        extra_targets — additional user targets in `{label: address}` form (from
            a config file, say). They are added AFTER the default targets; on a
            clashing label the user's value wins. (Reading the config file is
            Layer 2's job; this function only accepts a ready-made dict.)
    """
    targets: dict[str, str] = {}
    if gateway:
        targets["Gateway (local)"] = gateway
    if include_global:
        targets.update(DEFAULT_GLOBAL_TARGETS)
    if include_ipv6:
        targets.update(DEFAULT_GLOBAL_TARGETS_V6)
    if extra_targets:
        targets.update(extra_targets)
    return targets


@dataclass(slots=True)
class WatchStats:
    """Cumulative statistics for `ping --watch` (for a single target)."""

    label: str
    address: str
    sent: int = 0
    received: int = 0
    last_rtt: float = 0.0
    min_rtt: float = 0.0
    avg_rtt: float = 0.0
    max_rtt: float = 0.0
    _rtt_sum: float = 0.0  # internal: used to compute avg

    @property
    def loss_pct(self) -> float:
        if self.sent == 0:
            return 0.0
        return (self.sent - self.received) / self.sent * 100.0

    def update(self, alive: bool, rtt: float) -> None:
        """Updates the statistics with the result of a single ping."""
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
    """An endless ping stream: one packet every `interval` seconds, updated stats.

    For `--watch` mode. Stopping is the caller's business (CancelledError /
    KeyboardInterrupt). Each iteration yields the updated `WatchStats`.
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
        # We wait out the interval minus the time the ping took (less drift).
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


# --- The Windows branch (the system `ping` command, no admin needed) ---------

# We cap the number of parallel `ping` processes on Windows (saving resources).
_WIN_PING_CONCURRENCY = 64


def _is_ipv6(address: str) -> bool:
    """True when the address is IPv6 (Windows `ping` then needs the `-6` flag)."""
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
    except ValueError:
        # A hostname — we treat it as IPv4; `ping` resolves it itself.
        return ":" in address


async def _win_ping(
    address: str,
    count: int = 4,
    timeout: float = 2.0,
) -> tuple[bool, list[float], float]:
    """ICMP ping on Windows (alive, rtts_ms, loss) — no admin required.

    The primary path: Win32 `IcmpSendEcho` (`_platform.win_icmp_ping`) —
    independent of language/codepage, with no text parsing. It works for an IPv4
    address.

    The fallback path: if `IcmpSendEcho` is unavailable (a very old environment)
    or the address does not resolve to IPv4 (IPv6, for instance) -> we fall back
    to the system `ping.exe` command and parse its output in a
    LANGUAGE-INDEPENDENT way (`parse_windows_ping`). If the command is missing /
    times out -> (False, [], 1.0).
    """
    count = max(1, count)

    # 1) The primary path: IcmpSendEcho (IPv4, independent of language/codepage).
    if not _is_ipv6(address):
        icmp = await asyncio.to_thread(_platform.win_icmp_ping, address, count, timeout)
        if icmp is not None:
            return icmp

    # 2) The fallback path: the system `ping.exe` + a language-independent parse
    #    (IPv6, or no DLL).
    wait_ms = max(1, int(timeout * 1000))
    cmd = ["ping", "-n", str(count), "-w", str(wait_ms)]
    if _is_ipv6(address):
        cmd.append("-6")
    cmd.append(address)

    # An overall timeout for the whole process: each packet waits `-w`, plus
    # some slack on top.
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
    """Builds a `PingResult` from the parsed Windows `ping` result (same shape as icmplib)."""
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
    """The mean absolute difference between consecutive values (icmplib's jitter definition)."""
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
    """Pings several targets in parallel on Windows (capped with a semaphore)."""
    sem = asyncio.Semaphore(_WIN_PING_CONCURRENCY)

    async def one(label: str, address: str) -> PingResult:
        async with sem:
            alive, rtts, loss = await _win_ping(address, count=count, timeout=timeout)
        return _win_result(label, address, alive, rtts, loss)

    if not addresses:
        return []
    tasks = [one(lbl, addr) for lbl, addr in zip(labels, addresses, strict=True)]
    return await asyncio.gather(*tasks)
