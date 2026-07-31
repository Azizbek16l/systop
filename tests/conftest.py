"""Shared test helpers — all OFFLINE.

This file NEVER touches the network. It holds only fakes and
``httpx.MockTransport`` helpers, so the core logic can be exercised without one.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FakeHost:
    """Duck-typed stand-in for an ``icmplib`` Host object.

    ``ping._to_result`` and ``topology.discover_lan`` read only these
    attributes, so no real ICMP socket is needed.
    """

    address: str
    is_alive: bool = False
    min_rtt: float = 0.0
    avg_rtt: float = 0.0
    max_rtt: float = 0.0
    jitter: float = 0.0
    packet_loss: float = 1.0
    rtts: list[float] = field(default_factory=list)


@dataclass
class FakeRawHop:
    """Fake of the hop object returned by ``icmplib.traceroute``."""

    distance: int
    address: str | None
    avg_rtt: float = 0.0
    is_alive: bool = False


@dataclass
class FakeCompletedProcess:
    """Minimal stand-in for a ``subprocess.run`` result."""

    stdout: str = ""
    returncode: int = 0
    stderr: str = ""


@dataclass
class FakeSnicaddr:
    """A ``psutil`` snicaddr (address) record."""

    family: int
    address: str | None = None
    netmask: str | None = None
    broadcast: str | None = None
    ptp: str | None = None


@dataclass
class FakeSnicstats:
    """A ``psutil`` snicstats (interface state) record."""

    isup: bool = True
    duplex: int = 0
    speed: int = 0
    mtu: int = 1500
    flags: str = ""


@dataclass
class FakeIOCounters:
    """Stand-in for the ``psutil.net_io_counters`` snetio named tuple.

    ``bandwidth._compute_rates`` reads only ``bytes_recv``/``bytes_sent`` and
    ``packets_recv``/``packets_sent``; the remaining fields are optional.
    """

    bytes_recv: int = 0
    bytes_sent: int = 0
    packets_recv: int = 0
    packets_sent: int = 0
    errin: int = 0
    errout: int = 0
    dropin: int = 0
    dropout: int = 0


@dataclass
class FakeAddr:
    """Stand-in for the ``psutil`` connection address (ip, port) named tuple."""

    ip: str = ""
    port: int = 0


@dataclass
class FakeConn:
    """Duck-typed fake of a ``psutil.net_connections`` sconn record.

    ``connections.list_connections`` reads only ``family``/``type``/``laddr``/
    ``raddr``/``status``/``pid``.
    """

    family: int
    type: int
    laddr: object = None
    raddr: object = None
    status: str = "NONE"
    pid: int | None = None
    fd: int = -1


class FakeProcess:
    """Stand-in for ``psutil.Process(pid)`` — provides ``.name()`` only."""

    def __init__(self, pid: int, name: str = "proc") -> None:
        self._pid = pid
        self._name = name

    def name(self) -> str:
        return self._name
