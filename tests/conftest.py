"""Umumiy test yordamchilari — barchasi OFFLINE.

Bu fayl tarmoqqa CHIQMAYDI. Bu yerda faqat soxta (fake) obyektlar va
``httpx.MockTransport`` yordamchilari bor — core mantiqni tarmoqsiz sinash uchun.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FakeHost:
    """``icmplib`` Host obyektining duck-typed o'rnini bosuvchi soxta obyekt.

    ``ping._to_result`` va ``topology.discover_lan`` faqat shu atributlarni
    o'qiydi — shuning uchun haqiqiy ICMP soketi shart emas.
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
    """``icmplib.traceroute`` qaytaradigan hop obyektining soxtasi."""

    distance: int
    address: str | None
    avg_rtt: float = 0.0
    is_alive: bool = False


@dataclass
class FakeCompletedProcess:
    """``subprocess.run`` natijasining minimal o'rnini bosuvchisi."""

    stdout: str = ""
    returncode: int = 0
    stderr: str = ""


@dataclass
class FakeSnicaddr:
    """``psutil`` snicaddr (manzil) yozuvi."""

    family: int
    address: str | None = None
    netmask: str | None = None
    broadcast: str | None = None
    ptp: str | None = None


@dataclass
class FakeSnicstats:
    """``psutil`` snicstats (interfeys holati) yozuvi."""

    isup: bool = True
    duplex: int = 0
    speed: int = 0
    mtu: int = 1500
    flags: str = ""


@dataclass
class FakeIOCounters:
    """``psutil.net_io_counters`` snetio named-tuple o'rnini bosuvchi.

    ``bandwidth._compute_rates`` faqat ``bytes_recv``/``bytes_sent`` va
    ``packets_recv``/``packets_sent`` ni o'qiydi — qolgan maydonlar ixtiyoriy.
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
    """``psutil`` ulanish manzili (ip, port) named-tuple o'rnini bosuvchi."""

    ip: str = ""
    port: int = 0


@dataclass
class FakeConn:
    """``psutil.net_connections`` sconn yozuvining soxtasi (duck-typed).

    ``connections.list_connections`` faqat ``family``/``type``/``laddr``/
    ``raddr``/``status``/``pid`` ni o'qiydi.
    """

    family: int
    type: int
    laddr: object = None
    raddr: object = None
    status: str = "NONE"
    pid: int | None = None
    fd: int = -1


class FakeProcess:
    """``psutil.Process(pid)`` o'rnini bosuvchi — faqat ``.name()`` beradi."""

    def __init__(self, pid: int, name: str = "proc") -> None:
        self._pid = pid
        self._name = name

    def name(self) -> str:
        return self._name
