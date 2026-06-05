"""TCP port skaner — asyncio bilan, qo'shimcha bog'liqliksiz (faqat stdlib).

Har bir portga `asyncio.open_connection` orqali TCP connect urinishi qilinadi.
Ulanish ochilsa — port ochiq, javob vaqti (ms) o'lchanadi. Timeout/refused
bo'lsa — yopiq yoki filtrlangan. Hammasi parallel (semaphore bilan cheklangan),
shuning uchun root kerak emas va tez ishlaydi.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field

# Sysadminlar tez-tez tekshiradigan keng tarqalgan portlar -> xizmat nomi.
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-sub",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    3000: "Dev-HTTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9000: "PHP-FPM",
    9090: "Prometheus",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Holat kodlari (UI'da o'zbekcha matnga aylantiriladi).
STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_FILTERED = "filtered"


@dataclass(slots=True)
class PortResult:
    """Bitta port bo'yicha skaner natijasi."""

    port: int
    state: str = STATE_CLOSED  # open | closed | filtered
    service: str | None = None
    rtt_ms: float = 0.0  # faqat ochiq portlar uchun mazmunli

    @property
    def is_open(self) -> bool:
        return self.state == STATE_OPEN


@dataclass(slots=True)
class ScanResult:
    """Bitta host bo'yicha to'liq skaner natijasi."""

    host: str
    resolved_ip: str | None = None
    error: str | None = None
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]


def default_ports() -> list[int]:
    """Standart skaner uchun keng tarqalgan portlar ro'yxati (tartiblangan)."""
    return sorted(COMMON_PORTS)


def parse_ports(spec: str) -> list[int]:
    """`22,80,443` yoki `1-1024` yoki `22,80,8000-8100` kabi spec'ni parse qiladi.

    Noto'g'ri qiymatlar e'tiborsiz qoldiriladi; natija tartiblangan, takrorsiz.
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            for p in range(max(lo, 1), min(hi, 65535) + 1):
                ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


async def _resolve(host: str) -> str | None:
    """Host nomini IP'ga aylantiradi (best-effort, xato yutiladi)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return infos[0][4][0] if infos else None
    except (socket.gaierror, OSError):
        return None


async def _scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult:
    """Bitta portga TCP connect urinib, holatini aniqlaydi."""
    async with sem:
        start = time.perf_counter()
        writer = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            rtt = (time.perf_counter() - start) * 1000.0
            return PortResult(
                port=port,
                state=STATE_OPEN,
                service=COMMON_PORTS.get(port),
                rtt_ms=rtt,
            )
        except TimeoutError:
            # Javob yo'q — ko'pincha firewall tomonidan filtrlangan.
            return PortResult(port=port, state=STATE_FILTERED, service=COMMON_PORTS.get(port))
        except (ConnectionRefusedError, OSError):
            # Aktiv rad etish — port yopiq.
            return PortResult(port=port, state=STATE_CLOSED, service=COMMON_PORTS.get(port))
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass


async def scan_host(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    concurrency: int = 200,
) -> ScanResult:
    """Hostdagi portlarni parallel skaner qiladi.

    ports — tekshiriladigan portlar; None bo'lsa keng tarqalganlari ishlatiladi.
    Natija dataclass: resolved IP, xato xabari (o'zbekcha), portlar holati.
    """
    port_list = sorted(set(ports)) if ports else default_ports()

    resolved = await _resolve(host)
    if resolved is None:
        return ScanResult(
            host=host,
            error=f"'{host}' nomini IP manzilga aylantirib bo'lmadi (DNS yoki host xato).",
        )

    sem = asyncio.Semaphore(max(concurrency, 1))
    tasks = [_scan_port(resolved, p, timeout, sem) for p in port_list]
    results = await asyncio.gather(*tasks)
    results.sort(key=lambda r: r.port)
    return ScanResult(host=host, resolved_ip=resolved, ports=results)
