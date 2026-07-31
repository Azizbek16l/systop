"""TCP port skaner — asyncio bilan, qo'shimcha bog'liqliksiz (faqat stdlib).

Har bir portga `asyncio.open_connection` orqali TCP connect urinishi qilinadi.
Ulanish ochilsa — port ochiq, javob vaqti (ms) o'lchanadi. Timeout/refused
bo'lsa — yopiq yoki filtrlangan. Hammasi parallel (semaphore bilan cheklangan),
shuning uchun root kerak emas va tez ishlaydi.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
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

# Manzil oilasi (address family) tanlovi.
#   auto — OS nimani birinchi qaytarsa (odatda IPv6 bo'lsa IPv6, aks holda IPv4)
#   ipv4 / ipv6 — majburan shu oila; host o'sha oilada resolve bo'lmasa xato
FAMILY_AUTO = "auto"
FAMILY_V4 = "ipv4"
FAMILY_V6 = "ipv6"

_FAMILY_MAP: dict[str, int] = {
    FAMILY_AUTO: socket.AF_UNSPEC,
    FAMILY_V4: socket.AF_INET,
    FAMILY_V6: socket.AF_INET6,
}


@dataclass(slots=True)
class PortResult:
    """Bitta port bo'yicha skaner natijasi."""

    port: int
    state: str = STATE_CLOSED  # open | closed | filtered
    service: str | None = None
    rtt_ms: float = 0.0  # faqat ochiq portlar uchun mazmunli
    banner: str | None = None  # xizmat versiyasi (--banner bilan to'ldiriladi)

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
    family: str = FAMILY_AUTO  # so'ralgan oila
    resolved_family: str | None = None  # amalda ishlatilgani: ipv4 | ipv6

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


def family_of(address: str) -> str | None:
    """Tayyor IP manzilning oilasini aytadi (`ipv4`/`ipv6`), nom bo'lsa None.

    Sof funksiya — tarmoqqa chiqmaydi, offline sinaladi.
    """
    try:
        return FAMILY_V6 if isinstance(
            ipaddress.ip_address(address), ipaddress.IPv6Address
        ) else FAMILY_V4
    except ValueError:
        return None


async def _resolve(host: str, family: str = FAMILY_AUTO) -> tuple[str | None, str | None]:
    """Host nomini IP'ga aylantiradi. Qaytaradi: (manzil, oila) yoki (None, None).

    `family` — `auto` bo'lsa OS tanlovi (AF_UNSPEC), aks holda majburan IPv4
    yoki IPv6. So'ralgan oilada manzil bo'lmasa (masalan AAAA yozuvi yo'q)
    (None, None) qaytadi va chaqiruvchi mazmunli xato beradi.

    Eslatma: qavs (`[::1]`) faqat URL'larda kerak — `asyncio.open_connection`
    xom IPv6 manzilni qavssiz qabul qiladi, shuning uchun bu yerda qo'shilmaydi.
    """
    af = _FAMILY_MAP.get(family, socket.AF_UNSPEC)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, family=af, proto=socket.IPPROTO_TCP
        )
    except (socket.gaierror, OSError):
        return None, None
    if not infos:
        return None, None

    # IPv6 so'ralganda IPv4-mapped (`::ffff:1.2.3.4`) manzillarni RAD ETAMIZ.
    # Ular IPv6 emas — trafik IPv4 ustidan ketadi. Ularni qabul qilish
    # `scan -6` / `nc -6` ni jimgina IPv4'da ishlatardi, ya'ni "IPv6
    # qo'llab-quvvatlanadi" degan da'vo yolg'on bo'lardi.
    candidates = infos
    if family == FAMILY_V6:
        candidates = [
            i for i in infos
            if i[0] == socket.AF_INET6 and not str(i[4][0]).startswith("::ffff:")
        ]
        if not candidates:
            return None, None

    info = candidates[0]
    address = info[4][0]
    resolved = FAMILY_V6 if info[0] == socket.AF_INET6 else FAMILY_V4

    # IPv6 zona identifikatorini (`%en0`) SAQLAB QOLAMIZ. Link-local manzil
    # zonasiz ishlatib bo'lmaydi: `fe80::1` ga ulanish "No route to host"
    # beradi va port YOPIQ deb ko'rsatiladi. `getaddrinfo` zonani alohida
    # `scope_id` maydonida qaytaradi, manzil satrida emas.
    if resolved == FAMILY_V6 and "%" not in address:
        scope_id = info[4][3] if len(info[4]) > 3 else 0
        if scope_id:
            try:
                address = f"{address}%{socket.if_indextoname(scope_id)}"
            except (OSError, ValueError):
                address = f"{address}%{scope_id}"
    return address, resolved


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
    family: str = FAMILY_AUTO,
) -> ScanResult:
    """Hostdagi portlarni parallel skaner qiladi (IPv4 va IPv6).

    ports — tekshiriladigan portlar; None bo'lsa keng tarqalganlari ishlatiladi.
    family — `auto` | `ipv4` | `ipv6` (majburan oila tanlash).
    Natija dataclass: resolved IP, oila, xato xabari (o'zbekcha), portlar holati.
    """
    port_list = sorted(set(ports)) if ports else default_ports()

    resolved, resolved_family = await _resolve(host, family)
    if resolved is None:
        if family == FAMILY_V6:
            msg = (
                f"'{host}' uchun haqiqiy IPv6 manzil topilmadi — AAAA yozuvi "
                "yo'q yoki OS faqat IPv4-mapped (`::ffff:`) qaytardi "
                "(hostda global IPv6 marshruti yo'qligi belgisi)."
            )
        elif family == FAMILY_V4:
            msg = f"'{host}' uchun IPv4 manzil topilmadi (A yozuvi yo'q?)."
        else:
            msg = f"'{host}' nomini IP manzilga aylantirib bo'lmadi (DNS yoki host xato)."
        return ScanResult(host=host, error=msg, family=family)

    sem = asyncio.Semaphore(max(concurrency, 1))
    tasks = [_scan_port(resolved, p, timeout, sem) for p in port_list]
    results = await asyncio.gather(*tasks)
    results.sort(key=lambda r: r.port)
    return ScanResult(
        host=host,
        resolved_ip=resolved,
        ports=results,
        family=family,
        resolved_family=resolved_family,
    )


# ===========================================================================
# LAN bo'ylab skan (nmap -sT uslubi) + banner (nmap -sV yengil)
# ===========================================================================

# nmap'ning "top ports" g'oyasi: eng ko'p uchraydigan portlar oldinda.
# Tartib muhim — `--top N` shu ro'yxatning boshidan N tasini oladi.
TOP_PORTS: tuple[int, ...] = (
    80, 443, 22, 3389, 445, 139, 135, 8080, 21, 23, 25, 110, 143, 53,
    3306, 5432, 8443, 8000, 5900, 6379, 111, 993, 995, 587, 161, 389,
    1433, 27017, 9200, 11211, 2375, 9090, 5601, 631, 8081, 8090, 4081,
    8006, 9000, 10000, 1521, 2049, 465, 591, 8555, 8110,
)

# Ulanishda birinchi javobni O'ZI yuboradigan xizmatlar (banner grab uchun
# hech narsa yubormasdan kutish kifoya). Boshqalarga (HTTP) so'rov kerak.
_GREETING_PORTS: frozenset[int] = frozenset(
    {21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379, 11211, 27017}
)

# TLS ustida ishlaydigan portlar. Bularga ochiq matnli HTTP yuborish ma'nosiz —
# server "400 Bad Request" qaytaradi va banner foydasiz bo'ladi. Shuning uchun
# avval TLS handshake qilinadi, keyin so'rov shifrlangan kanalda ketadi.
_TLS_PORTS: frozenset[int] = frozenset(
    {443, 465, 993, 995, 4081, 8006, 8443, 8834, 9443, 2376}
)

# Banner'dan mahsulot/versiyani ajratish naqshlari (sof matn ustida ishlaydi).
_BANNER_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"^SSH-[\d.]+-(?P<v>[^\r\n]+)", "SSH"),
    (r"^220[- ](?P<v>[^\r\n]*(?:FTP|vsftpd|ProFTPD|FileZilla)[^\r\n]*)", "FTP"),
    (r"^220[- ](?P<v>[^\r\n]*(?:SMTP|Postfix|Exim|Sendmail)[^\r\n]*)", "SMTP"),
    (r"^\+OK (?P<v>[^\r\n]+)", "POP3"),
    (r"^\* OK (?P<v>[^\r\n]+)", "IMAP"),
    (r"(?P<v>\d+\.\d+\.\d+[-\w.]*)\x00.*mysql_native", "MySQL"),
    (r"-ERR (?P<v>[^\r\n]*unauthenticated[^\r\n]*)", "Redis (parol bor)"),
    (r"^\$?\d*\r?\n?# Server\r?\nredis_version:(?P<v>[\d.]+)", "Redis"),
    (r"^HTTP/[\d.]+ \d+[^\r\n]*\r?\n(?:.*\r?\n)*?Server: (?P<v>[^\r\n]+)", "HTTP"),
)


def parse_targets(spec: str, max_hosts: int = 1024) -> list[str]:
    """Nishon spec'ini IP ro'yxatiga aylantiradi — SOF funksiya (offline test).

    Qo'llab-quvvatlanadigan shakllar (vergul bilan aralash bo'lishi mumkin):
      * `192.168.1.10`           — bitta manzil
      * `192.168.1.0/24`         — CIDR (tarmoq/broadcast chiqarib tashlanadi)
      * `192.168.1.10-50`        — oxirgi oktet diapazoni
      * `192.168.1.10-192.168.1.50` — to'liq manzil diapazoni
      * `example.com`            — nom (o'zi qaytariladi, resolve keyin bo'ladi)

    IPv6 CIDR **ataylab rad etiladi**: /64 da 2^64 manzil bor, sweep imkonsiz
    (IPv6 uchun `topology.discover_lan6` ishlatiladi). Bitta IPv6 manzil esa
    qabul qilinadi.

    `max_hosts` — himoya chegarasi: /8 kabi spec bilan xotirani to'ldirmaslik.
    Natija takrorsiz, kiritilish tartibi saqlanadi.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen and len(out) < max_hosts:
            seen.add(value)
            out.append(value)

    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue

        # CIDR
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
            except ValueError:
                continue
            if net.version == 6:
                continue  # IPv6 sweep imkonsiz — yuqoridagi izohga qarang
            for ip in net.hosts():
                if len(out) >= max_hosts:
                    break
                add(str(ip))
            continue

        # Diapazon (IPv6 manzillarda ham '-' bo'lmaydi, xavfsiz)
        if "-" in part and ":" not in part:
            lo_s, _, hi_s = part.partition("-")
            lo_s, hi_s = lo_s.strip(), hi_s.strip()
            try:
                lo = ipaddress.ip_address(lo_s)
            except ValueError:
                add(part)  # nom bo'lishi mumkin ("my-host")
                continue
            # "10.0.0.5-50" -> oxirgi oktetni to'ldiramiz
            if "." not in hi_s:
                prefix = lo_s.rsplit(".", 1)[0]
                hi_s = f"{prefix}.{hi_s}"
            try:
                hi = ipaddress.ip_address(hi_s)
            except ValueError:
                continue
            if int(hi) < int(lo):
                lo, hi = hi, lo
            for n in range(int(lo), int(hi) + 1):
                if len(out) >= max_hosts:
                    break
                add(str(ipaddress.ip_address(n)))
            continue

        add(part)

    return out


def top_ports(count: int = 20) -> list[int]:
    """Eng ko'p uchraydigan `count` ta portni qaytaradi (tartiblangan)."""
    return sorted(TOP_PORTS[: max(count, 1)])


def parse_banner(data: str) -> tuple[str | None, str | None]:
    """Banner matnidan (xizmat, versiya) ajratadi — SOF funksiya.

    Topilmasa (None, None) yoki (None, qisqartirilgan_matn) qaytaradi, shunda
    chaqiruvchi baribir xom bannerni ko'rsata oladi.
    """
    if not data:
        return None, None
    text = data[:2048]
    for pattern, service in _BANNER_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if m:
            version = (m.groupdict().get("v") or "").strip()
            return service, version[:120] or None
    # Tanilmagan — birinchi mazmunli qatorni qaytaramiz.
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return None, first[:120] or None


async def grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
    probe: bytes | None = None,
) -> str | None:
    """Ochiq portdan banner o'qiydi (nmap -sV ning yengil varianti).

    Ko'p xizmat (SSH/SMTP/FTP/MySQL) ulanishda salomlashish yuboradi — shunda
    hech narsa yubormasdan o'qiymiz. HTTP kabi so'rov kutadigan portlarga
    minimal probe yuboriladi.

    Istisno ko'tarmaydi: xato/timeout bo'lsa None qaytadi.
    """
    writer = None
    try:
        ssl_ctx = None
        if port in _TLS_PORTS:
            # LAN qurilmalarida self-signed sertifikat odatiy holat — tekshirmaymiz
            # (maqsad inventarizatsiya; sertifikat sifati uchun `systop tls`).
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
        )
        if probe is None and port not in _GREETING_PORTS:
            # Salomlashmaydigan port — HTTP so'rovi eng keng tarqalgan holat.
            # Host header'i uchun ASCII kifoya: bu yerda IP yoki LAN nomi keladi.
            # `idna` kodeki ATAYLAB ishlatilmaydi — u `errors=` argumentini
            # qo'llab-quvvatlamaydi va `UnicodeError` ko'tarib, banner'ni jimgina
            # yo'q qilardi (aynan shu bug bo'lgan).
            host_hdr = host.encode("ascii", "replace")
            probe = b"HEAD / HTTP/1.0\r\nHost: " + host_hdr + b"\r\n\r\n"
        if probe:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode("utf-8", errors="replace") if data else None
    except (TimeoutError, OSError, UnicodeError, ValueError, ssl.SSLError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, TimeoutError):
                pass


@dataclass(slots=True)
class SweepResult:
    """Ko'p host bo'yicha skan natijasi."""

    hosts: list[ScanResult] = field(default_factory=list)
    scanned_hosts: int = 0
    scanned_ports: int = 0

    @property
    def responsive(self) -> list[ScanResult]:
        """Kamida bitta ochiq porti bor hostlar."""
        return [h for h in self.hosts if h.open_ports]

    @property
    def total_open(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)


async def scan_targets(
    targets: list[str],
    ports: list[int] | None = None,
    timeout: float = 1.5,
    concurrency: int = 64,
    family: str = FAMILY_AUTO,
    banner: bool = False,
    delay: float = 0.0,
) -> SweepResult:
    """Bir nechta hostni parallel skan qiladi (nmap `-sT` uslubi).

    `concurrency` — BUTUN sweep bo'ylab umumiy chegara (host×port emas), shunda
    /24 skan tarmoqni ko'mmaydi. IPS/anti-scan himoyasi bor tarmoqda `delay`
    bering (har ulanishdan keyin pauza) — tez keng skan skanerlovchi IP'ni
    bloklanishiga olib keladi.

    `banner=True` — ochiq portlardan xizmat versiyasini ham o'qiydi (sekinroq).
    """
    port_list = sorted(set(ports)) if ports else top_ports(20)
    if not targets or not port_list:
        return SweepResult()

    sem = asyncio.Semaphore(max(concurrency, 1))

    async def one_host(host: str) -> ScanResult:
        resolved, resolved_family = await _resolve(host, family)
        if resolved is None:
            return ScanResult(host=host, error="resolve bo'lmadi", family=family)

        async def one_port(port: int) -> PortResult:
            async with sem:
                res = await _scan_port(resolved, port, timeout, asyncio.Semaphore(1))
                if delay > 0:
                    await asyncio.sleep(delay)
            if banner and res.is_open:
                raw = await grab_banner(resolved, port, timeout=timeout)
                if raw:
                    svc, ver = parse_banner(raw)
                    res.banner = ver
                    if svc:
                        res.service = f"{res.service or svc} ({svc})" if res.service else svc
            return res

        results = await asyncio.gather(*[one_port(p) for p in port_list])
        results.sort(key=lambda r: r.port)
        return ScanResult(
            host=host,
            resolved_ip=resolved,
            ports=results,
            family=family,
            resolved_family=resolved_family,
        )

    hosts = await asyncio.gather(*[one_host(h) for h in targets])
    return SweepResult(
        hosts=list(hosts),
        scanned_hosts=len(targets),
        scanned_ports=len(port_list),
    )
