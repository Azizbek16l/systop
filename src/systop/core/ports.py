"""TCP port scanner — built on asyncio, with no extra dependencies (stdlib only).

Every port gets a TCP connect attempt via `asyncio.open_connection`. If the
connection opens, the port is open and the response time (ms) is measured. On a
timeout/refusal it is closed or filtered. Everything runs in parallel (bounded by
a semaphore), so no root is needed and it is fast.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field

# The common ports a sysadmin checks most often -> service name.
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

# State codes (turned into display text by the UI).
STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_FILTERED = "filtered"

# Choosing the address family.
#   auto — whatever the OS returns first (usually IPv6 if there is one, else IPv4)
#   ipv4 / ipv6 — force that family; an error if the host does not resolve in it
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
    """The scan result for a single port."""

    port: int
    state: str = STATE_CLOSED  # open | closed | filtered
    service: str | None = None
    rtt_ms: float = 0.0  # only meaningful for open ports
    banner: str | None = None  # the service version (filled in with --banner)

    @property
    def is_open(self) -> bool:
        return self.state == STATE_OPEN


@dataclass(slots=True)
class ScanResult:
    """The full scan result for a single host."""

    host: str
    resolved_ip: str | None = None
    error: str | None = None
    ports: list[PortResult] = field(default_factory=list)
    family: str = FAMILY_AUTO  # the family that was requested
    resolved_family: str | None = None  # the one actually used: ipv4 | ipv6

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]


def default_ports() -> list[int]:
    """The list of common ports for a standard scan (sorted)."""
    return sorted(COMMON_PORTS)


def parse_ports(spec: str) -> list[int]:
    """Parses a spec such as `22,80,443` or `1-1024` or `22,80,8000-8100`.

    Invalid values are ignored; the result is sorted and free of duplicates.
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
    """Tells the family of a ready IP address (`ipv4`/`ipv6`); None for a name.

    A pure function — it never touches the network and is tested offline.
    """
    try:
        return (
            FAMILY_V6
            if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
            else FAMILY_V4
        )
    except ValueError:
        return None


async def _resolve(host: str, family: str = FAMILY_AUTO) -> tuple[str | None, str | None]:
    """Turns a host name into an IP. Returns: (address, family) or (None, None).

    `family` — with `auto` the OS chooses (AF_UNSPEC), otherwise IPv4 or IPv6 is
    forced. If there is no address in the requested family (no AAAA record, for
    instance) it returns (None, None) and the caller reports a meaningful error.

    Note: the brackets (`[::1]`) are only needed in URLs — `asyncio.
    open_connection` accepts a raw IPv6 address without them, so none are added
    here.
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

    # When IPv6 is requested we REJECT IPv4-mapped (`::ffff:1.2.3.4`) addresses.
    # They are not IPv6 — the traffic goes over IPv4. Accepting them would make
    # `scan -6` / `nc -6` silently run on IPv4, which would make the claim
    # "IPv6 is supported" a lie.
    candidates = infos
    if family == FAMILY_V6:
        candidates = [
            i for i in infos if i[0] == socket.AF_INET6 and not str(i[4][0]).startswith("::ffff:")
        ]
        if not candidates:
            return None, None

    info = candidates[0]
    address = info[4][0]
    resolved = FAMILY_V6 if info[0] == socket.AF_INET6 else FAMILY_V4

    # We KEEP the IPv6 zone identifier (`%en0`). A link-local address is
    # unusable without its zone: connecting to `fe80::1` gives "No route to
    # host" and the port is reported CLOSED. `getaddrinfo` returns the zone in a
    # separate `scope_id` field, not inside the address string.
    if resolved == FAMILY_V6 and "%" not in address:
        scope_id = info[4][3] if len(info[4]) > 3 else 0
        if scope_id:
            try:
                address = f"{address}%{socket.if_indextoname(scope_id)}"
            except (OSError, ValueError):
                address = f"{address}%{scope_id}"
    return address, resolved


async def _scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult:
    """Attempts a TCP connect to a single port and determines its state."""
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
            # No answer — most often filtered by a firewall.
            return PortResult(port=port, state=STATE_FILTERED, service=COMMON_PORTS.get(port))
        except (ConnectionRefusedError, OSError):
            # An active refusal — the port is closed.
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
    """Scans the ports on a host in parallel (IPv4 and IPv6).

    ports — the ports to check; when None the common ones are used.
    family — `auto` | `ipv4` | `ipv6` (forcing the address family).
    The result is a dataclass: the resolved IP, the family, an error message and
    the state of each port.
    """
    port_list = sorted(set(ports)) if ports else default_ports()

    resolved, resolved_family = await _resolve(host, family)
    if resolved is None:
        if family == FAMILY_V6:
            msg = (
                f"No real IPv6 address was found for '{host}' — either there is "
                "no AAAA record, or the OS returned only IPv4-mapped (`::ffff:`) "
                "results (a sign that this host has no global IPv6 route)."
            )
        elif family == FAMILY_V4:
            msg = f"No IPv4 address was found for '{host}' (no A record?)."
        else:
            msg = f"Could not turn the name '{host}' into an IP address (DNS or host error)."
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
# Sweeping a LAN (nmap -sT style) + banners (a lightweight nmap -sV)
# ===========================================================================

# nmap's "top ports" idea: the most frequently seen ports come first.
# The order matters — `--top N` takes the first N entries of this list.
TOP_PORTS: tuple[int, ...] = (
    80,
    443,
    22,
    3389,
    445,
    139,
    135,
    8080,
    21,
    23,
    25,
    110,
    143,
    53,
    3306,
    5432,
    8443,
    8000,
    5900,
    6379,
    111,
    993,
    995,
    587,
    161,
    389,
    1433,
    27017,
    9200,
    11211,
    2375,
    9090,
    5601,
    631,
    8081,
    8090,
    4081,
    8006,
    9000,
    10000,
    1521,
    2049,
    465,
    591,
    8555,
    8110,
)

# Services that send the first response THEMSELVES on connect (for a banner
# grab it is enough to wait without sending anything). The others (HTTP) need a
# request.
_GREETING_PORTS: frozenset[int] = frozenset(
    {21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6379, 11211, 27017}
)

# Ports that run over TLS. Sending plaintext HTTP to these is pointless — the
# server answers "400 Bad Request" and the banner is useless. So a TLS handshake
# is done first, and the request then travels over the encrypted channel.
_TLS_PORTS: frozenset[int] = frozenset({443, 465, 993, 995, 4081, 8006, 8443, 8834, 9443, 2376})

# Patterns for pulling the product/version out of a banner (they work on plain text).
_BANNER_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"^SSH-[\d.]+-(?P<v>[^\r\n]+)", "SSH"),
    (r"^220[- ](?P<v>[^\r\n]*(?:FTP|vsftpd|ProFTPD|FileZilla)[^\r\n]*)", "FTP"),
    (r"^220[- ](?P<v>[^\r\n]*(?:SMTP|Postfix|Exim|Sendmail)[^\r\n]*)", "SMTP"),
    (r"^\+OK (?P<v>[^\r\n]+)", "POP3"),
    (r"^\* OK (?P<v>[^\r\n]+)", "IMAP"),
    (r"(?P<v>\d+\.\d+\.\d+[-\w.]*)\x00.*mysql_native", "MySQL"),
    (r"-ERR (?P<v>[^\r\n]*unauthenticated[^\r\n]*)", "Redis (password set)"),
    (r"^\$?\d*\r?\n?# Server\r?\nredis_version:(?P<v>[\d.]+)", "Redis"),
    (r"^HTTP/[\d.]+ \d+[^\r\n]*\r?\n(?:.*\r?\n)*?Server: (?P<v>[^\r\n]+)", "HTTP"),
)


def parse_targets(spec: str, max_hosts: int = 1024) -> list[str]:
    """Turns a target spec into a list of IPs — a pure function (offline test).

    The supported forms (they may be mixed, separated by commas):
      * `192.168.1.10`           — a single address
      * `192.168.1.0/24`         — CIDR (network/broadcast are excluded)
      * `192.168.1.10-50`        — a last-octet range
      * `192.168.1.10-192.168.1.50` — a full address range
      * `example.com`            — a name (returned as is; resolution happens later)

    An IPv6 CIDR is **rejected deliberately**: a /64 holds 2^64 addresses, so a
    sweep is impossible (`topology.discover_lan6` is used for IPv6). A single
    IPv6 address, on the other hand, is accepted.

    `max_hosts` — a protective threshold: it stops a spec like /8 from filling
    up memory. The result is free of duplicates and keeps the input order.
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
                continue  # an IPv6 sweep is impossible — see the note above
            for ip in net.hosts():
                if len(out) >= max_hosts:
                    break
                add(str(ip))
            continue

        # A range (IPv6 addresses never contain '-' either, so this is safe)
        if "-" in part and ":" not in part:
            lo_s, _, hi_s = part.partition("-")
            lo_s, hi_s = lo_s.strip(), hi_s.strip()
            try:
                lo = ipaddress.ip_address(lo_s)
            except ValueError:
                add(part)  # it may be a name ("my-host")
                continue
            # "10.0.0.5-50" -> fill in the last octet
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
    """Returns the `count` most frequently seen ports (sorted)."""
    return sorted(TOP_PORTS[: max(count, 1)])


def parse_banner(data: str) -> tuple[str | None, str | None]:
    """Pulls (service, version) out of the banner text — a pure function.

    When nothing is found it returns (None, None) or (None, truncated_text), so
    that the caller can still show the raw banner.
    """
    if not data:
        return None, None
    text = data[:2048]
    for pattern, service in _BANNER_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if m:
            version = (m.groupdict().get("v") or "").strip()
            return service, version[:120] or None
    # Unrecognised — we return the first meaningful line.
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return None, first[:120] or None


async def grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
    probe: bytes | None = None,
) -> str | None:
    """Reads the banner from an open port (a lightweight variant of nmap -sV).

    Many services (SSH/SMTP/FTP/MySQL) send a greeting on connect — for those we
    simply read without sending anything. Ports that expect a request, such as
    HTTP, get a minimal probe.

    It never raises: on an error/timeout it returns None.
    """
    writer = None
    try:
        ssl_ctx = None
        if port in _TLS_PORTS:
            # A self-signed certificate is the norm on LAN devices — we do not
            # verify (the goal is inventory; for certificate quality use
            # `systop tls`).
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
        )
        if probe is None and port not in _GREETING_PORTS:
            # A port that does not greet — an HTTP request is by far the most
            # common case. ASCII is enough for the Host header: what arrives here
            # is an IP or a LAN name. The `idna` codec is DELIBERATELY not used —
            # it does not support the `errors=` argument and would raise
            # `UnicodeError`, silently destroying the banner (that was the exact
            # bug).
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
    """The scan result across many hosts."""

    hosts: list[ScanResult] = field(default_factory=list)
    scanned_hosts: int = 0
    scanned_ports: int = 0

    @property
    def responsive(self) -> list[ScanResult]:
        """The hosts with at least one open port."""
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
    """Scans several hosts in parallel (nmap `-sT` style).

    `concurrency` — the overall threshold across the WHOLE sweep (not host×port),
    so that scanning a /24 does not bury the network. On a network with
    IPS/anti-scan protection pass a `delay` (a pause after each connection) — a
    fast, broad scan gets the scanning IP blocked.

    `banner=True` — the service version is read from the open ports too (slower).
    """
    port_list = sorted(set(ports)) if ports else top_ports(20)
    if not targets or not port_list:
        return SweepResult()

    sem = asyncio.Semaphore(max(concurrency, 1))

    async def one_host(host: str) -> ScanResult:
        resolved, resolved_family = await _resolve(host, family)
        if resolved is None:
            return ScanResult(host=host, error="did not resolve", family=family)

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
