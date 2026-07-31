"""Automatic detection of network problems — the "doctor" layer.

The other `core/*` modules produce **measurements** (RTT, loss, open ports, DNS
timings). This module turns measurements into **conclusions**: what is broken,
how serious it is and what to do about it. That is, instead of "ping 12% loss"
it says "12% packet loss to the gateway — a cable or Wi-Fi problem, check the
switch port".

Architecture (project rule: tests run offline):
  * `evaluate_*` — pure functions. They take a finished measurement and return
    `Finding`s. They never touch the network => fully testable offline.
  * `run_diagnostics` — the orchestrator. It performs the network calls and
    hands the results to `evaluate_*`.

The thresholds live in one place — the `Thresholds` dataclass — so they can be
adapted per network (Wi-Fi and fibre do not deserve the same numbers).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# --- Severity levels (the order matters: it drives sorting) ------------------
SEV_CRITICAL = "critical"  # the service is down
SEV_HIGH = "high"  # serious risk or noticeable breakage
SEV_MEDIUM = "medium"  # there is a problem, but work carries on
SEV_LOW = "low"  # minor defect / worth keeping an eye on
SEV_INFO = "info"  # information, not a problem

_SEV_ORDER: dict[str, int] = {
    SEV_CRITICAL: 0,
    SEV_HIGH: 1,
    SEV_MEDIUM: 2,
    SEV_LOW: 3,
    SEV_INFO: 4,
}

# --- Categories --------------------------------------------------------------
CAT_CONNECTIVITY = "connectivity"
CAT_LATENCY = "latency"
CAT_DNS = "DNS"
CAT_IPV6 = "IPv6"
CAT_EXPOSURE = "exposure"
CAT_INTERFACE = "interface"
CAT_LAN = "LAN"
CAT_TLS = "TLS"


@dataclass(slots=True)
class Thresholds:
    """Evaluation thresholds — adjustable per network type."""

    loss_high_pct: float = 20.0  # loss above this = high
    loss_medium_pct: float = 5.0
    gateway_rtt_ms: float = 50.0  # the LAN gateway must not be slower than this
    internet_rtt_ms: float = 200.0
    jitter_ms: float = 30.0  # matters for VoIP
    dns_slow_ms: float = 500.0
    iface_error_rate: float = 0.001  # error/packet ratio (0.1%)
    tls_warn_days: int = 14


# Services that are dangerous to expose: port -> (name, severity, reason).
# Listening on "0.0.0.0"/"::" means exposed to the whole network.
RISKY_LISTENERS: dict[int, tuple[str, str, str]] = {
    2375: (
        "Docker API (no TLS)",
        SEV_CRITICAL,
        "Unauthenticated Docker API — whoever connects gets root on the host",
    ),
    23: ("Telnet", SEV_HIGH, "The password is transmitted in clear text"),
    6379: ("Redis", SEV_HIGH, "Usually passwordless — data can be read and written"),
    27017: ("MongoDB", SEV_HIGH, "Usually passwordless — the whole database is exposed"),
    9200: ("Elasticsearch", SEV_HIGH, "Usually unauthenticated — the indices are exposed"),
    11211: ("Memcached", SEV_HIGH, "No authentication + UDP amplification risk"),
    5900: ("VNC", SEV_HIGH, "Direct access to the screen"),
    445: ("SMB", SEV_MEDIUM, "File sharing — a ransomware target"),
    3389: ("RDP", SEV_MEDIUM, "Brute-force target; put it behind a VPN"),
    5432: ("PostgreSQL", SEV_MEDIUM, "Database exposed to the network"),
    3306: ("MySQL", SEV_MEDIUM, "Database exposed to the network"),
    9000: ("Portainer/PHP-FPM", SEV_MEDIUM, "Management panel exposed to the network"),
    2049: ("NFS", SEV_MEDIUM, "File system exposed to the network"),
}

_WILDCARD_HOSTS = ("0.0.0.0", "::", "*")


@dataclass(slots=True)
class Finding:
    """A single problem that was found."""

    severity: str
    category: str
    title: str
    detail: str
    fix: str | None = None
    host: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)

    @property
    def is_problem(self) -> bool:
        return self.severity != SEV_INFO


@dataclass(slots=True)
class Report:
    """A diagnostics report."""

    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    duration_ms: float = 0.0
    skipped: list[str] = field(default_factory=list)
    link_type: str = "unknown"  # wired | wifi | cellular | vpn — thresholds adapted to this

    @property
    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.is_problem]

    @property
    def worst_severity(self) -> str | None:
        probs = self.problems
        if not probs:
            return None
        return min((f.severity for f in probs), key=lambda s: _SEV_ORDER.get(s, 9))

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sorts by severity (critical -> info), then by category."""
    return sorted(findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.category, f.title))


# ===========================================================================
# Pure evaluation functions — no network, tested offline
# ===========================================================================


def evaluate_ping(
    label: str,
    address: str,
    alive: bool,
    loss_pct: float,
    avg_rtt: float,
    jitter: float,
    is_lan: bool = False,
    th: Thresholds | None = None,
) -> list[Finding]:
    """Evaluates a single ping measurement (a gateway or an internet target)."""
    th = th or Thresholds()
    out: list[Finding] = []
    rtt_limit = th.gateway_rtt_ms if is_lan else th.internet_rtt_ms
    where = "gateway" if is_lan else "internet target"

    if not alive or loss_pct >= 100.0:
        out.append(
            Finding(
                severity=SEV_CRITICAL if is_lan else SEV_HIGH,
                category=CAT_CONNECTIVITY,
                title=f"{label} is not responding",
                detail=f"{address} — 100% packet loss, the {where} could not be reached.",
                fix=(
                    "Check the cable/Wi-Fi connection, the interface state and the gateway address."
                    if is_lan
                    else "Check the ISP link or the firewall's ICMP rule."
                ),
                host=address,
                evidence={"loss_pct": loss_pct, "alive": alive},
            )
        )
        return out  # without a reply, RTT/jitter are meaningless

    if loss_pct >= th.loss_high_pct:
        sev = SEV_HIGH
    elif loss_pct >= th.loss_medium_pct:
        sev = SEV_MEDIUM
    elif loss_pct > 0:
        sev = SEV_LOW
    else:
        sev = None
    if sev:
        out.append(
            Finding(
                severity=sev,
                category=CAT_CONNECTIVITY,
                title=f"{label}: {loss_pct:.0f}% packet loss",
                detail=f"{address} — {loss_pct:.1f}% of packets never arrived.",
                fix=(
                    "Check the cable/connector, the switch port or the Wi-Fi signal."
                    if is_lan
                    else "Check the ISP link and the hops along the path (mtr)."
                ),
                host=address,
                evidence={"loss_pct": loss_pct},
            )
        )

    if avg_rtt > rtt_limit:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_LATENCY,
                title=f"{label}: latency is high ({avg_rtt:.0f} ms)",
                detail=f"{address} — average RTT {avg_rtt:.1f} ms, expected threshold "
                f"{rtt_limit:.0f} ms.",
                fix=(
                    "On a LAN this should be 1-10 ms — check switch load, a duplex "
                    "mismatch or Wi-Fi interference."
                    if is_lan
                    else "Trace the path with mtr — find which hop is adding the delay."
                ),
                host=address,
                evidence={"avg_rtt_ms": avg_rtt, "limit_ms": rtt_limit},
            )
        )

    if jitter > th.jitter_ms:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_LATENCY,
                title=f"{label}: jitter is high ({jitter:.0f} ms)",
                detail=f"{address} — latency varies by {jitter:.1f} ms. VoIP/video calls "
                "will drop out and sound metallic.",
                fix="Configure QoS, check link saturation and Wi-Fi interference.",
                host=address,
                evidence={"jitter_ms": jitter},
            )
        )
    return out


def evaluate_interface(
    name: str,
    is_up: bool,
    ipv4: str | None,
    errors: int = 0,
    drops: int = 0,
    packets: int = 0,
    th: Thresholds | None = None,
) -> list[Finding]:
    """Evaluates the interface state and its error counters."""
    th = th or Thresholds()
    out: list[Finding] = []

    if is_up and ipv4 and ipv4.startswith("169.254."):
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_INTERFACE,
                title=f"{name}: APIPA address ({ipv4})",
                detail="The interface got no address from DHCP and assigned itself "
                "169.254.x.x — it is effectively not on the network.",
                fix="Check the DHCP server, the VLAN and the cable connection.",
                host=name,
                evidence={"ipv4": ipv4},
            )
        )

    if packets > 0:
        err_rate = errors / packets
        drop_rate = drops / packets
        if err_rate > th.iface_error_rate:
            out.append(
                Finding(
                    severity=SEV_HIGH,
                    category=CAT_INTERFACE,
                    title=f"{name}: {err_rate * 100:.2f}% packet errors",
                    detail=f"{errors} errors / {packets} packets. This is a hardware "
                    "signature — a bad cable, connector, SFP or port.",
                    fix="Try swapping the cable, move to a different switch port, "
                    "check the duplex/speed settings.",
                    host=name,
                    evidence={"errors": errors, "packets": packets, "rate": err_rate},
                )
            )
        if drop_rate > th.iface_error_rate:
            out.append(
                Finding(
                    severity=SEV_MEDIUM,
                    category=CAT_INTERFACE,
                    title=f"{name}: {drop_rate * 100:.2f}% packet drops",
                    detail=f"{drops} dropped / {packets} packets. Buffers are full or "
                    "the CPU cannot keep up.",
                    fix="Review the interface load, the ring buffer size and the offload settings.",
                    host=name,
                    evidence={"drops": drops, "packets": packets, "rate": drop_rate},
                )
            )
    return out


def evaluate_listeners(
    listeners: list[tuple[str, int, str | None]],
) -> list[Finding]:
    """Evaluates the list of listening services.

    `listeners` — (bind_host, port, process) triples. Only the ones listening on
    a wildcard (`0.0.0.0`/`::`) count as dangerous: a service bound to localhost
    is not exposed to the network.
    """
    out: list[Finding] = []
    seen: set[int] = set()
    for host, port, proc in listeners:
        if host not in _WILDCARD_HOSTS or port in seen:
            continue
        info = RISKY_LISTENERS.get(port)
        if not info:
            continue
        seen.add(port)
        name, sev, why = info
        out.append(
            Finding(
                severity=sev,
                category=CAT_EXPOSURE,
                title=f"{name} is exposed to the whole network (port {port})",
                detail=f"Listening on {host}:{port}"
                + (f" (process: {proc})" if proc else "")
                + f". {why}.",
                fix=f"Bind it to localhost only (127.0.0.1:{port}) or restrict it with "
                "a firewall; enable authentication and TLS if it must stay reachable.",
                evidence={"bind": host, "port": port, "process": proc},
            )
        )
    return out


def evaluate_remote_exposure(
    services: list[tuple[str, int]],
) -> list[Finding]:
    """Evaluates dangerous open ports on OTHER hosts on the LAN — pure function.

    DELIBERATELY kept separate from `evaluate_listeners`. That one says "a
    service on your machine is exposed to the network" and advises "bind it to
    localhost" — for a remote device that advice is **wrong**: it is not your
    service and you cannot bind it. Mixing the two sent the user off to fix
    their own machine while the problem sat on the neighbour's NVR.

    `services` — `(ip, port)` pairs.
    """
    out: list[Finding] = []
    by_port: dict[int, list[str]] = {}
    for ip, port in services:
        if port in RISKY_LISTENERS:
            by_port.setdefault(port, []).append(ip)
    for port, ips in sorted(by_port.items()):
        name, sev, why = RISKY_LISTENERS[port]
        # A remote finding sits one level lower: it is not your host, but it
        # still matters as a risk present on the network.
        lowered = {SEV_CRITICAL: SEV_HIGH, SEV_HIGH: SEV_MEDIUM}.get(sev, sev)
        out.append(
            Finding(
                severity=lowered,
                category=CAT_EXPOSURE,
                title=f"{name} exposed on the network: {len(ips)} hosts (port {port})",
                detail=f"Addresses: {', '.join(sorted(ips)[:6])}. {why}. These are OTHER "
                "devices — it is those devices, or the segment firewall, that need "
                "configuring, not your own machine.",
                fix=f"Identify the devices and restrict port {port} with a VLAN/ACL.",
                evidence={"port": port, "hosts": sorted(ips)},
            )
        )
    return out


def evaluate_ipv6(
    link_local_count: int,
    global_count: int,
    has_ipv6_internet: bool | None = None,
) -> list[Finding]:
    """Evaluates the state of IPv6.

    The most common real-world problem: the devices have IPv6 addresses (SLAAC
    hands them out automatically) but there is no global route. Applications
    then try IPv6 first and sit through a timeout, so **everything feels slow**
    — with no visible cause, because IPv4 eventually works.
    """
    out: list[Finding] = []
    if link_local_count == 0 and global_count == 0:
        out.append(
            Finding(
                severity=SEV_INFO,
                category=CAT_IPV6,
                title="No IPv6 neighbours found",
                detail="IPv6 is not in use on this network (or the neighbour table is empty).",
                evidence={"link_local": 0, "global": 0},
            )
        )
        return out

    if global_count == 0 and link_local_count > 0:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_IPV6,
                title=f"IPv6 is link-local only ({link_local_count} hosts)",
                detail="The devices have fe80::/10 addresses but no global/ULA "
                "address. Applications may try IPv6 first and sit through a "
                "timeout — the invisible cause behind 'the internet is slow'.",
                fix="Either configure IPv6 properly (router advertisement + prefix) "
                "or disable it on the devices entirely — the half-configured state "
                "is the worst one.",
                evidence={"link_local": link_local_count, "global": global_count},
            )
        )
    if has_ipv6_internet is False and global_count > 0:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_IPV6,
                title="IPv6 address present, but no IPv6 internet",
                detail=f"{global_count} global IPv6 addresses exist, yet no external "
                "host could be reached over IPv6. This is a black-hole state.",
                fix="Check the router advertisement and the IPv6 route; if it cannot "
                "be fixed, disable IPv6 (better than a half-working one).",
                evidence={"global": global_count},
            )
        )
    return out


def is_real_device_mac(mac: str | None) -> bool:
    """Says whether a MAC belongs to a real device (unicast) — pure function.

    REQUIRED for duplicate detection: broadcast (`ff:ff:ff:ff:ff:ff`) and
    multicast MACs are naturally bound to several IPs at once, and flagging them
    as a "duplicate MAC" is a pure false positive.

    The multicast marker is the lowest bit of the first octet (the I/G bit)
    being 1: IPv4 multicast `01:00:5e:...`, IPv6 multicast `33:33:...`.
    """
    if not mac:
        return False
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    try:
        first = int(parts[0], 16)
    except ValueError:
        return False
    if all(p.lower() == "ff" for p in parts):
        return False  # broadcast
    return not (first & 0x01)  # I/G bit -> multicast


def evaluate_lan(
    hosts: list[tuple[str, str | None, bool]],
    gateway: str | None = None,
) -> list[Finding]:
    """Evaluates the LAN inventory — `(ip, mac, is_gateway)` triples.

    One MAC appearing on several IPs is either a router/NAT (normal) or ARP
    spoofing / a duplicate configuration (a problem). If the gateway's MAC turns
    up on other IPs as well, that is especially suspicious.
    """
    out: list[Finding] = []
    by_mac: dict[str, list[str]] = {}
    for ip, mac, _ in hosts:
        if is_real_device_mac(mac):
            by_mac.setdefault(mac, []).append(ip)

    gw_mac = next((mac for ip, mac, _ in hosts if ip == gateway and mac), None)

    for mac, ips in by_mac.items():
        if len(ips) < 2:
            continue
        is_gw = mac == gw_mac
        out.append(
            Finding(
                severity=SEV_HIGH if is_gw else SEV_MEDIUM,
                category=CAT_LAN,
                title=f"One MAC on {len(ips)} IPs: {mac}",
                detail=f"{mac} was seen on {', '.join(sorted(ips)[:6])}."
                + (
                    " This is the gateway MAC — ARP spoofing is possible."
                    if is_gw
                    else " This may be a router/NAT, or a duplicate IP."
                ),
                fix=(
                    "Pin the gateway MAC with a static ARP entry and check that no "
                    "unexpected device is on the network."
                    if is_gw
                    else "Confirm the device is a router/proxy; otherwise resolve the duplicate IP."
                ),
                evidence={"mac": mac, "ips": sorted(ips)},
            )
        )
    return out


def evaluate_web(
    services: list[tuple[str, int, str, bool, str, str | None]],
) -> list[Finding]:
    """Evaluates web services — `(ip, port, scheme, is_admin, risk, product)`.

    The headline finding: **an admin panel over unencrypted HTTP**. Logging into
    such a panel sends the username and password across the network in clear text.
    """
    out: list[Finding] = []
    for ip, port, scheme, is_admin, risk, product in services:
        if not is_admin:
            continue
        label = product or "management panel"
        if risk == "high":
            out.append(
                Finding(
                    severity=SEV_HIGH,
                    category=CAT_EXPOSURE,
                    title=f"{label}: password in clear text ({ip}:{port})",
                    detail=f"http://{ip}:{port}/ — the admin panel is on HTTP and uses "
                    "HTTP Basic/Digest authentication. The username and password "
                    "travel the network unencrypted.",
                    fix="Move it to HTTPS, or leave the panel reachable only from a "
                    "VPN/trusted network.",
                    host=ip,
                    evidence={"port": port, "scheme": scheme, "product": product},
                )
            )
        elif risk == "medium":
            out.append(
                Finding(
                    severity=SEV_MEDIUM,
                    category=CAT_EXPOSURE,
                    title=f"{label}: admin panel over HTTP ({ip}:{port})",
                    detail=f"http://{ip}:{port}/ — the management interface runs on an "
                    "unencrypted channel.",
                    fix="Install a TLS certificate and move it to HTTPS.",
                    host=ip,
                    evidence={"port": port, "scheme": scheme, "product": product},
                )
            )
    return out


def evaluate_dns(
    system_ok: bool,
    system_error: str | None,
    resolvers: list[tuple[str, bool, float, bool]],
    th: Thresholds | None = None,
) -> list[Finding]:
    """Evaluates the DNS state — `(server, ok, elapsed_ms, is_system)` quadruples.

    **`is_system` decides the severity.** This function used to look only at the
    public servers (8.8.8.8, 1.1.1.1...), and when none of them answered it
    returned HIGH: "All DNS servers are unresponsive / check the firewall for
    UDP/53". On corporate networks outbound port 53 is closed **deliberately** —
    so a completely healthy network produced a false warning and `exit 2`, and on
    top of that the remediation it gave was wrong.

    The rule now:

    * the system resolvers are dead — a REAL failure (`high`);
    * the system works and only the public ones are blocked — that is ordinary
      policy (`info`, not a problem);
    * no system resolver could be identified at all — the old, cautious verdict
      is kept.

    The old triple (without `is_system`) is still accepted — everything is then
    treated as "not system" and the old behaviour is preserved.
    """
    th = th or Thresholds()
    out: list[Finding] = []
    # Do not fall over when the caller passes the old triple.
    rows = [(r[0], r[1], r[2], r[3] if len(r) > 3 else False) for r in resolvers]

    if not system_ok:
        out.append(
            Finding(
                severity=SEV_CRITICAL,
                category=CAT_DNS,
                title="System DNS is not working",
                detail=f"The name could not be turned into an IP: "
                f"{system_error or 'reason unknown'}. In this state nothing opens by "
                "name — no site, no service.",
                fix="Check that /etc/resolv.conf (or the DNS handed out by DHCP) is "
                "correct and that the DNS server is reachable.",
                evidence={"error": system_error},
            )
        )

    system_rows = [r for r in rows if r[3]]
    public_rows = [r for r in rows if not r[3]]
    dead_system = [s for s, ok, _, _ in system_rows if not ok]
    dead_public = [s for s, ok, _, _ in public_rows if not ok]
    dead = [s for s, ok, _, _ in rows if not ok]

    if system_rows and len(dead_system) == len(system_rows):
        # The resolver the machine itself uses is unresponsive — always a problem.
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DNS,
                title="System DNS server is not responding",
                detail=f"None of the {len(system_rows)} resolvers configured on this "
                f"machine answered: {', '.join(dead_system[:5])}. Nothing will open "
                "by name once the cache expires.",
                fix="Check the path to the resolver (ping) and make sure UDP/53 is open.",
                evidence={"dead": dead_system, "scope": "system"},
            )
        )
    elif system_rows and public_rows and len(dead_public) == len(public_rows):
        # The system works and only the external servers are blocked — on MANY
        # networks that is deliberate policy, not a failure. INFO => is_problem
        # is False, so it does not affect the exit code.
        out.append(
            Finding(
                severity=SEV_INFO,
                category=CAT_DNS,
                title="Egress to public DNS servers is blocked",
                detail=f"The system resolver works, but {len(public_rows)} public "
                f"servers did not answer: {', '.join(dead_public[:5])}. At many "
                "organisations this is deliberate (only internal DNS is allowed).",
                fix=None,
                evidence={"dead": dead_public, "scope": "public"},
            )
        )
    elif dead and len(dead) == len(rows) and rows:
        # No system resolver was identified — the old, cautious verdict.
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DNS,
                title="All DNS servers are unresponsive",
                detail=f"None of the {len(rows)} servers checked answered: {', '.join(dead[:5])}.",
                fix="Check that the firewall is not blocking UDP/53 and TCP/53.",
                evidence={"dead": dead},
            )
        )
    elif dead:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_DNS,
                title=f"{len(dead)} DNS servers did not answer",
                detail=f"No answer from: {', '.join(dead[:5])}. The others work.",
                fix="Remove the dead servers from the list.",
                evidence={"dead": dead},
            )
        )

    # Slowness is measured over the SYSTEM resolvers only (when they were
    # identified): 120 ms to a public server is a normal distance, whereas
    # 120 ms to the system resolver really does delay every page load.
    measured = system_rows or rows
    slow = [(s, ms) for s, ok, ms, _ in measured if ok and ms > th.dns_slow_ms]
    if slow:
        worst = max(slow, key=lambda x: x[1])
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_DNS,
                title=f"DNS is slow ({worst[1]:.0f} ms)",
                detail=f"{len(slow)} servers answered slower than {th.dns_slow_ms:.0f} "
                f"ms; the slowest is {worst[0]} — {worst[1]:.0f} ms. Every page load "
                "is delayed by that much.",
                fix="Pick a closer or faster resolver (a local caching server, say).",
                evidence={"slow": slow},
            )
        )
    return out


def evaluate_tls(
    host: str,
    days_left: int | None,
    error: str | None = None,
    th: Thresholds | None = None,
) -> list[Finding]:
    """Evaluates how long the TLS certificate has left."""
    th = th or Thresholds()
    if error:
        return [
            Finding(
                severity=SEV_HIGH,
                category=CAT_TLS,
                title=f"{host}: TLS could not be checked",
                detail=error,
                fix="Check that the certificate and the port are correct.",
                host=host,
            )
        ]
    if days_left is None:
        return []
    if days_left < 0:
        return [
            Finding(
                severity=SEV_CRITICAL,
                category=CAT_TLS,
                title=f"{host}: certificate has EXPIRED",
                detail=f"It expired {abs(days_left)} days ago. Browsers show a warning "
                "and API clients refuse to connect.",
                fix="Renew the certificate immediately (automate it with certbot/ACME).",
                host=host,
                evidence={"days_left": days_left},
            )
        ]
    if days_left <= th.tls_warn_days:
        return [
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_TLS,
                title=f"{host}: certificate expires in {days_left} days",
                detail=f"{days_left} days left before expiry.",
                fix="Set up automatic renewal (ACME).",
                host=host,
                evidence={"days_left": days_left},
            )
        ]
    return []


# ===========================================================================
# Orchestrator — network calls + the pure evaluators above
# ===========================================================================

# Management device kinds — the `device_kind` values `webscan` produces.
# The inventory that matters most to a sysadmin: the devices that run the network.
#
# This is a DATA CONTRACT with `core/webscan.py`, not display text: the tokens
# must match its `Fingerprint.device_kind` values exactly, or `--mgmt` filters
# nothing and says so with a straight face.
MANAGEMENT_KINDS: frozenset[str] = frozenset(
    {"firewall", "router", "network", "hypervisor", "camera/NVR", "telephony", "NAS"}
)


def is_management_device(device_kind: str | None, is_gateway: bool = False) -> bool:
    """Is the device a network-managing kind (router/firewall/switch/AP/NVR)?"""
    return is_gateway or (device_kind in MANAGEMENT_KINDS if device_kind else False)


async def run_diagnostics(
    quick: bool = False,
    include_web: bool = True,
    include_ipv6: bool = True,
    tls_hosts: list[str] | None = None,
    th: Thresholds | None = None,
    max_hosts: int = 64,
) -> Report:
    """Runs every check and returns a report sorted by severity.

    `quick=True` skips the slow stages (web scan, IPv6 multicast). Every stage
    sits in its own `try`: if one falls over the rest carry on (the reason is
    written to `report.skipped`) — a diagnostics tool must not be the thing that
    crashes.
    """
    started = time.perf_counter()
    report = Report()
    findings: list[Finding] = []

    from systop.core import netinfo, ping, topology

    # --- 0. Detect the link type and ADAPT the thresholds -------------------
    # One absolute number cannot be right on every network: 50 ms to the gateway
    # is a disaster on copper, normal on Wi-Fi, good on LTE. A value the user set
    # explicitly in the config wins.
    link = LINK_UNKNOWN
    try:
        from systop.core import wifi as _wifi_probe

        _w = await _wifi_probe.status()
        _iface = netinfo.primary_interface()
        link = classify_link(
            _iface.name if _iface else None,
            wifi_connected=_w.connected,
            wifi_interface=_w.interface,
        )
    except Exception:  # noqa: BLE001 — if undetectable, use the `unknown` profile
        link = LINK_UNKNOWN
    th = thresholds_for_link(link, th)
    report.link_type = link

    # --- 1. Interfaces -------------------------------------------------------
    try:
        import psutil

        counters = psutil.net_io_counters(pernic=True)
        for iface in netinfo.list_interfaces():
            c = counters.get(iface.name)
            packets = (c.packets_recv + c.packets_sent) if c else 0
            errors = (c.errin + c.errout) if c else 0
            drops = (c.dropin + c.dropout) if c else 0
            findings += evaluate_interface(
                iface.name, iface.is_up, iface.ipv4, errors, drops, packets, th
            )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001 — diagnostics must not stop here
        report.skipped.append(f"interface: {type(exc).__name__}")

    # --- 2. Gateway + internet ping -----------------------------------------
    gateway = None
    try:
        gateway = netinfo.default_gateway()
        targets: dict[str, str] = {}
        if gateway:
            targets["Gateway"] = gateway
        targets["Cloudflare"] = "1.1.1.1"
        if not quick:
            targets["Google"] = "8.8.8.8"
        results = await ping.ping_many(targets, count=3 if quick else 5, timeout=2.0)
        for r in results:
            findings += evaluate_ping(
                r.label,
                r.address,
                r.alive,
                r.loss_pct,
                r.avg_rtt,
                r.jitter,
                is_lan=(r.address == gateway),
                th=th,
            )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"ping: {type(exc).__name__}")

    # --- 2b. IPv6 REACHABILITY (not merely its presence) --------------------
    # Finding IPv6 hosts is one thing; TRAFFIC actually flowing over IPv6 is
    # another. On a dual-stack network broken IPv6 is invisible while IPv4 still
    # works, and it shows up as "some sites are slow" (the application tries IPv6
    # first and sits through a timeout).
    if include_ipv6 and not quick:
        try:
            # IMPORTANT: IPv6 reachability is probed only when a GLOBAL IPv6
            # address exists. Without an address, getting no reply is natural —
            # reporting that as a problem is pure noise, and it is already
            # covered by the "IPv6 is link-local only" finding.
            has_global6 = any(i.ipv6_global for i in netinfo.list_interfaces())
            if has_global6:
                gw6 = netinfo.default_gateway_v6()
                targets6: dict[str, str] = {}
                if gw6 and not gw6.startswith("fe80"):
                    targets6["IPv6 gateway"] = gw6
                targets6["IPv6 Cloudflare"] = "2606:4700:4700::1111"
                r6 = await ping.ping_many(targets6, count=3, timeout=2.0)
                for x in r6:
                    findings += evaluate_ping(
                        x.label,
                        x.address,
                        x.alive,
                        x.loss_pct,
                        x.avg_rtt,
                        x.jitter,
                        is_lan=(x.address == gw6),
                        th=th,
                    )
                # An address exists but nothing is reachable — a black hole.
                if not any(x.alive for x in r6):
                    findings += evaluate_ipv6(0, 1, has_ipv6_internet=False)
                report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"IPv6 reachability: {type(exc).__name__}")

    # --- 3. Exposed listening services (local host) -------------------------
    try:
        from systop.core import connections

        scan = await connections.scan_connections(states=["LISTEN"])
        if not scan.permitted:
            # IMPORTANT: `checks_run` is NOT incremented here. Otherwise the
            # report reads "N checks run, no problems" while the security check
            # never ran at all — false reassurance. The INFO finding is visible
            # to `--json` consumers too (is_problem=False, no effect on the exit
            # code).
            report.skipped.append(f"listeners: permission denied ({scan.error})")
            findings.append(
                Finding(
                    severity=SEV_INFO,
                    category=CAT_EXPOSURE,
                    title="Exposed services were not checked",
                    detail=(
                        "This system does not allow reading the socket table, so "
                        "exposed ports (Docker API, Redis, telnet...) were NOT "
                        "CHECKED — that is not the same as 'no problems'."
                    ),
                    fix="For a full check: sudo systop doctor",
                    evidence={"reason": scan.error or "unknown"},
                )
            )
        else:
            listeners: list[tuple[str, int, str | None]] = []
            for c in scan.conns:
                host, _, port_s = c.laddr.rpartition(":")
                try:
                    port = int(port_s)
                except ValueError:
                    continue
                listeners.append((host.strip("[]"), port, c.process))
            findings += evaluate_listeners(listeners)
            report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"listeners: {type(exc).__name__}")

    # --- 4. DNS --------------------------------------------------------------
    try:
        from systop.core import dns as dns_mod

        d = await dns_mod.diagnose_dns("example.com")
        findings += evaluate_dns(
            system_ok=bool(d.system_addresses),
            system_error=d.system_error,
            resolvers=[(r.server, r.ok, r.rtt_ms, r.is_system) for r in d.resolvers],
            th=th,
        )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"DNS: {type(exc).__name__}")

    # --- 5. LAN inventory (IPv4) --------------------------------------------
    lan_hosts: list[topology.LanHost] = []
    reported_dup_macs: set[str] = set()
    try:
        lan_hosts = await topology.discover_lan(max_hosts=max_hosts)
        lan_findings = evaluate_lan([(h.ip, h.mac, h.is_gateway) for h in lan_hosts], gateway)
        findings += lan_findings
        # Stage 13 (arpwatch) rediscovers the very same duplicate. Reporting one
        # fact twice costs the report its credibility, so remember the MACs seen
        # here.
        reported_dup_macs = {
            str(f.evidence.get("mac")) for f in lan_findings if f.evidence.get("mac")
        }
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"LAN: {type(exc).__name__}")

    # --- 6. IPv6 -------------------------------------------------------------
    if include_ipv6 and not quick:
        try:
            v6 = await topology.discover_lan6(timeout=2.0)
            ll = sum(1 for h in v6 if h.is_link_local)
            findings += evaluate_ipv6(ll, len(v6) - ll)
            report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"IPv6: {type(exc).__name__}")

    # --- 7. Web/admin panels ------------------------------------------------
    if include_web and not quick and lan_hosts:
        try:
            from systop.core import webscan

            ips = [h.ip for h in lan_hosts][:max_hosts]
            services = await webscan.discover_web(
                ips,
                ports=list(webscan.QUICK_WEB_PORTS),
                timeout=3.0,
                concurrency=16,
                delay=0.05,
            )
            findings += evaluate_web(
                [(s.ip, s.port, s.scheme, s.is_admin, s.risk, s.product) for s in services]
            )
            report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"web: {type(exc).__name__}")

    # --- 7b. Exposed ports on IPv6 hosts (the ones found via NDP) -----------
    # An IPv6 /64 cannot be swept, BUT the exact addresses found in the neighbour
    # table can be scanned — that is how "are there exposed ports on IPv6?" gets
    # answered at all.
    if include_ipv6 and not quick:
        try:
            from systop.core.ports import scan_targets

            # Do not scan OURSELVES: `ndp -an` also lists our own `fe80::…%en0`
            # addresses, and scanning those only to say "these are OTHER devices,
            # go configure them" makes no sense.
            own_v6 = {a.split("%")[0] for i in netinfo.list_interfaces() for a, _ in i.ipv6}
            v6_hosts = [
                h.ip
                for h in await topology.discover_lan6(include_link_local=True)
                if h.ip.split("%")[0] not in own_v6
            ][:max_hosts]
            if v6_hosts:
                sweep = await scan_targets(
                    v6_hosts,
                    ports=[22, 23, 80, 443, 445, 3389, 2375, 6379, 27017],
                    timeout=1.0,
                    concurrency=16,
                    family="ipv6",
                )
                # IMPORTANT: these are REMOTE hosts. Using `evaluate_listeners`
                # here would give the WRONG advice — "your service is exposed,
                # bind it to localhost" — when it is a neighbour's device.
                remote6 = [
                    (h.resolved_ip or h.host, p.port) for h in sweep.hosts for p in h.open_ports
                ]
                findings += evaluate_remote_exposure(remote6)
                report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"IPv6 ports: {type(exc).__name__}")

    # --- 8b. Wi-Fi (when the hardware exists) -------------------------------
    try:
        from systop.core import wifi as wifi_mod

        w = await wifi_mod.status()
        overlap = 0
        if w.channel and w.is_24ghz:
            overlap = len(
                wifi_mod.overlapping_channels(w.channel, w.band, w.width_mhz, w.neighbours)
            )
        findings += evaluate_wifi(
            available=w.available,
            connected=w.connected,
            rssi=w.rssi_dbm,
            snr=w.snr_db,
            band=w.band,
            channel=w.channel,
            width_mhz=w.width_mhz,
            phy_gen=w.phy_generation,
            card_gen=w.supported_generation,
            tx_rate=w.tx_rate_mbps,
            security=w.security,
            five_ghz_available=w.five_ghz_available,
            overlap_count=overlap,
        )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"Wi-Fi: {type(exc).__name__}")

    # --- 8c. Link speed (cable/duplex fault) --------------------------------
    try:
        # Virtual interfaces are skipped — link speed is meaningless on them.
        virtual = ("utun", "awdl", "llw", "bridge", "vmnet", "veth", "docker", "lo")
        for iface in netinfo.list_interfaces():
            findings += evaluate_link_speed(
                iface.name,
                iface.speed_mbps,
                iface.is_up,
                is_virtual=iface.name.startswith(virtual),
            )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"link speed: {type(exc).__name__}")

    # --- 9. Time (NTP) ------------------------------------------------------
    try:
        from systop.core import ntp

        rep = await ntp.check_time()
        findings += evaluate_ntp(
            responded=len(rep.responded),
            total=len(rep.results),
            median_offset_s=rep.median_offset_s,
            th=th,
        )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"NTP: {type(exc).__name__}")

    # --- 10. Routing table ---------------------------------------------------
    try:
        from systop.core import routes as routes_mod

        table = await routes_mod.list_routes()
        alive = await routes_mod.check_next_hops(table)
        # The ping in stage 2 may already have reported a dead gateway as
        # CRITICAL — do not repeat it.
        already_dead = {
            f.host
            for f in findings
            if f.category == CAT_CONNECTIVITY and f.severity == SEV_CRITICAL and f.host
        }
        dead_all = [gw for gw, ok in alive.items() if not ok and gw not in already_dead]

        def _gw_family(gw: str) -> str:
            return "ipv6" if ":" in gw.split("%")[0] else "ipv4"

        findings += evaluate_routes(
            default_count=len(table.routable_defaults_for("ipv4")),
            gateways=[g for g in table.routable_default_gateways if _gw_family(g) == "ipv4"],
            dead_gateways=[g for g in dead_all if _gw_family(g) == "ipv4"],
            has_vpn_split=table.has_vpn_split_hack,
            family="ipv4",
        )
        # The IPv6 route is evaluated only when the host has a GLOBAL IPv6
        # address. On an IPv4-only network (most of the world) a missing IPv6
        # default is entirely normal — reporting it as a problem is pure noise,
        # and it is already covered by `evaluate_ipv6`.
        if any(i.ipv6_global for i in netinfo.list_interfaces()):
            findings += evaluate_routes(
                default_count=len(table.routable_defaults_for("ipv6")),
                gateways=[g for g in table.routable_default_gateways if _gw_family(g) == "ipv6"],
                dead_gateways=[g for g in dead_all if _gw_family(g) == "ipv6"],
                family="ipv6",
            )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"route: {type(exc).__name__}")

    # --- 11. Path MTU --------------------------------------------------------
    if not quick and gateway:
        try:
            from systop.core import mtu as mtu_mod

            res = await mtu_mod.discover_path_mtu("1.1.1.1", timeout=2.0)
            findings += evaluate_mtu(res.path_mtu, res.error)
            report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"MTU: {type(exc).__name__}")

    # --- 12. DHCP ------------------------------------------------------------
    try:
        from systop.core import dhcp as dhcp_mod

        lease = await dhcp_mod.current_lease()
        probe = await dhcp_mod.discover_servers(listen_s=2.0) if not quick else None
        servers = list(probe.servers) if probe else []
        if lease and lease.identity not in servers:
            servers.append(lease.identity)
        findings += evaluate_dhcp(
            servers=servers,
            lease_server=lease.identity if lease else None,
            partial=bool(probe and probe.partial),
        )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"DHCP: {type(exc).__name__}")

    # --- 13. ARP watch (diff against the baseline) --------------------------
    try:
        from systop.core import arpwatch

        # `update=False` — diagnostics must NOT change state; the baseline is
        # only refreshed by the `systop arpwatch` command.
        diff = await arpwatch.check(update=False)
        findings += evaluate_arpwatch(
            mac_changes=[(c.ip, c.old_mac or "?", c.new_mac or "?") for c in diff.mac_changes],
            duplicates=[
                (c.new_mac or "?", [c.ip, *c.extra_ips])
                for c in diff.changes
                if c.kind == "duplicate_mac" and c.new_mac not in reported_dup_macs
            ],
            first_run=diff.first_run,
        )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"ARP watch: {type(exc).__name__}")

    # --- 8. TLS (only the hosts that were asked for) ------------------------
    if tls_hosts:
        try:
            from systop.core import tls as tls_mod

            for host in tls_hosts:
                res = await tls_mod.check_tls(host)
                findings += evaluate_tls(host, res.days_left, res.error, th)
            report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"TLS: {type(exc).__name__}")

    report.findings = sort_findings(findings)
    report.duration_ms = (time.perf_counter() - started) * 1000.0
    return report


# --- New categories (0.6.0) --------------------------------------------------
CAT_TIME = "time"
CAT_ROUTE = "route"
CAT_MTU = "MTU"
CAT_DHCP = "DHCP"


def evaluate_ntp(
    responded: int,
    total: int,
    median_offset_s: float | None,
    th: Thresholds | None = None,
) -> list[Finding]:
    """Evaluates clock skew — pure function."""
    out: list[Finding] = []
    if total and responded == 0:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_TIME,
                title="NTP servers did not answer",
                detail=f"None of the {total} NTP servers answered — the clock could "
                "not be checked (UDP/123 may be blocked).",
                fix="Allow outbound UDP/123 in the firewall, or point at a local NTP server.",
                evidence={"servers": total},
            )
        )
        return out
    if median_offset_s is None:
        return out

    a = abs(median_offset_s)
    if a >= 300:
        sev, why = (
            SEV_CRITICAL,
            (
                "Kerberos/Active Directory REJECTS authentication above 300 seconds "
                "of skew — domain logon stops working."
            ),
        )
    elif a >= 30:
        sev, why = (
            SEV_HIGH,
            ("TLS certificates can wrongly appear 'expired' and TOTP/2FA codes can be rejected."),
        )
    elif a >= 1:
        sev, why = SEV_MEDIUM, "Logs will not line up with those of other servers."
    else:
        return out
    out.append(
        Finding(
            severity=sev,
            category=CAT_TIME,
            title=f"Clock has drifted: {median_offset_s:+.1f} s",
            detail=f"Median offset across {responded}/{total} NTP servers is "
            f"{median_offset_s:+.2f} seconds. {why}",
            fix="Synchronise the time over NTP (macOS: Settings > Date & Time; "
            "Linux: `timedatectl set-ntp true`; Windows: `w32tm /resync`).",
            evidence={"offset_s": median_offset_s, "responded": responded},
        )
    )
    return out


def evaluate_routes(
    default_count: int,
    gateways: list[str],
    dead_gateways: list[str],
    has_vpn_split: bool = False,
    family: str = "ipv4",
) -> list[Finding]:
    """Evaluates the routing table — pure function.

    `default_count`/`gateways` must be passed as the MEANINGFUL defaults
    (`RouteTable.routable_defaults`); otherwise the bare `fe80::%utunN` entries
    macOS keeps around produce a false "several default routes" warning.

    `family` is `ipv4` or `ipv6`. The two are evaluated separately, DELIBERATELY:

    * no IPv4 default — nothing can leave the machine at all, `critical`;
    * no IPv6 default — everything still works over IPv4, `high`, and the caller
      only asks for it when the host has a global IPv6 address.

    Counting the two together produced a permanent false "No default route" on
    IPv4-only networks (most of the world).
    """
    is_v6 = family == "ipv6"
    tag = "IPv6 " if is_v6 else ""
    out: list[Finding] = []
    if default_count == 0:
        out.append(
            Finding(
                severity=SEV_HIGH if is_v6 else SEV_CRITICAL,
                category=CAT_ROUTE,
                title=f"No {tag}default route" if is_v6 else "No default route",
                detail=(
                    "The routing table has no IPv6 default (::/0) — nothing can go "
                    "out over IPv6 (IPv4 keeps working)."
                    if is_v6
                    else "The routing table has no default (0.0.0.0/0) — nothing "
                    "leaves the local network at all."
                ),
                fix=(
                    "Check that the router is sending RAs (Router Advertisements)."
                    if is_v6
                    else "Check whether DHCP failed to hand out a gateway, or review "
                    "the manual configuration."
                ),
                evidence={"family": family},
            )
        )
        return out

    if default_count > 1:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_ROUTE,
                title=f"{default_count} {tag}default routes",
                detail=f"Several default gateways: {', '.join(gateways[:4])}. Traffic "
                "leaves via one path sometimes and another path at other times — "
                "the symptom is 'it works sometimes, and sometimes it does not'.",
                fix="Remove the default on the interface that does not need one, or "
                "set the priority explicitly with a metric.",
                evidence={"gateways": gateways, "family": family},
            )
        )

    for gw in dead_gateways:
        out.append(
            Finding(
                severity=SEV_CRITICAL,
                category=CAT_ROUTE,
                title=f"{tag}default gateway is not responding: {gw}",
                detail="The routing table is correct, but the next hop does not answer a ping.",
                fix="Check that the gateway device is powered on and that the "
                "cable/VLAN is correct.",
                host=gw,
                evidence={"family": family},
            )
        )

    if has_vpn_split and not is_v6:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_ROUTE,
                title="The VPN has taken over all traffic",
                detail="The `0.0.0.0/1` + `128.0.0.0/1` routes are present — they beat "
                "the default and every packet goes through the tunnel.",
                fix="Configure the VPN profile if you need split tunnelling.",
            )
        )
    return out


def evaluate_mtu(path_mtu: int | None, error: str | None = None) -> list[Finding]:
    """Evaluates the path MTU result — pure function."""
    if error:
        return [
            Finding(
                severity=SEV_LOW,
                category=CAT_MTU,
                title="MTU could not be measured",
                detail=error,
                fix="Check that the target answers ICMP, or pick another host.",
            )
        ]
    if path_mtu is None:
        return []
    if path_mtu >= 1500:
        return []
    sev = SEV_MEDIUM if path_mtu >= 1400 else SEV_HIGH
    return [
        Finding(
            severity=sev,
            category=CAT_MTU,
            title=f"Path MTU is reduced: {path_mtu}",
            detail=f"The smallest MTU along the path is {path_mtu} bytes (1500 is "
            "standard). Sites that return large responses can load halfway and then "
            "hang — a PMTUD black hole.",
            fix=f"Lower the interface MTU to {path_mtu}, or enable TCP MSS clamping "
            "(on the router/VPN concentrator).",
            evidence={"path_mtu": path_mtu},
        )
    ]


def evaluate_dhcp(
    servers: list[str],
    lease_server: str | None = None,
    expected_server: str | None = None,
    partial: bool = False,
) -> list[Finding]:
    """Evaluates the DHCP state — pure function.

    `partial=True` means the broadcast probe got no reply. That is NOT the same
    as "there is no server" (port 68 cannot be bound without root), so no warning
    is raised — the verdict is drawn from the active lease alone.
    """
    out: list[Finding] = []
    if len(servers) > 1:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DHCP,
                title=f"{len(servers)} DHCP servers on the network",
                detail=f"Answered: {', '.join(servers)}. A second (rogue) DHCP server "
                "can hand devices the wrong gateway/DNS — the symptom is 'some "
                "machines have internet and others do not'.",
                fix="Find the unauthorised DHCP server and shut it down; enable DHCP "
                "snooping on the switch.",
                evidence={"servers": servers},
            )
        )
    if expected_server and lease_server and lease_server != expected_server:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DHCP,
                title="Address came from an unexpected DHCP server",
                detail=f"The current lease is from `{lease_server}`, the expected one "
                f"is `{expected_server}`.",
                fix="Go looking for a rogue DHCP server.",
                evidence={"actual": lease_server, "expected": expected_server},
            )
        )
    return out


def evaluate_arpwatch(
    mac_changes: list[tuple[str, str, str]],
    duplicates: list[tuple[str, list[str]]],
    first_run: bool = False,
) -> list[Finding]:
    """Evaluates ARP changes — pure function.

    `mac_changes` is `(ip, old_mac, new_mac)`; `duplicates` is `(mac, ips)`.
    On the first run there is no baseline to compare against, so nothing is
    returned (otherwise every new machine produced an "every host is new" storm).
    """
    if first_run:
        return []
    out: list[Finding] = []
    for ip, old, new in mac_changes:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_LAN,
                title=f"{ip}: MAC changed",
                detail=f"{old} -> {new}. This may be ARP spoofing (MITM), a duplicate "
                "IP, or simply a swapped device.",
                fix="Confirm the device really was replaced; otherwise check the switch "
                "port and the ARP table.",
                host=ip,
                evidence={"old_mac": old, "new_mac": new},
            )
        )
    for mac, ips in duplicates:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_LAN,
                title=f"One MAC on {len(ips)} IPs: {mac}",
                detail=f"Addresses: {', '.join(ips[:6])}. This may be a router/NAT, or "
                "a duplicate IP.",
                fix="Confirm the device is a router; otherwise review the IP allocation.",
                evidence={"mac": mac, "ips": ips},
            )
        )
    return out


CAT_WIFI = "Wi-Fi"


def evaluate_wifi(
    available: bool,
    connected: bool,
    rssi: int | None,
    snr: int | None,
    band: str | None,
    channel: int | None,
    width_mhz: int | None,
    phy_gen: str | None,
    card_gen: str | None,
    tx_rate: float | None,
    security: str | None,
    five_ghz_available: bool,
    overlap_count: int = 0,
) -> list[Finding]:
    """Evaluates the Wi-Fi state — pure function.

    Returns **nothing at all** when there is no Wi-Fi hardware (a server, a wired
    workstation) or when it is not connected. Otherwise every Ethernet host got a
    false "Wi-Fi problem" — one of this project's false-positive lessons.
    """
    if not available or not connected:
        return []
    out: list[Finding] = []

    # --- signal strength ---
    if rssi is not None:
        if rssi < -80:
            out.append(
                Finding(
                    severity=SEV_CRITICAL,
                    category=CAT_WIFI,
                    title=f"Wi-Fi signal is very weak ({rssi} dBm)",
                    detail="At this level packets are retransmitted over and over; "
                    "throughput collapses and the connection keeps dropping.",
                    fix="Move closer to the access point, or add an AP/mesh node in between.",
                    evidence={"rssi_dbm": rssi},
                )
            )
        elif rssi < -70:
            out.append(
                Finding(
                    severity=SEV_MEDIUM,
                    category=CAT_WIFI,
                    title=f"Wi-Fi signal is weak ({rssi} dBm)",
                    detail="A borderline signal — throughput drops under load.",
                    fix="Reconsider where the AP sits, or how its antennas are aimed.",
                    evidence={"rssi_dbm": rssi},
                )
            )

    # --- SNR: matters more than the raw signal ---
    if snr is not None and snr < 15:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_WIFI,
                title=f"Wi-Fi noise level is high (SNR {snr} dB)",
                detail="The signal does not stand far enough above the noise. This "
                "collapses throughput even when the signal itself is strong — the "
                "cause is another radio source.",
                fix="Check for a microwave oven, a cordless phone, Bluetooth devices "
                "or neighbouring APs; move to 5 GHz.",
                evidence={"snr_db": snr},
            )
        )

    # --- sitting on 2.4 GHz while 5 GHz is available ---
    if band == "2.4GHz" and five_ghz_available:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_WIFI,
                title="Connected on 2.4 GHz, 5 GHz is available",
                detail="2.4 GHz is slow (~144 Mbps at 20 MHz) and congested. A 5 GHz "
                "AP is visible nearby — it offers a much wider channel.",
                fix="Connect the device to the 5 GHz SSID, or enable band steering on the router.",
                evidence={"band": band},
            )
        )

    # --- channel overlap (2.4 GHz only) ---
    if band == "2.4GHz" and overlap_count >= 3:
        out.append(
            Finding(
                severity=SEV_MEDIUM if overlap_count < 6 else SEV_HIGH,
                category=CAT_WIFI,
                title=f"Channel {channel} is congested ({overlap_count} APs interfering)",
                detail="2.4 GHz has only 3 non-overlapping channels (1/6/11). "
                "Neighbouring APs are sharing this one — throughput drops even when "
                "the SNR is good.",
                fix="Move to 5 GHz; if that is impossible, pick the emptiest of channels 1/6/11.",
                evidence={"channel": channel, "overlap": overlap_count},
            )
        )

    # --- non-standard channel on 2.4 GHz ---
    if band == "2.4GHz" and channel is not None and channel not in (1, 6, 11):
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_WIFI,
                title=f"Non-standard channel on 2.4 GHz ({channel})",
                detail="Any channel other than 1/6/11 partially overlaps the "
                "neighbours' and interferes in both directions.",
                fix="Change the channel on the router to 1, 6 or 11.",
                evidence={"channel": channel},
            )
        )

    # --- PHY below what the card can do ---
    rank = {"legacy": 0, "n": 1, "ac": 2, "ax": 3, "be": 4}
    if phy_gen and card_gen and rank.get(phy_gen, 0) < rank.get(card_gen, 0):
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_WIFI,
                title=f"Wi-Fi is running at {phy_gen}, the card supports {card_gen}",
                detail=f"The adapter is capable of 802.11{card_gen}, yet the link is at "
                f"802.11{phy_gen} — most of the available speed is going unused.",
                fix="Check the router/AP firmware and the wireless mode setting (a "
                "legacy mode may be forced on).",
                evidence={"phy": phy_gen, "card": card_gen},
            )
        )

    # --- security ---
    if security:
        low = security.lower()
        if "wep" in low:
            out.append(
                Finding(
                    severity=SEV_CRITICAL,
                    category=CAT_WIFI,
                    title="Wi-Fi is using WEP encryption",
                    detail="WEP is broken within minutes — in practice there is no "
                    "protection at all.",
                    fix="Move to WPA2 or WPA3 immediately.",
                    evidence={"security": security},
                )
            )
        elif "none" in low or "open" in low:
            out.append(
                Finding(
                    severity=SEV_HIGH,
                    category=CAT_WIFI,
                    title="Wi-Fi is open (no encryption)",
                    detail="Traffic goes out over the air in the clear — anyone can read it.",
                    fix="Set a WPA2/WPA3 password.",
                    evidence={"security": security},
                )
            )

    # --- narrow channel width ---
    if band == "5GHz" and width_mhz is not None and width_mhz <= 20:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_WIFI,
                title=f"Narrow channel on 5 GHz ({width_mhz} MHz)",
                detail="5 GHz allows up to 80 MHz; 20 MHz caps the speed at a quarter of that.",
                fix="Raise the channel width to 80 MHz on the router.",
                evidence={"width_mhz": width_mhz},
            )
        )

    _ = tx_rate  # informational for now; the PHY verdict is the stronger signal
    return out


def evaluate_link_speed(
    name: str,
    speed_mbps: int,
    is_up: bool,
    is_virtual: bool = False,
) -> list[Finding]:
    """Evaluates the interface link speed — pure function.

    Negotiating 100 Mbps on a gigabit port is the classic invisible fault:
    everything works, it is just 10x slower. The cause is usually the cable
    (2 pairs wired instead of 4), the connector, or a duplex mismatch.

    Virtual interfaces (`utun*`, `awdl0`, `llw0`, `bridge*`) are skipped — the
    notion of "speed" does not apply to them and they produced false warnings.
    """
    if not is_up or is_virtual or speed_mbps <= 0:
        return []
    if speed_mbps >= 1000:
        return []
    if speed_mbps <= 10:
        sev, note = SEV_HIGH, "10 Mbps — almost certainly a cable or port fault."
    else:
        sev, note = (
            SEV_MEDIUM,
            (
                "100 Mbps — where a gigabit port was expected, this is the signature "
                "of a cable (2 pairs instead of 4), a connector, or a duplex mismatch."
            ),
        )
    return [
        Finding(
            severity=sev,
            category=CAT_INTERFACE,
            title=f"{name}: link negotiated at {speed_mbps} Mbps",
            detail=note,
            fix="Swap the cable (Cat5e or better), check the connector and the switch "
            "port; make sure the port is set to auto-negotiation.",
            host=name,
            evidence={"speed_mbps": speed_mbps},
        )
    ]


# ===========================================================================
# Adaptive thresholds — chosen by link type
# ===========================================================================
#
# One absolute number cannot be right on every network. 50 ms to the gateway is:
#   wired LAN  -> a DISASTER (normal is < 2 ms)
#   Wi-Fi      -> normal
#   4G/LTE     -> good
#   satellite  -> excellent (normal is ~600 ms)
# So the thresholds are picked from the link type.

LINK_WIRED = "wired"
LINK_WIFI = "wifi"
LINK_CELLULAR = "cellular"
LINK_VPN = "vpn"
LINK_UNKNOWN = "unknown"

# Thresholds per profile. `unknown` is a cautious middle ground (close to
# Wi-Fi), because a strict threshold on an unknown network yields false warnings.
_PROFILES: dict[str, dict[str, float]] = {
    LINK_WIRED: {
        "gateway_rtt_ms": 5.0,
        "internet_rtt_ms": 120.0,
        "jitter_ms": 5.0,
        "loss_medium_pct": 0.5,
        "loss_high_pct": 2.0,
        "dns_slow_ms": 200.0,
    },
    LINK_WIFI: {
        "gateway_rtt_ms": 50.0,
        "internet_rtt_ms": 200.0,
        "jitter_ms": 30.0,
        "loss_medium_pct": 5.0,
        "loss_high_pct": 20.0,
        "dns_slow_ms": 500.0,
    },
    LINK_CELLULAR: {
        "gateway_rtt_ms": 120.0,
        "internet_rtt_ms": 400.0,
        "jitter_ms": 80.0,
        "loss_medium_pct": 8.0,
        "loss_high_pct": 25.0,
        "dns_slow_ms": 900.0,
    },
    LINK_VPN: {
        "gateway_rtt_ms": 80.0,
        "internet_rtt_ms": 350.0,
        "jitter_ms": 50.0,
        "loss_medium_pct": 5.0,
        "loss_high_pct": 20.0,
        "dns_slow_ms": 700.0,
    },
    LINK_UNKNOWN: {
        "gateway_rtt_ms": 40.0,
        "internet_rtt_ms": 250.0,
        "jitter_ms": 30.0,
        "loss_medium_pct": 5.0,
        "loss_high_pct": 20.0,
        "dns_slow_ms": 600.0,
    },
}

# Prefixes used to guess the link type from the interface name (cross-platform).
_WIFI_PREFIXES = ("wlan", "wl", "wlp", "ath", "wifi")
_VPN_PREFIXES = ("utun", "tun", "tap", "ppp", "wg", "ipsec", "gpd", "nordlynx")
_CELLULAR_PREFIXES = ("pdp_ip", "rmnet", "wwan", "ccmni", "cdc-wdm")


def classify_link(
    interface_name: str | None,
    wifi_connected: bool = False,
    wifi_interface: str | None = None,
) -> str:
    """Determines the link type — pure function (tested offline).

    The order matters: the Wi-Fi state comes first (on macOS the Wi-Fi interface
    is also called `en0` and cannot be told apart by name), then the name
    prefixes.
    """
    if not interface_name:
        return LINK_UNKNOWN
    name = interface_name.lower()

    # On macOS Wi-Fi is `en0` too — we tell from the STATE, not from the name.
    if wifi_connected and wifi_interface and name == wifi_interface.lower():
        return LINK_WIFI
    if name.startswith(_VPN_PREFIXES):
        return LINK_VPN
    if name.startswith(_CELLULAR_PREFIXES):
        return LINK_CELLULAR
    if name.startswith(_WIFI_PREFIXES):
        return LINK_WIFI
    if name.startswith(("en", "eth", "eno", "ens", "enp", "em")):
        return LINK_WIRED
    return LINK_UNKNOWN


def thresholds_for_link(link: str, base: Thresholds | None = None) -> Thresholds:
    """Returns the thresholds that match the link type — pure function.

    When `base` is given (the user's config), its values WIN: automatic adaptation
    must never override a setting somebody typed by hand.
    """
    profile = _PROFILES.get(link, _PROFILES[LINK_UNKNOWN])
    default = Thresholds()
    result = Thresholds(**profile)  # type: ignore[arg-type]
    if base is None:
        return result
    # Keep the fields the user set to something other than the default.
    for f in (
        "gateway_rtt_ms",
        "internet_rtt_ms",
        "jitter_ms",
        "loss_medium_pct",
        "loss_high_pct",
        "dns_slow_ms",
        "iface_error_rate",
        "tls_warn_days",
    ):
        user_val = getattr(base, f)
        if user_val != getattr(default, f):
            setattr(result, f, user_val)
        elif not hasattr(result, f) or f in ("iface_error_rate", "tls_warn_days"):
            setattr(result, f, user_val)
    return result
