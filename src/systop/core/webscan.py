"""Discovering web services and identifying admin panels — "exploring" the network.

Why this is needed: a LAN holds dozens of devices (router, switch, NVR, camera,
printer, Docker panel...) and many of them leave an **unprotected HTTP admin
panel** exposed. `scan` only says "the port is open"; this module sends a
request to the open web port and tells you **what it is** and, **if it is an
admin panel, how risky it is**.

Architecture: the network call (`probe_service`) is deliberately separated from
the detection logic (`classify`) — `classify` is a pure function and is tested
without any network (the project's "tests are offline" rule).

Important (lesson of 2026-07-28): checking many ports/hosts in quick succession
trips the IPS/anti-scan protection on the network and the scanning IP gets
**temporarily blocked** (symptom: ICMP works, new TCP connections say
"Connection refused"). That is why `concurrency` here is low (default 16) and a
`delay` (a pause between hosts) exists. On a network with an inline firewall/IPS
use `--polite`.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

import httpx

# Ports where a web interface is likely -> scheme. Only these are checked
# (hitting all 65535 ports with an HTTP request is pointless and provokes the IPS).
WEB_PORTS: dict[int, str] = {
    80: "http",
    81: "http",
    443: "https",
    591: "http",
    2375: "http",  # Docker API (very dangerous if unprotected)
    2376: "https",
    3000: "http",  # Grafana / dev server
    4081: "https",  # Kerio Control admin
    5000: "http",
    5601: "http",  # Kibana
    7080: "http",
    8000: "http",
    8006: "https",  # Proxmox VE
    8008: "http",
    8080: "http",
    8081: "http",
    8090: "http",
    8443: "https",
    8834: "https",  # Nessus
    9000: "http",  # Portainer / SonarQube
    9090: "http",  # Prometheus
    9443: "https",  # Portainer HTTPS
    10000: "http",  # Webmin
}

# The short list of the most common ones (for quick mode).
QUICK_WEB_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 8006, 4081, 9000)


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """The trace of a single product: body and header patterns kept SEPARATE.

    `klass` is deliberately split in two:
      "admin" — the product itself is a management panel (Kerio, Hikvision,
                Proxmox...). Such a trace adds +2 to the admin score.
      "infra" — merely a web server/proxy (nginx, Apache, Caddy, Traefik).
                For IDENTIFICATION only, adds **0** to the admin score.

    This split is necessary: otherwise even an ordinary nginx welcome page was
    flagged as an "admin panel" (that exact false positive appeared in the
    first version).
    """

    product: str
    device_kind: str
    klass: str  # "admin" | "infra"
    body_patterns: tuple[str, ...] = ()
    header_patterns: tuple[str, ...] = ()


# Product fingerprints.
#
# The patterns are searched in two SEPARATE texts: `body_patterns` only in the
# HTML body, `header_patterns` only in the "key:value" shaped header text.
# Previously the two were glued into a single string and a header token
# (`x-jenkins`) would "match" inside the page text as well (and vice versa).
#
# The patterns are deliberately LONG/specific: a substring search falls inside
# ordinary English words. False positives seen in practice:
#   "asterisk" ⊂ "marked with an asterisk (*)"  -> Asterisk/FreePBX (telephony!)
#   "unifi"    ⊂ "Unified Communications"       -> UniFi
#   "minio"    ⊂ "dominion"                     -> MinIO
#   "prometheus" — Greek mythology/blog prose   -> Prometheus
#   "jenkins"  — a surname ("Sarah Jenkins")    -> Jenkins
#   '"apiversion"' — any k8s manifest           -> exposed Docker API
#   "hass"     ⊂ "chassis"                      -> Home Assistant
# The `\b` word boundary is NOT THE FIX (it was tried): both `\basterisk\b` and
# `\bprometheus\b` still match the cases above — they really are standalone
# words there. The fix is to put the context into the pattern ITSELF
# ("asterisk management portal", "unifi network", "minio console", "x-jenkins").
_FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint(
        "Kerio Control", "firewall", "admin", ("kerio control", "kerio-control", "keriocontrol")
    ),
    Fingerprint(
        "Hikvision",
        "camera/NVR",
        "admin",
        ("hikvision", "/doc/page/login.asp", "webcomponents.exe"),
    ),
    Fingerprint("Dahua", "camera/NVR", "admin", ("dahua", "dh_web", "webplugin")),
    Fingerprint("UniFi", "network", "admin", ("unifi network", "unifi os", "ubiquiti"), ("ubnt",)),
    Fingerprint("MikroTik", "router", "admin", ("mikrotik", "routeros", "webfig")),
    Fingerprint("TP-Link", "router", "admin", ("tp-link", "tplink")),
    Fingerprint(
        "Proxmox VE",
        "hypervisor",
        "admin",
        ("proxmox virtual environment", "pve-manager", "pvemanagerlib.js"),
    ),
    Fingerprint("Grafana", "monitoring", "admin", ("grafana",)),
    Fingerprint("Portainer", "docker", "admin", ("portainer",)),
    Fingerprint("Prometheus", "monitoring", "admin", ("prometheus time series", "/graph?g0.expr")),
    Fingerprint("Zabbix", "monitoring", "admin", ("zabbix",)),
    Fingerprint("phpMyAdmin", "database", "admin", ("phpmyadmin", "pma_username")),
    Fingerprint("pgAdmin", "database", "admin", ("pgadmin",)),
    Fingerprint("GitLab", "devops", "admin", ("gitlab",)),
    Fingerprint(
        "Jenkins",
        "devops",
        "admin",
        ("[jenkins]", "jenkins ver.", "/static/jenkins"),
        ("x-jenkins",),
    ),
    Fingerprint("Synology DSM", "NAS", "admin", ("synology",)),
    Fingerprint("QNAP", "NAS", "admin", ("qnap",)),
    Fingerprint("pfSense", "firewall", "admin", ("pfsense",)),
    Fingerprint("OPNsense", "firewall", "admin", ("opnsense",)),
    Fingerprint("Webmin", "server panel", "admin", ("webmin",)),
    Fingerprint("cPanel", "server panel", "admin", ("cpanel",)),
    Fingerprint(
        "Home Assistant",
        "smart home",
        "admin",
        ("home assistant", "home-assistant", "homeassistant"),
    ),
    Fingerprint("Docker API (exposed!)", "docker", "admin", (), ("server:docker/",)),
    Fingerprint("HP printer", "printer", "admin", ("hp laserjet", "hp officejet", "hp color")),
    Fingerprint("Canon printer", "printer", "admin", ("remote ui", "canon inkjet", "canon laser")),
    Fingerprint(
        "Epson printer", "printer", "admin", ("epson stylus", "epson workforce", "epson et-")
    ),
    Fingerprint(
        "Asterisk/FreePBX",
        "telephony",
        "admin",
        ("freepbx", "asterisk management portal", "digium"),
    ),
    Fingerprint("MinIO", "storage", "admin", ("minio console",), ("x-minio", "server:minio")),
    Fingerprint("Keycloak", "identity", "admin", ("keycloak",)),
    # --- identification only, contributes no admin score ---
    Fingerprint("Nginx", "web server", "infra", ("welcome to nginx",), ("server:nginx",)),
    Fingerprint(
        "Apache", "web server", "infra", ("apache2 ubuntu default", "it works!"), ("server:apache",)
    ),
    Fingerprint("Traefik", "proxy", "infra", ("traefik",), ("server:traefik",)),
    Fingerprint("Caddy", "proxy", "infra", (), ("server:caddy",)),
)

# Title/text keywords that hint at an admin panel. The non-English entries are
# deliberate: device firmware is frequently shipped with a localised login page,
# and dropping them would silently miss those panels.
_ADMIN_WORDS: tuple[str, ...] = (
    "login",
    "log in",
    "sign in",
    "signin",
    "admin",
    "administrator",
    "kirish",
    "tizimga kirish",
    "вход",
    "войти",
    "авторизация",
    "dashboard",
    "control panel",
    "management",
    "boshqaruv",
    "router",
    "gateway",
    "firewall",
    "nvr",
    "dvr",
    "camera",
    "web client",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_RE = re.compile(r"""<input[^>]*type\s*=\s*["']?password""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form[^>]", re.IGNORECASE)


@dataclass(slots=True)
class AdminVerdict:
    """The result of `classify` — from the pure detection logic (tested offline)."""

    is_admin: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    product: str | None = None
    device_kind: str | None = None
    auth_type: str | None = None  # basic | digest | form | None


@dataclass(slots=True)
class WebService:
    """The web-service result for a single host:port."""

    ip: str
    port: int
    scheme: str = "http"
    status: int | None = None
    title: str | None = None
    server: str | None = None
    product: str | None = None
    device_kind: str | None = None
    is_admin: bool = False
    admin_score: int = 0
    admin_reasons: list[str] = field(default_factory=list)
    auth_type: str | None = None
    insecure_admin: bool = False  # an admin panel over unencrypted HTTP
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def url(self) -> str:
        host = f"[{self.ip}]" if ":" in self.ip else self.ip
        return f"{self.scheme}://{host}:{self.port}/"

    @property
    def risk(self) -> str:
        """Risk level: high | medium | low | none."""
        if not self.is_admin:
            return "none"
        if self.insecure_admin and self.auth_type in ("basic", "digest"):
            return "high"  # the password travels in clear text
        if self.insecure_admin:
            return "medium"
        return "low"


def _is_strong(pattern: str) -> bool:
    """Does the pattern prove a management panel BY ITSELF (with no other evidence)?

    A strong pattern is a string that is NOT purely alphanumeric: a path
    (`/doc/page/login.asp`), a file (`pvemanagerlib.js`), a header token
    (`x-jenkins`) or a multi-word phrase ("kerio control"). Such a string does
    not turn up by accident inside ordinary prose.

    A bare word ("grafana", "gitlab", "minio") on the other hand can — so it
    only yields IDENTIFICATION; the "admin panel" verdict additionally requires
    corroborating evidence (auth / a login title / a 401).
    """
    return not pattern.isalnum()


def _match_fingerprint(fp: Fingerprint, body: str, headers_blob: str) -> tuple[str, bool] | None:
    """Did the fingerprint match — `(matched pattern, is it strong)` or `None`.

    A body pattern is searched ONLY in the body, a header pattern ONLY in the
    header text. A header match is always considered strong: a header is a
    "key:value" — a fact stated by the server, not prose on a page.
    """
    best: tuple[str, bool] | None = None

    def offer(pattern: str, strong: bool) -> None:
        nonlocal best
        if best is None or (strong, len(pattern)) > (best[1], len(best[0])):
            best = (pattern, strong)

    for pattern in fp.body_patterns:
        if pattern in body:
            offer(pattern, _is_strong(pattern))
    for pattern in fp.header_patterns:
        if pattern in headers_blob:
            offer(pattern, True)
    return best


def _fingerprint_rank(item: tuple[int, Fingerprint, str, bool]) -> tuple[int, int, int, int]:
    """The selection order when several fingerprints match (smaller is better).

    Previously there was a `break` on the first match, and a FALSE match sitting
    higher in the list would SHADOW the correct product (for example the word
    "asterisk" on a page would override Proxmox). Now all matches are collected
    and the most trustworthy one is chosen: the `admin` class first, then a
    strong pattern, then a longer (more specific) pattern, and finally the
    declaration order.
    """
    idx, fp, pattern, strong = item
    return (0 if fp.klass == "admin" else 1, 0 if strong else 1, -len(pattern), idx)


def extract_title(body: str) -> str | None:
    """Takes the <title> out of the HTML (whitespace collapsed, up to 120 chars)."""
    m = _TITLE_RE.search(body)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:120] or None


def classify(
    body: str,
    headers: dict[str, str] | None = None,
    status: int | None = None,
    scheme: str = "http",
) -> AdminVerdict:
    """Decides from the response content whether this is an admin panel — a PURE function.

    The scoring system (a total of >= 2 counts as an admin panel):
      +3  a WWW-Authenticate header (Basic/Digest) — this is clearly a protected panel
      +2  a password field is present (`<input type=password>`)
      +2  a product fingerprint of the "admin" class (Kerio/Hikvision/Proxmox...)
      +0  a fingerprint of the "infra" class (nginx/Apache/Caddy) — identification only
      +1  an admin/login keyword in the title
      +1  a 401/403 status (it demands authentication)

    An extra condition (CORROBORATION): if the 2 points come only from a WEAK
    product fingerprint (a bare word), `is_admin` is **not** granted. That exact
    situation turned a single word collision ("dominion" -> MinIO) into a
    security finding. A strong fingerprint (path/file/header token/multi-word
    phrase) is enough on its own.

    Does not touch the network, and is therefore tested offline.
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    low = body.lower()
    verdict = AdminVerdict()

    # --- product fingerprint (body and header searched SEPARATELY) ---
    # The headers are joined in "key:value" form so that patterns such as
    # "server:nginx" match exactly (with no whitespace). They are NOT MIXED with
    # the body: a header token must not get "found" inside the page text.
    headers_blob = "\n".join(f"{k}:{v}".lower() for k, v in headers.items())
    matches = [
        (idx, fp, hit[0], hit[1])
        for idx, fp in enumerate(_FINGERPRINTS)
        if (hit := _match_fingerprint(fp, low, headers_blob)) is not None
    ]
    strong_product = False
    if matches:
        _, fp, pattern, strong = min(matches, key=_fingerprint_rank)
        verdict.product = fp.product
        verdict.device_kind = fp.device_kind
        if fp.klass == "admin":
            verdict.score += 2
            strong_product = strong
            verdict.reasons.append(f"management product: {fp.product}")
        else:
            verdict.reasons.append(f"web server: {fp.product}")

    # --- authentication type ---
    corroborated = False  # is there evidence OTHER than the product fingerprint
    www_auth = headers.get("www-authenticate", "")
    if www_auth:
        scheme_name = www_auth.split()[0].lower() if www_auth.split() else "unknown"
        verdict.auth_type = (
            "basic"
            if "basic" in scheme_name
            else ("digest" if "digest" in scheme_name else scheme_name)
        )
        verdict.score += 3
        verdict.reasons.append(f"HTTP authentication: {verdict.auth_type}")
        corroborated = True
    elif _PASSWORD_RE.search(body):
        verdict.auth_type = "form"
        verdict.score += 2
        verdict.reasons.append("password field present (login form)")
        corroborated = True

    # --- title keywords ---
    title = extract_title(body)
    if title:
        tl = title.lower()
        hit_word = next((w for w in _ADMIN_WORDS if w in tl), None)
        if hit_word:
            verdict.score += 1
            verdict.reasons.append(f"'{hit_word}' in the title")
            corroborated = True

    # --- status ---
    if status in (401, 403):
        verdict.score += 1
        verdict.reasons.append(f"status {status} — it demands authentication")
        corroborated = True

    verdict.is_admin = verdict.score >= 2 and (corroborated or strong_product)
    return verdict


async def probe_service(
    ip: str,
    port: int,
    scheme: str | None = None,
    timeout: float = 4.0,
    max_bytes: int = 65536,
) -> WebService:
    """Sends an HTTP request to a single host:port and identifies the service.

    Raises no exception — errors come back in the `error` field. Only
    `max_bytes` are read from the start of the response (so that large pages are
    not fetched in full). The TLS certificate is **not verified**
    (`verify=False`): LAN devices almost always carry a self-signed certificate
    and the goal is inventory, not trust.
    """
    scheme = scheme or WEB_PORTS.get(port, "http")
    svc = WebService(ip=ip, port=port, scheme=scheme)
    host = f"[{ip}]" if ":" in ip else ip
    url = f"{scheme}://{host}:{port}/"

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "systop/webscan"})
            body = resp.text[:max_bytes] if resp.content else ""
    except httpx.HTTPError as exc:
        svc.elapsed_ms = (time.perf_counter() - start) * 1000.0
        svc.error = f"request error: {type(exc).__name__}"
        return svc
    except (OSError, ValueError) as exc:
        svc.elapsed_ms = (time.perf_counter() - start) * 1000.0
        svc.error = f"connection error: {type(exc).__name__}"
        return svc

    svc.elapsed_ms = (time.perf_counter() - start) * 1000.0
    svc.status = resp.status_code
    svc.server = resp.headers.get("server")
    svc.title = extract_title(body)

    verdict = classify(body, dict(resp.headers), resp.status_code, scheme)
    svc.product = verdict.product
    svc.device_kind = verdict.device_kind
    svc.is_admin = verdict.is_admin
    svc.admin_score = verdict.score
    svc.admin_reasons = verdict.reasons
    svc.auth_type = verdict.auth_type
    svc.insecure_admin = verdict.is_admin and scheme == "http"
    return svc


async def discover_web(
    hosts: list[str],
    ports: list[int] | None = None,
    timeout: float = 4.0,
    concurrency: int = 16,
    delay: float = 0.0,
    admin_only: bool = False,
) -> list[WebService]:
    """Finds the web services on the given hosts and flags the admin panels.

    `concurrency` is deliberately low (16) — see the anti-scan note above.
    `delay` is the pause after every request (seconds); on a network with an IPS
    give it 0.2-0.5.
    If `admin_only=True`, only the ones found to be admin panels come back.

    The result order is stable: host order, then port.
    """
    port_list = sorted(set(ports)) if ports else sorted(WEB_PORTS)
    if not hosts or not port_list:
        return []

    sem = asyncio.Semaphore(max(concurrency, 1))

    async def one(ip: str, port: int) -> WebService:
        async with sem:
            svc = await probe_service(ip, port, timeout=timeout)
            if delay > 0:
                await asyncio.sleep(delay)
            return svc

    tasks = [one(ip, p) for ip in hosts for p in port_list]
    results = await asyncio.gather(*tasks)

    # Drop the ones that did not answer — they mean "no web service".
    live = [s for s in results if s.error is None]
    if admin_only:
        live = [s for s in live if s.is_admin]

    order = {ip: i for i, ip in enumerate(hosts)}
    live.sort(key=lambda s: (order.get(s.ip, 1 << 30), s.port))
    return live


def summarize(services: list[WebService]) -> dict[str, int]:
    """Short statistics over the results (for the CLI footnote)."""
    return {
        "total": len(services),
        "admin": sum(1 for s in services if s.is_admin),
        "insecure_admin": sum(1 for s in services if s.insecure_admin),
        "high_risk": sum(1 for s in services if s.risk == "high"),
        "http_80": sum(1 for s in services if s.port == 80),
    }
