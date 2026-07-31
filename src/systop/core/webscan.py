"""Web xizmatlarni topish va admin panellarni aniqlash — tarmoqni "explore" qilish.

Nima uchun kerak: LAN'da o'nlab qurilma bo'ladi (router, switch, NVR, kamera,
printer, Docker paneli...) va ularning ko'pi **himoyalanmagan HTTP admin
panel**ini ochiq qoldiradi. `scan` faqat "port ochiq" deydi; bu modul ochiq
web portga so'rov yuborib **nima ekanini** va **admin panel bo'lsa xavf
darajasini** aytadi.

Arxitektura: tarmoq chaqiruvi (`probe_service`) bilan aniqlash mantiqi
(`classify`) ataylab ajratilgan — `classify` sof funksiya, tarmoqsiz test
qilinadi (loyihaning "testlar offline" qoidasi).

Muhim (2026-07-28 saboqi): tez ketma-ket ko'p port/host tekshirish tarmoqdagi
IPS/anti-scan himoyasini ishga tushiradi va skanerlovchi IP **vaqtincha
bloklanadi** (alomat: ICMP ishlaydi, yangi TCP "Connection refused"). Shuning
uchun bu yerda `concurrency` past (default 16) va `delay` (host orasidagi
pauza) mavjud. Kerio/Fortigate turgan tarmoqda `--polite` ishlating.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

import httpx

# Web interfeys uchraydigan portlar -> sxema. Faqat shular tekshiriladi
# (65535 portni HTTP so'rov bilan urish ma'nosiz va IPS'ni qo'zg'atadi).
WEB_PORTS: dict[int, str] = {
    80: "http",
    81: "http",
    443: "https",
    591: "http",
    2375: "http",  # Docker API (himoyasiz bo'lsa juda xavfli)
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

# Eng ko'p uchraydigan qisqa ro'yxat (tez rejim uchun).
QUICK_WEB_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 8006, 4081, 9000)


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """Bitta mahsulot izi: body va header naqshlari ALOHIDA.

    `klass` ataylab ikkiga bo'lingan:
      "admin" — mahsulotning o'zi boshqaruv paneli (Kerio, Hikvision, Proxmox...).
                Bunday iz admin-ballga +2 qo'shadi.
      "infra" — shunchaki web server/proxy (nginx, Apache, Caddy, Traefik).
                Faqat IDENTIFIKATSIYA uchun, admin-ballga **0** qo'shadi.

    Bu bo'linish kerak: aks holda oddiy nginx welcome sahifasi ham "admin panel"
    deb belgilanardi (dastlabki versiyada aynan shu soxta pozitiv chiqdi).
    """

    product: str
    device_kind: str
    klass: str  # "admin" | "infra"
    body_patterns: tuple[str, ...] = ()
    header_patterns: tuple[str, ...] = ()


# Mahsulot barmoq izlari.
#
# Naqshlar ikki AJRATILGAN matnda izlanadi: `body_patterns` faqat HTML tanasida,
# `header_patterns` faqat "kalit:qiymat" ko'rinishidagi header matnida. Ilgari
# ikkalasi bitta satrga yopishtirilardi va header tokeni (`x-jenkins`) sahifa
# matnida ham "mos kelardi" (va aksincha).
#
# Naqshlar ataylab UZUN/aniq: substring qidiruvi oddiy inglizcha so'z ichiga
# tushib ketadi. Amalda ko'rilgan soxta pozitivlar:
#   "asterisk" ⊂ "marked with an asterisk (*)"  -> Asterisk/FreePBX (telefoniya!)
#   "unifi"    ⊂ "Unified Communications"       -> UniFi
#   "minio"    ⊂ "dominion"                     -> MinIO
#   "prometheus" — Yunon mifologiyasi/blog matni -> Prometheus
#   "jenkins"  — familiya ("Sarah Jenkins")     -> Jenkins
#   '"apiversion"' — har qanday k8s manifesti   -> ochiq Docker API
#   "hass"     ⊂ "chassis"                      -> Home Assistant
# `\b` so'z chegarasi YECHIM EMAS (sinab ko'rilgan): `\basterisk\b` ham,
# `\bprometheus\b` ham yuqoridagi holatlarga baribir mos keladi — ular
# haqiqatan ham alohida so'z. Yechim — kontekstni naqshning O'ZIGA kiritish
# ("asterisk management portal", "unifi network", "minio console", "x-jenkins").
_FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint(
        "Kerio Control", "firewall", "admin", ("kerio control", "kerio-control", "keriocontrol")
    ),
    Fingerprint(
        "Hikvision",
        "kamera/NVR",
        "admin",
        ("hikvision", "/doc/page/login.asp", "webcomponents.exe"),
    ),
    Fingerprint("Dahua", "kamera/NVR", "admin", ("dahua", "dh_web", "webplugin")),
    Fingerprint("UniFi", "tarmoq", "admin", ("unifi network", "unifi os", "ubiquiti"), ("ubnt",)),
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
    Fingerprint("Docker API (ochiq!)", "docker", "admin", (), ("server:docker/",)),
    Fingerprint("HP printer", "printer", "admin", ("hp laserjet", "hp officejet", "hp color")),
    Fingerprint("Canon printer", "printer", "admin", ("remote ui", "canon inkjet", "canon laser")),
    Fingerprint(
        "Epson printer", "printer", "admin", ("epson stylus", "epson workforce", "epson et-")
    ),
    Fingerprint(
        "Asterisk/FreePBX",
        "telefoniya",
        "admin",
        ("freepbx", "asterisk management portal", "digium"),
    ),
    Fingerprint("MinIO", "storage", "admin", ("minio console",), ("x-minio", "server:minio")),
    Fingerprint("Keycloak", "identity", "admin", ("keycloak",)),
    # --- faqat identifikatsiya, admin-ball bermaydi ---
    Fingerprint("Nginx", "web server", "infra", ("welcome to nginx",), ("server:nginx",)),
    Fingerprint(
        "Apache", "web server", "infra", ("apache2 ubuntu default", "it works!"), ("server:apache",)
    ),
    Fingerprint("Traefik", "proxy", "infra", ("traefik",), ("server:traefik",)),
    Fingerprint("Caddy", "proxy", "infra", (), ("server:caddy",)),
)

# Admin panelga ishora qiluvchi sarlavha/matn kalitlari.
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
    """`classify` natijasi — sof aniqlash mantiqidan (tarmoqsiz sinaladi)."""

    is_admin: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    product: str | None = None
    device_kind: str | None = None
    auth_type: str | None = None  # basic | digest | form | None


@dataclass(slots=True)
class WebService:
    """Bitta host:port bo'yicha web xizmat natijasi."""

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
    insecure_admin: bool = False  # admin panel shifrlanmagan HTTP ustida
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def url(self) -> str:
        host = f"[{self.ip}]" if ":" in self.ip else self.ip
        return f"{self.scheme}://{host}:{self.port}/"

    @property
    def risk(self) -> str:
        """Xavf darajasi: high | medium | low | none."""
        if not self.is_admin:
            return "none"
        if self.insecure_admin and self.auth_type in ("basic", "digest"):
            return "high"  # parol ochiq matnda uzatiladi
        if self.insecure_admin:
            return "medium"
        return "low"


def _is_strong(pattern: str) -> bool:
    """Naqsh O'ZICHA boshqaruv panelini isbotlaydimi (qo'shimcha dalilsiz).

    Kuchli naqsh — sof harf/raqamdan iborat BO'LMAGAN satr: yo'l
    (`/doc/page/login.asp`), fayl (`pvemanagerlib.js`), header tokeni
    (`x-jenkins`) yoki ko'p so'zli ibora ("kerio control"). Bunday satr oddiy
    nasr ichida tasodifan uchramaydi.

    Yalang'och so'z ("grafana", "gitlab", "minio") esa uchrashi mumkin —
    shuning uchun u faqat IDENTIFIKATSIYA beradi; "admin panel" xulosasi uchun
    qo'shimcha dalil (auth / login sarlavhasi / 401) talab qilinadi.
    """
    return not pattern.isalnum()


def _match_fingerprint(fp: Fingerprint, body: str, headers_blob: str) -> tuple[str, bool] | None:
    """Iz mos keldimi — `(mos kelgan naqsh, kuchlimi)` yoki `None`.

    Body naqshi FAQAT tanada, header naqshi FAQAT header matnida izlanadi.
    Header mosligi doim kuchli deb hisoblanadi: header "kalit:qiymat" —
    server aytgan fakt, sahifadagi nasr emas.
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
    """Bir nechta iz mos kelganda tanlov tartibi (kichigi — yaxshisi).

    Ilgari birinchi moslikda `break` bor edi va ro'yxatda yuqoriroq turgan
    SOXTA moslik to'g'ri mahsulotni SOYALAB qo'yardi (masalan sahifadagi
    "asterisk" so'zi Proxmox'ni bosib ketardi). Endi barcha mosliklar yig'ilib,
    eng ishonchlisi tanlanadi: avval `admin` sinfi, keyin kuchli naqsh, keyin
    uzunroq (aniqroq) naqsh, oxirida e'lon tartibi.
    """
    idx, fp, pattern, strong = item
    return (0 if fp.klass == "admin" else 1, 0 if strong else 1, -len(pattern), idx)


def extract_title(body: str) -> str | None:
    """HTML'dan <title> ni oladi (bo'sh joylar siqiladi, 120 belgigacha)."""
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
    """Javob mazmunidan admin panel ekanini aniqlaydi — SOF funksiya.

    Ball tizimi (jami >= 2 bo'lsa admin panel deb hisoblanadi):
      +3  WWW-Authenticate header (Basic/Digest) — bu aniq himoyalangan panel
      +2  parol maydoni bor (`<input type=password>`)
      +2  "admin" sinfidagi mahsulot izi (Kerio/Hikvision/Proxmox...)
      +0  "infra" sinfidagi iz (nginx/Apache/Caddy) — faqat identifikatsiya
      +1  sarlavhada admin/login kaliti
      +1  401/403 status (autentifikatsiya talab qiladi)

    Qo'shimcha shart (TASDIQ): 2 ball faqat ZAIF mahsulot izidan (yalang'och
    so'z) kelgan bo'lsa, `is_admin` **berilmaydi**. Aynan shu holat bitta so'z
    to'qnashuvini ("dominion" -> MinIO) xavfsizlik topilmasiga aylantirardi.
    Kuchli iz (yo'l/fayl/header tokeni/ko'p so'zli ibora) o'zicha yetarli.

    Tarmoqqa chiqmaydi, shuning uchun offline test qilinadi.
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    low = body.lower()
    verdict = AdminVerdict()

    # --- mahsulot barmoq izi (body va header ALOHIDA izlanadi) ---
    # Header'lar "kalit:qiymat" ko'rinishida birlashtiriladi, shunda
    # "server:nginx" kabi naqshlar aniq mos keladi (bo'sh joysiz). Body bilan
    # ARALASHTIRILMAYDI: header tokeni sahifa matnida "topilib" qolmasin.
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
            verdict.reasons.append(f"boshqaruv mahsuloti: {fp.product}")
        else:
            verdict.reasons.append(f"web server: {fp.product}")

    # --- autentifikatsiya turi ---
    corroborated = False  # mahsulot izidan BOSHQA dalil bormi
    www_auth = headers.get("www-authenticate", "")
    if www_auth:
        scheme_name = www_auth.split()[0].lower() if www_auth.split() else "unknown"
        verdict.auth_type = (
            "basic"
            if "basic" in scheme_name
            else ("digest" if "digest" in scheme_name else scheme_name)
        )
        verdict.score += 3
        verdict.reasons.append(f"HTTP autentifikatsiya: {verdict.auth_type}")
        corroborated = True
    elif _PASSWORD_RE.search(body):
        verdict.auth_type = "form"
        verdict.score += 2
        verdict.reasons.append("parol maydoni bor (login formasi)")
        corroborated = True

    # --- sarlavha kalitlari ---
    title = extract_title(body)
    if title:
        tl = title.lower()
        hit_word = next((w for w in _ADMIN_WORDS if w in tl), None)
        if hit_word:
            verdict.score += 1
            verdict.reasons.append(f"sarlavhada '{hit_word}'")
            corroborated = True

    # --- status ---
    if status in (401, 403):
        verdict.score += 1
        verdict.reasons.append(f"status {status} — autentifikatsiya talab qiladi")
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
    """Bitta host:port ga HTTP so'rov yuborib xizmatni aniqlaydi.

    Istisno ko'tarmaydi — xato `error` maydonida qaytadi. Faqat javobning
    boshidan `max_bytes` o'qiladi (katta sahifalarni to'liq yuklamaslik uchun).
    TLS sertifikati **tekshirilmaydi** (`verify=False`): LAN qurilmalarida
    deyarli har doim self-signed sertifikat bo'ladi va maqsad inventarizatsiya,
    ishonch emas.
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
        svc.error = f"so'rov xatosi: {type(exc).__name__}"
        return svc
    except (OSError, ValueError) as exc:
        svc.elapsed_ms = (time.perf_counter() - start) * 1000.0
        svc.error = f"ulanish xatosi: {type(exc).__name__}"
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
    """Berilgan hostlarda web xizmatlarni topadi va admin panellarni belgilaydi.

    `concurrency` ataylab past (16) — yuqoridagi anti-scan izohiga qarang.
    `delay` har so'rovdan keyin pauza (sekund); IPS'li tarmoqda 0.2-0.5 bering.
    `admin_only=True` bo'lsa faqat admin panel deb topilganlar qaytadi.

    Natija tartibi barqaror: host tartibi, keyin port.
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

    # Javob bermaganlarni tashlaymiz — ular "web xizmat yo'q" degani.
    live = [s for s in results if s.error is None]
    if admin_only:
        live = [s for s in live if s.is_admin]

    order = {ip: i for i, ip in enumerate(hosts)}
    live.sort(key=lambda s: (order.get(s.ip, 1 << 30), s.port))
    return live


def summarize(services: list[WebService]) -> dict[str, int]:
    """Natijalar bo'yicha qisqa statistika (CLI izohi uchun)."""
    return {
        "total": len(services),
        "admin": sum(1 for s in services if s.is_admin),
        "insecure_admin": sum(1 for s in services if s.insecure_admin),
        "high_risk": sum(1 for s in services if s.risk == "high"),
        "http_80": sum(1 for s in services if s.port == 80),
    }
