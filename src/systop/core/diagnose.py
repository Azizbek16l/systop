"""Tarmoq muammolarini avtomatik topish — "doctor" qatlami.

Boshqa `core/*` modullari **o'lchov** beradi (RTT, loss, ochiq portlar, DNS
vaqti). Bu modul o'lchovlarni **xulosa**ga aylantiradi: nima buzuq, qanchalik
jiddiy va nima qilish kerak. Ya'ni "ping 12% loss" o'rniga "gateway'ga paket
yo'qotish 12% — kabel yoki Wi-Fi muammosi, kommutator portini tekshiring".

Arxitektura (loyiha qoidasi: testlar offline):
  * `evaluate_*` — SOF funksiyalar. Tayyor o'lchovni oladi, `Finding` qaytaradi.
    Tarmoqqa chiqmaydi => to'liq offline sinaladi.
  * `run_diagnostics` — orkestrator. Tarmoq chaqiruvlarini bajarib, natijalarni
    `evaluate_*` ga uzatadi.

Chegaralar (thresholds) bir joyda — `Thresholds` dataclass'ida, shunda
tarmoqqa qarab moslash mumkin (Wi-Fi va optika uchun bir xil emas).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# --- Jiddiylik darajalari (tartib muhim: saralashda ishlatiladi) -------------
SEV_CRITICAL = "critical"  # xizmat ishlamaydi
SEV_HIGH = "high"  # jiddiy xavf yoki sezilarli buzilish
SEV_MEDIUM = "medium"  # muammo bor, lekin ish davom etadi
SEV_LOW = "low"  # kichik nuqson / kuzatish kerak
SEV_INFO = "info"  # ma'lumot, muammo emas

_SEV_ORDER: dict[str, int] = {
    SEV_CRITICAL: 0,
    SEV_HIGH: 1,
    SEV_MEDIUM: 2,
    SEV_LOW: 3,
    SEV_INFO: 4,
}

# --- Kategoriyalar -----------------------------------------------------------
CAT_CONNECTIVITY = "ulanish"
CAT_LATENCY = "kechikish"
CAT_DNS = "DNS"
CAT_IPV6 = "IPv6"
CAT_EXPOSURE = "ochiqlik"
CAT_INTERFACE = "interfeys"
CAT_LAN = "LAN"
CAT_TLS = "TLS"


@dataclass(slots=True)
class Thresholds:
    """Baholash chegaralari — tarmoq turiga qarab moslash mumkin."""

    loss_high_pct: float = 20.0  # bundan yuqori yo'qotish = high
    loss_medium_pct: float = 5.0
    gateway_rtt_ms: float = 50.0  # LAN gateway shundan sekin bo'lmasligi kerak
    internet_rtt_ms: float = 200.0
    jitter_ms: float = 30.0  # VoIP uchun muhim
    dns_slow_ms: float = 500.0
    iface_error_rate: float = 0.001  # xato/paket nisbati (0.1%)
    tls_warn_days: int = 14


# Tashqariga ochilishi xavfli xizmatlar: port -> (nom, jiddiylik, sabab).
# "0.0.0.0"/"::" da tinglash = butun tarmoqqa ochiq degani.
RISKY_LISTENERS: dict[int, tuple[str, str, str]] = {
    2375: (
        "Docker API (TLS'siz)",
        SEV_CRITICAL,
        "Autentifikatsiyasiz Docker API — kim ulansa hostda root oladi",
    ),
    23: ("Telnet", SEV_HIGH, "Parol ochiq matnda uzatiladi"),
    6379: ("Redis", SEV_HIGH, "Odatda parolsiz — ma'lumot o'qish/yozish mumkin"),
    27017: ("MongoDB", SEV_HIGH, "Odatda parolsiz — butun baza ochiq"),
    9200: ("Elasticsearch", SEV_HIGH, "Odatda autentifikatsiyasiz — indekslar ochiq"),
    11211: ("Memcached", SEV_HIGH, "Autentifikatsiya yo'q + UDP amplifikatsiya xavfi"),
    5900: ("VNC", SEV_HIGH, "Ekranga to'g'ridan-to'g'ri kirish"),
    445: ("SMB", SEV_MEDIUM, "Fayl almashish — ransomware nishoni"),
    3389: ("RDP", SEV_MEDIUM, "Brute-force nishoni; VPN orqasiga oling"),
    5432: ("PostgreSQL", SEV_MEDIUM, "Baza tarmoqqa ochiq"),
    3306: ("MySQL", SEV_MEDIUM, "Baza tarmoqqa ochiq"),
    9000: ("Portainer/PHP-FPM", SEV_MEDIUM, "Boshqaruv paneli tarmoqqa ochiq"),
    2049: ("NFS", SEV_MEDIUM, "Fayl tizimi tarmoqqa ochiq"),
}

_WILDCARD_HOSTS = ("0.0.0.0", "::", "*")


@dataclass(slots=True)
class Finding:
    """Topilgan bitta muammo."""

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
    """Diagnostika hisoboti."""

    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    duration_ms: float = 0.0
    skipped: list[str] = field(default_factory=list)
    link_type: str = "unknown"  # wired | wifi | cellular | vpn — chegaralar shunga moslandi

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
    """Jiddiylik bo'yicha saralaydi (critical -> info), keyin kategoriya bo'yicha."""
    return sorted(findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.category, f.title))


# ===========================================================================
# SOF baholash funksiyalari — tarmoqsiz, offline sinaladi
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
    """Bitta ping o'lchovini baholaydi (gateway yoki internet nishoni)."""
    th = th or Thresholds()
    out: list[Finding] = []
    rtt_limit = th.gateway_rtt_ms if is_lan else th.internet_rtt_ms
    where = "gateway" if is_lan else "internet nishoni"

    if not alive or loss_pct >= 100.0:
        out.append(
            Finding(
                severity=SEV_CRITICAL if is_lan else SEV_HIGH,
                category=CAT_CONNECTIVITY,
                title=f"{label} javob bermayapti",
                detail=f"{address} — 100% paket yo'qotish, {where} yetib bo'lmadi.",
                fix=(
                    "Kabel/Wi-Fi ulanishini, interfeys holatini va gateway manzilini tekshiring."
                    if is_lan
                    else "Provayder ulanishini yoki firewall ICMP qoidasini tekshiring."
                ),
                host=address,
                evidence={"loss_pct": loss_pct, "alive": alive},
            )
        )
        return out  # javob bermasa RTT/jitter ma'nosiz

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
                title=f"{label}: paket yo'qotish {loss_pct:.0f}%",
                detail=f"{address} — {loss_pct:.1f}% paket yetib bormadi.",
                fix=(
                    "Kabel/konnektor, kommutator porti yoki Wi-Fi signalini tekshiring."
                    if is_lan
                    else "Provayder kanalini va yo'ldagi hop'larni (mtr) tekshiring."
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
                title=f"{label}: kechikish yuqori ({avg_rtt:.0f} ms)",
                detail=f"{address} — o'rtacha RTT {avg_rtt:.1f} ms, kutilgan chegara "
                f"{rtt_limit:.0f} ms.",
                fix=(
                    "LAN'da bu 1-10 ms bo'lishi kerak — kommutator yuki, duplex "
                    "nomuvofiqligi yoki Wi-Fi shovqinini tekshiring."
                    if is_lan
                    else "Yo'lni mtr bilan tekshiring — qaysi hop kechiktirayotganini toping."
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
                title=f"{label}: jitter yuqori ({jitter:.0f} ms)",
                detail=f"{address} — kechikish tebranishi {jitter:.1f} ms. VoIP/video "
                "qo'ng'iroqlarda uzilish va metall ovoz beradi.",
                fix="QoS sozlang, kanal bandligini va Wi-Fi shovqinini tekshiring.",
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
    """Interfeys holati va xato hisoblagichlarini baholaydi."""
    th = th or Thresholds()
    out: list[Finding] = []

    if is_up and ipv4 and ipv4.startswith("169.254."):
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_INTERFACE,
                title=f"{name}: APIPA manzil ({ipv4})",
                detail="Interfeys DHCP'dan manzil olmagan va o'ziga 169.254.x.x "
                "bergan — tarmoqqa ulanmagan holat.",
                fix="DHCP serverni, VLAN'ni va kabel ulanishini tekshiring.",
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
                    title=f"{name}: paket xatolari {err_rate * 100:.2f}%",
                    detail=f"{errors} xato / {packets} paket. Bu apparat belgisi — "
                    "kabel, konnektor, SFP yoki port nosozligi.",
                    fix="Kabelni almashtirib ko'ring, kommutator portini o'zgartiring, "
                    "duplex/speed sozlamalarini tekshiring.",
                    host=name,
                    evidence={"errors": errors, "packets": packets, "rate": err_rate},
                )
            )
        if drop_rate > th.iface_error_rate:
            out.append(
                Finding(
                    severity=SEV_MEDIUM,
                    category=CAT_INTERFACE,
                    title=f"{name}: paket tashlanishi {drop_rate * 100:.2f}%",
                    detail=f"{drops} tashlangan / {packets} paket. Bufer to'lgan yoki "
                    "CPU yetishmayapti.",
                    fix="Interfeys yukini, ring buffer hajmini va offload sozlamalarini "
                    "ko'rib chiqing.",
                    host=name,
                    evidence={"drops": drops, "packets": packets, "rate": drop_rate},
                )
            )
    return out


def evaluate_listeners(
    listeners: list[tuple[str, int, str | None]],
) -> list[Finding]:
    """Tinglayotgan xizmatlar ro'yxatini baholaydi.

    `listeners` — (bind_host, port, process) uchliklari. Faqat wildcard
    (`0.0.0.0`/`::`) da tinglayotganlar xavfli deb hisoblanadi: localhost'ga
    bog'langan xizmat tarmoqqa ochiq emas.
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
                title=f"{name} butun tarmoqqa ochiq (port {port})",
                detail=f"{host}:{port} da tinglayapti"
                + (f" (jarayon: {proc})" if proc else "")
                + f". {why}.",
                fix=f"Faqat localhost'ga bog'lang (127.0.0.1:{port}) yoki firewall "
                "bilan cheklang; kerak bo'lsa autentifikatsiya va TLS yoqing.",
                evidence={"bind": host, "port": port, "process": proc},
            )
        )
    return out


def evaluate_remote_exposure(
    services: list[tuple[str, int]],
) -> list[Finding]:
    """LAN'dagi BOSHQA hostlarda ochiq xavfli portlarni baholaydi — SOF funksiya.

    `evaluate_listeners` dan ATAYLAB ajratilgan. U "sizning mashinangizda
    xizmat tarmoqqa ochiq" deydi va "localhost'ga bog'lang" deb maslahat
    beradi — masofaviy qurilma uchun bu **noto'g'ri**: bu sizning
    xizmatingiz emas, siz uni bog'lay olmaysiz. Aralashtirish foydalanuvchini
    o'z mashinasini tuzatishga yuborardi, holbuki muammo qo'shni NVR'da.

    `services` — `(ip, port)` juftliklari.
    """
    out: list[Finding] = []
    by_port: dict[int, list[str]] = {}
    for ip, port in services:
        if port in RISKY_LISTENERS:
            by_port.setdefault(port, []).append(ip)
    for port, ips in sorted(by_port.items()):
        name, sev, why = RISKY_LISTENERS[port]
        # Masofaviy topilma bir daraja pastroq: bu sizning hostingiz emas,
        # lekin tarmoqdagi xavf sifatida baribir muhim.
        lowered = {SEV_CRITICAL: SEV_HIGH, SEV_HIGH: SEV_MEDIUM}.get(sev, sev)
        out.append(
            Finding(
                severity=lowered,
                category=CAT_EXPOSURE,
                title=f"Tarmoqda ochiq {name}: {len(ips)} ta host (port {port})",
                detail=f"Manzillar: {', '.join(sorted(ips)[:6])}. {why}. Bu BOSHQA "
                "qurilmalar — o'z mashinangizni emas, o'sha qurilmalarni "
                "yoki segment firewall'ini sozlash kerak.",
                fix=f"Qurilmalarni aniqlang va {port}-portni VLAN/ACL bilan cheklang.",
                evidence={"port": port, "hosts": sorted(ips)},
            )
        )
    return out


def evaluate_ipv6(
    link_local_count: int,
    global_count: int,
    has_ipv6_internet: bool | None = None,
) -> list[Finding]:
    """IPv6 holatini baholaydi.

    Eng ko'p uchraydigan real muammo: qurilmalarda IPv6 manzil bor (SLAAC
    avtomatik beradi), lekin global marshrut yo'q. Natijada ilovalar avval
    IPv6'ni sinab, timeout kutadi va **hamma narsa sekin ishlaydi** — sababi
    ko'rinmaydi, chunki IPv4 oxir-oqibat ishlaydi.
    """
    out: list[Finding] = []
    if link_local_count == 0 and global_count == 0:
        out.append(
            Finding(
                severity=SEV_INFO,
                category=CAT_IPV6,
                title="IPv6 qo'shni topilmadi",
                detail="Tarmoqda IPv6 ishlatilmayapti (yoki qo'shni jadval bo'sh).",
                evidence={"link_local": 0, "global": 0},
            )
        )
        return out

    if global_count == 0 and link_local_count > 0:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_IPV6,
                title=f"IPv6 faqat link-local ({link_local_count} host)",
                detail="Qurilmalarda fe80::/10 manzil bor, lekin global/ULA manzil "
                "yo'q. Ilovalar IPv6'ni birinchi sinab timeout kutishi mumkin "
                "— bu 'internet sekin' shikoyatining ko'rinmas sababi.",
                fix="Yo IPv6'ni to'liq sozlang (router advertisement + prefiks), yo "
                "qurilmalarda butunlay o'chirib qo'ying — yarim holat eng yomoni.",
                evidence={"link_local": link_local_count, "global": global_count},
            )
        )
    if has_ipv6_internet is False and global_count > 0:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_IPV6,
                title="IPv6 manzil bor, lekin internet yo'q",
                detail=f"{global_count} global IPv6 manzil mavjud, ammo IPv6 orqali "
                "tashqi host'ga yetib bo'lmadi. Bu 'qora tuynuk' holati.",
                fix="Router advertisement va IPv6 marshrutni tekshiring; tuzatilmasa "
                "IPv6'ni o'chirib qo'ying (yarim ishlaydigan holatdan yaxshi).",
                evidence={"global": global_count},
            )
        )
    return out


def is_real_device_mac(mac: str | None) -> bool:
    """MAC haqiqiy qurilmaniki (unicast) ekanini aytadi — SOF funksiya.

    Dublikat aniqlashda SHART: broadcast (`ff:ff:ff:ff:ff:ff`) va multicast
    MAC'lar tabiiy ravishda bir nechta IP bilan bog'lanadi va ularni "MAC
    dublikati" deb belgilash sof soxta pozitiv beradi.

    Multicast belgisi — birinchi oktetning eng kichik biti (I/G bit) 1 bo'lishi:
    IPv4 multicast `01:00:5e:...`, IPv6 multicast `33:33:...`.
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
    """LAN inventarizatsiyasini baholaydi — `(ip, mac, is_gateway)` uchliklari.

    Bir MAC bir nechta IP'da ko'rinishi: yo router/NAT (normal), yo ARP
    spoofing/dublikat konfiguratsiya (muammo). Gateway MAC'i boshqa IP'larda
    ham chiqsa — bu ayniqsa shubhali.
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
                title=f"Bir MAC {len(ips)} ta IP'da: {mac}",
                detail=f"{mac} manzili {', '.join(sorted(ips)[:6])} da ko'rindi."
                + (
                    " Bu gateway MAC'i — ARP spoofing ehtimoli bor."
                    if is_gw
                    else " Bu router/NAT bo'lishi mumkin, yoki IP dublikati."
                ),
                fix=(
                    "Gateway MAC'ini statik ARP bilan qulflang va tarmoqda "
                    "kutilmagan qurilma yo'qligini tekshiring."
                    if is_gw
                    else "Qurilma router/proxy ekanini tasdiqlang; aks holda IP "
                    "dublikatini bartaraf qiling."
                ),
                evidence={"mac": mac, "ips": sorted(ips)},
            )
        )
    return out


def evaluate_web(
    services: list[tuple[str, int, str, bool, str, str | None]],
) -> list[Finding]:
    """Web xizmatlarni baholaydi — `(ip, port, scheme, is_admin, risk, product)`.

    Asosiy topilma: **shifrlanmagan HTTP ustidagi admin panel**. Bunday panelga
    kirilganda login/parol tarmoqda ochiq matnda uchadi.
    """
    out: list[Finding] = []
    for ip, port, scheme, is_admin, risk, product in services:
        if not is_admin:
            continue
        label = product or "boshqaruv paneli"
        if risk == "high":
            out.append(
                Finding(
                    severity=SEV_HIGH,
                    category=CAT_EXPOSURE,
                    title=f"{label}: parol ochiq matnda ({ip}:{port})",
                    detail=f"http://{ip}:{port}/ — admin panel HTTP ustida va HTTP "
                    "Basic/Digest autentifikatsiya ishlatadi. Login va parol "
                    "tarmoqda shifrlanmagan holda uzatiladi.",
                    fix="HTTPS'ga o'tkazing yoki panelni faqat VPN/ishonchli tarmoqdan "
                    "ochiq qoldiring.",
                    host=ip,
                    evidence={"port": port, "scheme": scheme, "product": product},
                )
            )
        elif risk == "medium":
            out.append(
                Finding(
                    severity=SEV_MEDIUM,
                    category=CAT_EXPOSURE,
                    title=f"{label}: HTTP ustidagi admin panel ({ip}:{port})",
                    detail=f"http://{ip}:{port}/ — boshqaruv interfeysi shifrlanmagan "
                    "kanalda ishlayapti.",
                    fix="TLS sertifikat qo'yib HTTPS'ga o'tkazing.",
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
    """DNS holatini baholaydi — `(server, ok, elapsed_ms, is_system)` to'rtliklari.

    **`is_system` jiddiylikni hal qiladi.** Ilgari bu funksiya faqat ommaviy
    serverlarni (8.8.8.8, 1.1.1.1...) ko'rardi va ularning hammasi javob
    bermasa "Barcha DNS serverlar javob bermayapti / Firewall UDP/53 ni
    tekshiring" deb HIGH berardi. Korporativ tarmoqlarda tashqi 53-port
    **ataylab** yopiladi — natijada butunlay sog'lom tarmoqda soxta ogohlantirish
    va `exit 2` chiqardi, ustiga tavsiya ham noto'g'ri edi.

    Endi qoida:

    * tizim resolverlari o'lik — HAQIQIY nosozlik (`high`);
    * tizim ishlaydi, ommaviylar yopiq — bu odatiy siyosat (`info`, muammo emas);
    * tizim resolveri umuman aniqlanmagan — eski, ehtiyotkor xulosa saqlanadi.

    Eski uchlik (`is_system`siz) ham qabul qilinadi — u holda hammasi
    "tizim emas" deb olinadi va eski xatti-harakat saqlanadi.
    """
    th = th or Thresholds()
    out: list[Finding] = []
    # Chaqiruvchi eski uchlik bergan bo'lsa ham yiqilmaymiz.
    rows = [(r[0], r[1], r[2], r[3] if len(r) > 3 else False) for r in resolvers]

    if not system_ok:
        out.append(
            Finding(
                severity=SEV_CRITICAL,
                category=CAT_DNS,
                title="Tizim DNS ishlamayapti",
                detail=f"Nomni IP'ga aylantirib bo'lmadi: {system_error or 'sabab noma`lum'}. "
                "Bu holatda hech qanday sayt/xizmat nomi bilan ochilmaydi.",
                fix="/etc/resolv.conf (yoki DHCP'dan kelgan DNS) to'g'riligini va DNS "
                "serverga yetib borishni tekshiring.",
                evidence={"error": system_error},
            )
        )

    system_rows = [r for r in rows if r[3]]
    public_rows = [r for r in rows if not r[3]]
    dead_system = [s for s, ok, _, _ in system_rows if not ok]
    dead_public = [s for s, ok, _, _ in public_rows if not ok]
    dead = [s for s, ok, _, _ in rows if not ok]

    if system_rows and len(dead_system) == len(system_rows):
        # Mashina o'zi ishlatadigan resolver javob bermayapti — har doim muammo.
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DNS,
                title="Tizim DNS serveri javob bermayapti",
                detail=f"Mashina sozlangan {len(system_rows)} resolverning hech biri "
                f"javob bermadi: {', '.join(dead_system[:5])}. Nom bo'yicha "
                "hech narsa ochilmaydi (kesh tugagach).",
                fix="Resolver'gacha yo'lni tekshiring (ping) va UDP/53 ochiqligiga "
                "ishonch hosil qiling.",
                evidence={"dead": dead_system, "scope": "system"},
            )
        )
    elif system_rows and public_rows and len(dead_public) == len(public_rows):
        # Tizim ishlayapti, faqat tashqi serverlar yopiq — bu KO'P TARMOQDA
        # ataylab qo'yilgan siyosat, nosozlik emas. INFO => is_problem False,
        # ya'ni exit kodga ta'sir qilmaydi.
        out.append(
            Finding(
                severity=SEV_INFO,
                category=CAT_DNS,
                title="Tashqi DNS serverlarga chiqish yopiq",
                detail=f"Tizim resolveri ishlayapti, lekin {len(public_rows)} ta ommaviy "
                f"server javob bermadi: {', '.join(dead_public[:5])}. Ko'p "
                "korxonada bu ataylab qilinadi (faqat ichki DNS'ga ruxsat).",
                fix=None,
                evidence={"dead": dead_public, "scope": "public"},
            )
        )
    elif dead and len(dead) == len(rows) and rows:
        # Tizim resolveri aniqlanmagan holat — eski, ehtiyotkor xulosa.
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DNS,
                title="Barcha DNS serverlar javob bermayapti",
                detail=f"Tekshirilgan {len(rows)} server javob bermadi: {', '.join(dead[:5])}.",
                fix="Firewall UDP/53 va TCP/53 ni bloklamayotganini tekshiring.",
                evidence={"dead": dead},
            )
        )
    elif dead:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_DNS,
                title=f"{len(dead)} DNS server javob bermadi",
                detail=f"Javobsiz: {', '.join(dead[:5])}. Boshqalari ishlayapti.",
                fix="Ishlamaydigan serverlarni ro'yxatdan olib tashlang.",
                evidence={"dead": dead},
            )
        )

    # Sekinlikni faqat TIZIM resolverlari bo'yicha o'lchaymiz (ular aniqlangan
    # bo'lsa): ommaviy serverga 120 ms — normal masofa, tizim resolveriga
    # 120 ms esa haqiqatan har sahifa ochilishini kechiktiradi.
    measured = system_rows or rows
    slow = [(s, ms) for s, ok, ms, _ in measured if ok and ms > th.dns_slow_ms]
    if slow:
        worst = max(slow, key=lambda x: x[1])
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_DNS,
                title=f"DNS sekin ({worst[1]:.0f} ms)",
                detail=f"{len(slow)} server {th.dns_slow_ms:.0f} ms dan sekin javob "
                f"berdi; eng sekini {worst[0]} — {worst[1]:.0f} ms. Har sahifa "
                "ochilishi shu qadar kechikadi.",
                fix="Yaqinroq yoki tezroq resolver tanlang (masalan lokal kesh serveri).",
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
    """TLS sertifikat muddatini baholaydi."""
    th = th or Thresholds()
    if error:
        return [
            Finding(
                severity=SEV_HIGH,
                category=CAT_TLS,
                title=f"{host}: TLS tekshirib bo'lmadi",
                detail=error,
                fix="Sertifikat va port to'g'riligini tekshiring.",
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
                title=f"{host}: sertifikat muddati TUGAGAN",
                detail=f"{abs(days_left)} kun oldin tugagan. Brauzerlar ogohlantirish "
                "ko'rsatadi, API mijozlari ulanmaydi.",
                fix="Sertifikatni darhol yangilang (certbot/ACME avtomatlashtiring).",
                host=host,
                evidence={"days_left": days_left},
            )
        ]
    if days_left <= th.tls_warn_days:
        return [
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_TLS,
                title=f"{host}: sertifikat {days_left} kunda tugaydi",
                detail=f"Muddat tugashiga {days_left} kun qoldi.",
                fix="Avtomatik yangilashni (ACME) sozlang.",
                host=host,
                evidence={"days_left": days_left},
            )
        ]
    return []


# ===========================================================================
# Orkestrator — tarmoq chaqiruvlari + yuqoridagi sof baholovchilar
# ===========================================================================

# Boshqaruvchi (management) qurilma turlari — `webscan` aniqlagan `device_kind`.
# Sysadmin uchun eng muhim inventar: tarmoqni boshqaradigan qurilmalar.
MANAGEMENT_KINDS: frozenset[str] = frozenset(
    {"firewall", "router", "tarmoq", "hypervisor", "kamera/NVR", "telefoniya", "NAS"}
)


def is_management_device(device_kind: str | None, is_gateway: bool = False) -> bool:
    """Qurilma tarmoqni boshqaruvchi turdami (router/firewall/switch/AP/NVR)."""
    return is_gateway or (device_kind in MANAGEMENT_KINDS if device_kind else False)


async def run_diagnostics(
    quick: bool = False,
    include_web: bool = True,
    include_ipv6: bool = True,
    tls_hosts: list[str] | None = None,
    th: Thresholds | None = None,
    max_hosts: int = 64,
) -> Report:
    """Barcha tekshiruvlarni bajarib, jiddiylik bo'yicha saralangan hisobot beradi.

    `quick=True` — sekin bosqichlarni (web skan, IPv6 multicast) tashlab ketadi.
    Har bosqich alohida `try` ichida: bittasi yiqilsa qolganlari davom etadi
    (`report.skipped` ga sabab yoziladi) — diagnostika tooli o'zi yiqilmasligi
    kerak.
    """
    started = time.perf_counter()
    report = Report()
    findings: list[Finding] = []

    from systop.core import netinfo, ping, topology

    # --- 0. Ulanish turini aniqlab, chegaralarni MOSLASHTIRAMIZ ------------
    # Bitta mutlaq raqam har tarmoqda to'g'ri bo'lolmaydi: gateway'ga 50 ms
    # kabelda falokat, Wi-Fi'da normal, LTE'da yaxshi. Foydalanuvchi config'da
    # aniq qiymat qo'ygan bo'lsa u ustun turadi.
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
    except Exception:  # noqa: BLE001 — aniqlanmasa `unknown` profil ishlatiladi
        link = LINK_UNKNOWN
    th = thresholds_for_link(link, th)
    report.link_type = link

    # --- 1. Interfeyslar -----------------------------------------------------
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
    except Exception as exc:  # noqa: BLE001 — diagnostika to'xtamasligi kerak
        report.skipped.append(f"interfeys: {type(exc).__name__}")

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

    # --- 2b. IPv6 ULANISHI (nafaqat mavjudligi) -----------------------------
    # IPv6 hostlarni topish boshqa, IPv6 orqali TRAFIK o'tishi boshqa. Dual-stack
    # tarmoqda IPv6 buzilgani IPv4 ishlab turganda ko'rinmaydi va "ba'zi saytlar
    # sekin" holatini beradi (ilova avval IPv6 sinab, timeout kutadi).
    if include_ipv6 and not quick:
        try:
            # MUHIM: IPv6 yetishuvini faqat GLOBAL IPv6 manzil bo'lganda
            # sinaymiz. Manzil yo'q bo'lsa javob kelmasligi tabiiy — buni
            # muammo deb ko'rsatish sof shovqin, ustiga u allaqachon
            # "IPv6 faqat link-local" topilmasi bilan qoplangan.
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
                # Manzil bor, lekin hech qayerga yetib bo'lmasa — "qora tuynuk".
                if not any(x.alive for x in r6):
                    findings += evaluate_ipv6(0, 1, has_ipv6_internet=False)
                report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"IPv6 ulanish: {type(exc).__name__}")

    # --- 3. Ochiq tinglayotgan xizmatlar (lokal host) ------------------------
    try:
        from systop.core import connections

        scan = await connections.scan_connections(states=["LISTEN"])
        if not scan.permitted:
            # MUHIM: bu yerda `checks_run` OSHIRILMAYDI. Aks holda hisobot
            # "N ta tekshiruv bajarildi, muammo yo'q" deb turadi, aslida esa
            # xavfsizlik tekshiruvi umuman ishlamagan bo'ladi — soxta
            # xotirjamlik. INFO topilma `--json` iste'molchilariga ham
            # ko'rinadi (is_problem=False, exit kodga ta'sir qilmaydi).
            report.skipped.append(f"tinglovchilar: ruxsat yo'q ({scan.error})")
            findings.append(
                Finding(
                    severity=SEV_INFO,
                    category=CAT_EXPOSURE,
                    title="Ochiq xizmatlar tekshirilmadi",
                    detail=(
                        "Bu tizimda socket jadvalini o'qishga ruxsat yo'q, "
                        "shuning uchun ochiq portlar (Docker API, Redis, "
                        "telnet...) TEKSHIRILMADI — 'muammo yo'q' degani emas."
                    ),
                    fix="To'liq tekshiruv uchun: sudo systop doctor",
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
        report.skipped.append(f"tinglovchilar: {type(exc).__name__}")

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

    # --- 5. LAN inventarizatsiyasi (IPv4) -----------------------------------
    lan_hosts: list[topology.LanHost] = []
    reported_dup_macs: set[str] = set()
    try:
        lan_hosts = await topology.discover_lan(max_hosts=max_hosts)
        lan_findings = evaluate_lan([(h.ip, h.mac, h.is_gateway) for h in lan_hosts], gateway)
        findings += lan_findings
        # 13-bosqich (arpwatch) xuddi shu dublikatni qayta topadi. Bir faktni
        # ikki marta ko'rsatish hisobotga ishonchni yo'qotadi, shuning uchun
        # bu yerda ko'rilgan MAC'larni eslab qolamiz.
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

    # --- 7. Web/admin panellar ----------------------------------------------
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

    # --- 7b. IPv6 hostlarda ochiq port (NDP orqali topilganlar) -------------
    # IPv6 /64 ni sweep qilib bo'lmaydi, LEKIN qo'shni jadvalidan topilgan aniq
    # manzillarni skan qilish mumkin — "IPv6'da ochiq port bormi" savoliga
    # javob shu yo'l bilan olinadi.
    if include_ipv6 and not quick:
        try:
            from systop.core.ports import scan_targets

            # O'ZIMIZNI skanerlamaymiz: `ndp -an` da o'z `fe80::…%en0`
            # manzillarimiz ham turadi va ularni skan qilib "bular BOSHQA
            # qurilmalar, ularni sozlang" deb aytish mantiqsiz.
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
                # MUHIM: bular MASOFAVIY hostlar. `evaluate_listeners` ni
                # ishlatish "sizning xizmatingiz ochiq, localhost'ga bog'lang"
                # degan NOTO'G'RI maslahatni berardi — bu qo'shni qurilma.
                remote6 = [
                    (h.resolved_ip or h.host, p.port) for h in sweep.hosts for p in h.open_ports
                ]
                findings += evaluate_remote_exposure(remote6)
                report.checks_run += 1
        except Exception as exc:  # noqa: BLE001
            report.skipped.append(f"IPv6 port: {type(exc).__name__}")

    # --- 8b. Wi-Fi (apparat bo'lsa) -----------------------------------------
    try:
        from systop.core import wifi as wifi_mod

        w = await wifi_mod.status()
        overlap = 0
        if w.channel and w.is_24ghz:
            overlap = len(wifi_mod.overlapping_24ghz(w.channel, w.neighbours))
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

    # --- 8c. Link tezligi (kabel/duplex nosozligi) --------------------------
    try:
        # Virtual interfeyslar chetlab o'tiladi — ularda link tezligi ma'nosiz.
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
        report.skipped.append(f"link tezligi: {type(exc).__name__}")

    # --- 9. Vaqt (NTP) ------------------------------------------------------
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

    # --- 10. Marshrut jadvali ------------------------------------------------
    try:
        from systop.core import routes as routes_mod

        table = await routes_mod.list_routes()
        alive = await routes_mod.check_next_hops(table)
        # 2-bosqichdagi ping allaqachon o'lik gateway'ni CRITICAL qilib
        # ko'rsatgan bo'lishi mumkin — takrorlamaymiz.
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
        # IPv6 marshruti faqat hostda GLOBAL IPv6 manzil bo'lsa baholanadi.
        # IPv4-only tarmoqda (dunyoning ko'pchiligida) IPv6 default'ining
        # yo'qligi mutlaqo normal — uni muammo deb ko'rsatish sof shovqin,
        # ustiga u allaqachon `evaluate_ipv6` bilan qoplangan.
        if any(i.ipv6_global for i in netinfo.list_interfaces()):
            findings += evaluate_routes(
                default_count=len(table.routable_defaults_for("ipv6")),
                gateways=[g for g in table.routable_default_gateways if _gw_family(g) == "ipv6"],
                dead_gateways=[g for g in dead_all if _gw_family(g) == "ipv6"],
                family="ipv6",
            )
        report.checks_run += 1
    except Exception as exc:  # noqa: BLE001
        report.skipped.append(f"marshrut: {type(exc).__name__}")

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

    # --- 13. ARP kuzatuv (baseline bilan farq) -------------------------------
    try:
        from systop.core import arpwatch

        # `update=False` — diagnostika holatni O'ZGARTIRMASLIGI kerak; baseline
        # faqat `systop arpwatch` buyrug'ida yangilanadi.
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
        report.skipped.append(f"ARP kuzatuv: {type(exc).__name__}")

    # --- 8. TLS (faqat so'ralgan hostlar) -----------------------------------
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


# --- Yangi kategoriyalar (0.6.0) --------------------------------------------
CAT_TIME = "vaqt"
CAT_ROUTE = "marshrut"
CAT_MTU = "MTU"
CAT_DHCP = "DHCP"


def evaluate_ntp(
    responded: int,
    total: int,
    median_offset_s: float | None,
    th: Thresholds | None = None,
) -> list[Finding]:
    """Soat siljishini baholaydi — SOF funksiya."""
    out: list[Finding] = []
    if total and responded == 0:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_TIME,
                title="NTP serverlari javob bermadi",
                detail=f"{total} ta NTP serveridan hech biri javob bermadi — soatni "
                "tekshirib bo'lmadi (UDP/123 bloklangan bo'lishi mumkin).",
                fix="Firewall'da UDP/123 chiqishiga ruxsat bering yoki "
                "lokal NTP server ko'rsating.",
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
                "Kerberos/Active Directory 300 soniyadan katta siljishda "
                "autentifikatsiyani RAD ETADI — domenga kirish ishlamaydi."
            ),
        )
    elif a >= 30:
        sev, why = (
            SEV_HIGH,
            (
                "TLS sertifikatlari noto'g'ri 'muddati tugagan' deb ko'rinishi va "
                "TOTP/2FA kodlari rad etilishi mumkin."
            ),
        )
    elif a >= 1:
        sev, why = SEV_MEDIUM, "Loglar boshqa serverlar bilan mos kelmaydi."
    else:
        return out
    out.append(
        Finding(
            severity=sev,
            category=CAT_TIME,
            title=f"Soat siljigan: {median_offset_s:+.1f} s",
            detail=f"{responded}/{total} NTP serveri bo'yicha mediana siljish "
            f"{median_offset_s:+.2f} soniya. {why}",
            fix="Vaqtni NTP bilan sinxronlang (macOS: Sozlamalar > Sana va vaqt; "
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
    """Marshrut jadvalini baholaydi — SOF funksiya.

    `default_count`/`gateways` — MA'NOLI default'lar bo'yicha berilishi kerak
    (`RouteTable.routable_defaults`); aks holda macOS'dagi yalang'och
    `fe80::%utunN` yozuvlari soxta "bir nechta default" ogohlantirishini
    beradi.

    `family` — `ipv4` yoki `ipv6`. Ikkalasi ATAYLAB alohida baholanadi:

    * IPv4 default yo'q — hech qayerga chiqib bo'lmaydi, `critical`;
    * IPv6 default yo'q — IPv4 orqali hammasi ishlayveradi, `high`, va
      chaqiruvchi buni faqat hostda global IPv6 manzil bo'lsa so'raydi.

    Ikkalasini bitta hisobda qo'shsak, IPv4-only tarmoqda (dunyoning
    ko'pchiligida) doimiy soxta "Default marshrut yo'q" chiqardi.
    """
    is_v6 = family == "ipv6"
    tag = "IPv6 " if is_v6 else ""
    out: list[Finding] = []
    if default_count == 0:
        out.append(
            Finding(
                severity=SEV_HIGH if is_v6 else SEV_CRITICAL,
                category=CAT_ROUTE,
                title=f"{tag}default marshrut yo'q" if is_v6 else "Default marshrut yo'q",
                detail=(
                    "Marshrut jadvalida IPv6 default (::/0) yo'q — IPv6 orqali "
                    "tashqariga chiqib bo'lmaydi (IPv4 ishlayveradi)."
                    if is_v6
                    else "Marshrut jadvalida default (0.0.0.0/0) yo'q — lokal tarmoqdan "
                    "tashqariga hech narsa chiqmaydi."
                ),
                fix=(
                    "Routerdan RA (Router Advertisement) kelayotganini tekshiring."
                    if is_v6
                    else "DHCP'dan gateway kelmaganini yoki qo'lda sozlamani tekshiring."
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
                title=f"{default_count} ta {tag}default marshrut",
                detail=f"Bir nechta default gateway: {', '.join(gateways[:4])}. Trafik "
                "gohida bir yo'ldan, gohida boshqasidan ketadi — alomat "
                "'ba'zan ishlaydi, ba'zan yo'q'.",
                fix="Keraksiz interfeys default'ini olib tashlang yoki metric bilan "
                "ustuvorlikni aniq belgilang.",
                evidence={"gateways": gateways, "family": family},
            )
        )

    for gw in dead_gateways:
        out.append(
            Finding(
                severity=SEV_CRITICAL,
                category=CAT_ROUTE,
                title=f"{tag}default gateway javob bermayapti: {gw}",
                detail="Marshrut jadvali to'g'ri, lekin next-hop ping'ga javob bermayapti.",
                fix="Gateway qurilmasi yoqilganini va kabel/VLAN to'g'riligini tekshiring.",
                host=gw,
                evidence={"family": family},
            )
        )

    if has_vpn_split and not is_v6:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_ROUTE,
                title="VPN barcha trafikni o'ziga olgan",
                detail="`0.0.0.0/1` + `128.0.0.0/1` marshrutlari bor — VPN default'dan "
                "ustun turadi va butun trafik tunnel orqali ketadi.",
                fix="Split-tunnel kerak bo'lsa VPN profilini sozlang.",
            )
        )
    return out


def evaluate_mtu(path_mtu: int | None, error: str | None = None) -> list[Finding]:
    """Path MTU natijasini baholaydi — SOF funksiya."""
    if error:
        return [
            Finding(
                severity=SEV_LOW,
                category=CAT_MTU,
                title="MTU o'lchab bo'lmadi",
                detail=error,
                fix="Nishon ICMP'ga javob berishini tekshiring yoki boshqa host tanlang.",
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
            title=f"Path MTU kamaytirilgan: {path_mtu}",
            detail=f"Yo'ldagi eng kichik MTU {path_mtu} bayt (standart 1500). Katta "
            "javob qaytaradigan saytlar yarim yuklanib qotishi mumkin — "
            "PMTUD qora tuynugi.",
            fix=f"Interfeys MTU'sini {path_mtu} ga tushiring yoki TCP MSS clamping "
            "yoqing (router/VPN konsentratorda).",
            evidence={"path_mtu": path_mtu},
        )
    ]


def evaluate_dhcp(
    servers: list[str],
    lease_server: str | None = None,
    expected_server: str | None = None,
    partial: bool = False,
) -> list[Finding]:
    """DHCP holatini baholaydi — SOF funksiya.

    `partial=True` — broadcast probe'ga javob kelmadi. Bu "server yo'q" degani
    EMAS (root'siz 68-portga bog'lanib bo'lmaydi), shuning uchun ogohlantirish
    berilmaydi — faqat faol lease bo'yicha xulosa chiqariladi.
    """
    out: list[Finding] = []
    if len(servers) > 1:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DHCP,
                title=f"Tarmoqda {len(servers)} ta DHCP server",
                detail=f"Javob berganlar: {', '.join(servers)}. Ikkinchi (rogue) DHCP "
                "server qurilmalarga noto'g'ri gateway/DNS berishi mumkin — "
                "alomat: 'ba'zi kompyuterlarda internet bor, ba'zilarida yo'q'.",
                fix="Ruxsatsiz DHCP serverni toping va o'chiring; kommutatorda "
                "DHCP snooping yoqing.",
                evidence={"servers": servers},
            )
        )
    if expected_server and lease_server and lease_server != expected_server:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_DHCP,
                title="Manzil kutilmagan DHCP serverdan olingan",
                detail=f"Joriy lease `{lease_server}` dan, kutilgani `{expected_server}`.",
                fix="Rogue DHCP serverni qidiring.",
                evidence={"actual": lease_server, "expected": expected_server},
            )
        )
    return out


def evaluate_arpwatch(
    mac_changes: list[tuple[str, str, str]],
    duplicates: list[tuple[str, list[str]]],
    first_run: bool = False,
) -> list[Finding]:
    """ARP o'zgarishlarini baholaydi — SOF funksiya.

    `mac_changes` — `(ip, eski_mac, yangi_mac)`; `duplicates` — `(mac, ip_lar)`.
    Birinchi ishlashda taqqoslash uchun asos yo'q — hech narsa qaytarilmaydi
    (aks holda har yangi mashinada "hamma host yangi" shovqini chiqardi).
    """
    if first_run:
        return []
    out: list[Finding] = []
    for ip, old, new in mac_changes:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_LAN,
                title=f"{ip}: MAC o'zgardi",
                detail=f"{old} -> {new}. Bu ARP spoofing (MITM), IP dublikati yoki "
                "qurilma almashtirilgani bo'lishi mumkin.",
                fix="Qurilma haqiqatan almashtirilganini tasdiqlang; aks holda "
                "kommutator portini va ARP jadvalini tekshiring.",
                host=ip,
                evidence={"old_mac": old, "new_mac": new},
            )
        )
    for mac, ips in duplicates:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_LAN,
                title=f"Bir MAC {len(ips)} ta IP'da: {mac}",
                detail=f"Manzillar: {', '.join(ips[:6])}. Router/NAT bo'lishi mumkin, "
                "yoki IP dublikati.",
                fix="Qurilma router ekanini tasdiqlang; aks holda IP taqsimotini tekshiring.",
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
    """Wi-Fi holatini baholaydi — SOF funksiya.

    Wi-Fi apparati yo'q (server, kabelli ish stansiyasi) yoki ulanmagan bo'lsa
    **hech narsa qaytarmaydi**. Aks holda har Ethernet hostda soxta "Wi-Fi
    muammosi" chiqardi — bugungi soxta pozitiv saboqlaridan biri.
    """
    if not available or not connected:
        return []
    out: list[Finding] = []

    # --- signal kuchi ---
    if rssi is not None:
        if rssi < -80:
            out.append(
                Finding(
                    severity=SEV_CRITICAL,
                    category=CAT_WIFI,
                    title=f"Wi-Fi signali juda zaif ({rssi} dBm)",
                    detail="Bu darajada paketlar qayta-qayta yuboriladi; tezlik "
                    "yiqiladi va ulanish uzilib turadi.",
                    fix="Access point'ga yaqinlashing yoki oraliqqa AP/mesh qo'ying.",
                    evidence={"rssi_dbm": rssi},
                )
            )
        elif rssi < -70:
            out.append(
                Finding(
                    severity=SEV_MEDIUM,
                    category=CAT_WIFI,
                    title=f"Wi-Fi signali zaif ({rssi} dBm)",
                    detail="Chegaraviy signal — yuk ostida tezlik tushadi.",
                    fix="AP joylashuvini yoki antenna yo'nalishini ko'rib chiqing.",
                    evidence={"rssi_dbm": rssi},
                )
            )

    # --- SNR: signalning o'zidan muhimroq ---
    if snr is not None and snr < 15:
        out.append(
            Finding(
                severity=SEV_HIGH,
                category=CAT_WIFI,
                title=f"Wi-Fi shovqin darajasi yuqori (SNR {snr} dB)",
                detail="Signal shovqindan yetarlicha ajralmayapti. Signal kuchli "
                "bo'lsa ham bu tezlikni yiqitadi — sabab boshqa radio manba.",
                fix="Mikroto'lqinli pech, simsiz telefon, Bluetooth qurilmalarini "
                "yoki qo'shni AP'larni tekshiring; 5 GHz ga o'ting.",
                evidence={"snr_db": snr},
            )
        )

    # --- 2.4 GHz da o'tirish, 5 GHz mavjud bo'lsa ---
    if band == "2.4GHz" and five_ghz_available:
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_WIFI,
                title="2.4 GHz da ulangan, 5 GHz mavjud",
                detail="2.4 GHz sekin (20 MHz da ~144 Mbps) va tiqilinch. Atrofda "
                "5 GHz AP ko'rinyapti — u ancha keng kanal beradi.",
                fix="Qurilmani 5 GHz SSID'ga ulang yoki routerda band-steering yoqing.",
                evidence={"band": band},
            )
        )

    # --- kanal ustma-ustligi (faqat 2.4 GHz) ---
    if band == "2.4GHz" and overlap_count >= 3:
        out.append(
            Finding(
                severity=SEV_MEDIUM if overlap_count < 6 else SEV_HIGH,
                category=CAT_WIFI,
                title=f"Kanal {channel} tiqilinch ({overlap_count} ta AP xalaqit beryapti)",
                detail="2.4 GHz da faqat 3 ta ustma-ust tushmaydigan kanal bor "
                "(1/6/11). Qo'shni AP'lar shu kanalni bo'lishyapti — SNR "
                "yaxshi bo'lsa ham o'tkazuvchanlik tushadi.",
                fix="5 GHz ga o'ting; iloji bo'lmasa eng bo'sh 1/6/11 kanalni tanlang.",
                evidence={"channel": channel, "overlap": overlap_count},
            )
        )

    # --- 2.4 GHz da noto'g'ri kanal ---
    if band == "2.4GHz" and channel is not None and channel not in (1, 6, 11):
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_WIFI,
                title=f"2.4 GHz da nostandart kanal ({channel})",
                detail="1/6/11 dan boshqa kanal qo'shnilar bilan qisman ustma-ust "
                "tushadi va ikkala tomonga ham xalaqit beradi.",
                fix="Routerda kanalni 1, 6 yoki 11 ga o'zgartiring.",
                evidence={"channel": channel},
            )
        )

    # --- PHY karta imkoniyatidan past ---
    rank = {"legacy": 0, "n": 1, "ac": 2, "ax": 3, "be": 4}
    if phy_gen and card_gen and rank.get(phy_gen, 0) < rank.get(card_gen, 0):
        out.append(
            Finding(
                severity=SEV_MEDIUM,
                category=CAT_WIFI,
                title=f"Wi-Fi {phy_gen} da ishlayapti, karta {card_gen} qo'llab-quvvatlaydi",
                detail=f"Adapter 802.11{card_gen} ga qodir, lekin ulanish "
                f"802.11{phy_gen} da — tezlikning katta qismi ishlatilmayapti.",
                fix="Router/AP proshivkasini va simsiz rejim sozlamasini tekshiring "
                "(eski rejim majburan yoqilgan bo'lishi mumkin).",
                evidence={"phy": phy_gen, "card": card_gen},
            )
        )

    # --- xavfsizlik ---
    if security:
        low = security.lower()
        if "wep" in low:
            out.append(
                Finding(
                    severity=SEV_CRITICAL,
                    category=CAT_WIFI,
                    title="Wi-Fi WEP shifrlashda",
                    detail="WEP daqiqalar ichida buziladi — amalda himoya yo'q.",
                    fix="Darhol WPA2 yoki WPA3 ga o'ting.",
                    evidence={"security": security},
                )
            )
        elif "none" in low or "open" in low:
            out.append(
                Finding(
                    severity=SEV_HIGH,
                    category=CAT_WIFI,
                    title="Wi-Fi ochiq (shifrlashsiz)",
                    detail="Trafik ochiq efirda uzatilyapti — istalgan kishi o'qiy oladi.",
                    fix="WPA2/WPA3 parol qo'ying.",
                    evidence={"security": security},
                )
            )

    # --- tor kanal kengligi ---
    if band == "5GHz" and width_mhz is not None and width_mhz <= 20:
        out.append(
            Finding(
                severity=SEV_LOW,
                category=CAT_WIFI,
                title=f"5 GHz da tor kanal ({width_mhz} MHz)",
                detail="5 GHz 80 MHz gacha imkon beradi; 20 MHz tezlikni 4 barobar cheklaydi.",
                fix="Routerda kanal kengligini 80 MHz ga oshiring.",
                evidence={"width_mhz": width_mhz},
            )
        )

    _ = tx_rate  # hozircha faqat ma'lumot uchun; PHY bahosi ustunroq
    return out


def evaluate_link_speed(
    name: str,
    speed_mbps: int,
    is_up: bool,
    is_virtual: bool = False,
) -> list[Finding]:
    """Interfeys link tezligini baholaydi — SOF funksiya.

    Gigabit portda 100 Mbps kelishuv — klassik va ko'rinmas nosozlik: hamma
    narsa ishlaydi, faqat 10 barobar sekin. Sabab odatda kabel (4 o'rniga 2
    juft ulangan), konnektor yoki duplex nomuvofiqligi.

    Virtual interfeyslar (`utun*`, `awdl0`, `llw0`, `bridge*`) chetlab
    o'tiladi — ularda "tezlik" tushunchasi yo'q va soxta ogohlantirish berardi.
    """
    if not is_up or is_virtual or speed_mbps <= 0:
        return []
    if speed_mbps >= 1000:
        return []
    if speed_mbps <= 10:
        sev, note = SEV_HIGH, "10 Mbps — deyarli aniq kabel yoki port nosozligi."
    else:
        sev, note = (
            SEV_MEDIUM,
            (
                "100 Mbps — gigabit port kutilgan joyda bu kabel (4 o'rniga 2 juft), "
                "konnektor yoki duplex nomuvofiqligi belgisidir."
            ),
        )
    return [
        Finding(
            severity=sev,
            category=CAT_INTERFACE,
            title=f"{name}: link {speed_mbps} Mbps da kelishilgan",
            detail=note,
            fix="Kabelni almashtiring (Cat5e+), konnektorni va kommutator portini "
            "tekshiring; port sozlamasi auto-negotiation ekaniga ishonch hosil qiling.",
            host=name,
            evidence={"speed_mbps": speed_mbps},
        )
    ]


# ===========================================================================
# Adaptiv chegaralar — ulanish turiga qarab
# ===========================================================================
#
# Bitta mutlaq raqam har tarmoqda to'g'ri bo'lolmaydi. Gateway'ga 50 ms:
#   kabelli LAN  -> FALOKAT (normal < 2 ms)
#   Wi-Fi        -> normal
#   4G/LTE       -> yaxshi
#   sputnik      -> ajoyib (normal ~600 ms)
# Shuning uchun chegaralar ulanish turidan kelib chiqib tanlanadi.

LINK_WIRED = "wired"
LINK_WIFI = "wifi"
LINK_CELLULAR = "cellular"
LINK_VPN = "vpn"
LINK_UNKNOWN = "unknown"

# Har profil uchun chegaralar. `unknown` — ehtiyotkor o'rtacha (Wi-Fi'ga yaqin),
# chunki noma'lum tarmoqda qattiq chegara soxta ogohlantirish beradi.
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

# Interfeys nomidan turini taxmin qilish uchun prefikslar (platformalararo).
_WIFI_PREFIXES = ("wlan", "wl", "wlp", "ath", "wifi")
_VPN_PREFIXES = ("utun", "tun", "tap", "ppp", "wg", "ipsec", "gpd", "nordlynx")
_CELLULAR_PREFIXES = ("pdp_ip", "rmnet", "wwan", "ccmni", "cdc-wdm")


def classify_link(
    interface_name: str | None,
    wifi_connected: bool = False,
    wifi_interface: str | None = None,
) -> str:
    """Ulanish turini aniqlaydi — SOF funksiya (offline sinaladi).

    Tartib muhim: avval Wi-Fi holati (macOS'da Wi-Fi interfeysi ham `en0`
    deyiladi va nomidan bilib bo'lmaydi), keyin nom prefikslari.
    """
    if not interface_name:
        return LINK_UNKNOWN
    name = interface_name.lower()

    # macOS'da Wi-Fi ham `en0` — nomdan emas, HOLATDAN bilamiz.
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
    """Ulanish turiga mos chegaralarni qaytaradi — SOF funksiya.

    `base` berilsa (foydalanuvchi configi), undagi qiymatlar USTUN turadi:
    avtomatik moslashuv qo'lda qo'yilgan sozlamani bekor qilmasligi kerak.
    """
    profile = _PROFILES.get(link, _PROFILES[LINK_UNKNOWN])
    default = Thresholds()
    result = Thresholds(**profile)  # type: ignore[arg-type]
    if base is None:
        return result
    # Foydalanuvchi default'dan farqli qilib qo'ygan maydonlarni saqlab qolamiz.
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
