"""Path MTU discovery — "ba'zi saytlar ochilmaydi" muammosining sababi. Root kerak emas.

Nima uchun sysadmin uchun muhim: MTU qora tuynugi (**PMTUD black hole**) eng
chalg'ituvchi tarmoq nosozliklaridan biri —

  * ping ishlaydi (kichik paket), DNS ishlaydi, SSH ham ulanadi;
  * lekin katta javob qaytaradigan saytlar **yarim yuklanib qotadi**;
  * VPN/GRE/PPPoE tunnel ortidagi hostlarda ayniqsa ko'p uchraydi (tunnel
    sarlavhasi 1500 dan 1420-1472 gacha kamaytiradi);
  * sabab: yo'ldagi qurilma katta paketni bo'lishi kerak, lekin DF (Don't
    Fragment) bayrog'i qo'yilgan va u ICMP "fragmentation needed" xabarini
    **bloklaydi** — jo'natuvchi hech qachon MTU ni bilmaydi.

Usul: DF bayrog'i bilan turli o'lchamdagi ping yuborib, **ikkilik qidiruv**
bilan o'tadigan eng katta payload topiladi. Tizim `ping` binari ishlatiladi
(macOS `-D`, Linux `-M do`, Windows `-f`) — root shart emas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Manzil oilasi hostname SATRIDAN taxmin qilinmaydi — u `ports` dagi umumiy
# resolver bilan BIR MARTA aniqlanadi (`resolve_host`). Ilgari `":" in host`
# ishlatilardi: AAAA-only nom (`ipv6.google.com`) IPv4 deb belgilanib, IPv4
# ping'i javobsiz qolardi va tool "host o'lik yoki ICMP bloklangan" degan
# SOXTA xulosa berardi. Ikkinchi resolver YOZILMAYDI — `ports` dagisi
# `::ffff:` (IPv4-mapped) shakllarni rad etadi va `%zona` ni saqlaydi.
from systop.core import _platform
from systop.core.ports import FAMILY_AUTO, FAMILY_V6
from systop.core.ports import _resolve as resolve_host

# IPv4 sarlavha (20) + ICMP sarlavha (8) = 28 bayt, payload'dan tashqari.
IP_ICMP_OVERHEAD = 28
IP6_ICMP_OVERHEAD = 48  # IPv6 sarlavha (40) + ICMPv6 (8)

ETHERNET_MTU = 1500
# Odatiy tunnel MTU'lari — topilgan qiymatni izohlash uchun.
KNOWN_MTU: dict[int, str] = {
    1500: "Ethernet (standart)",
    1492: "PPPoE",
    1480: "GRE tunnel",
    1476: "GRE + PPPoE",
    1472: "IPSec/L2TP (tipik)",
    1450: "VXLAN / ba'zi VPN",
    1420: "WireGuard (tipik)",
    1400: "IPSec (konservativ)",
    1280: "IPv6 minimal MTU",
}

# "fragmentation needed", "message too long", "Packet needs to be fragmented"
_TOO_BIG_RE = re.compile(
    r"too long|frag(?:ment)?|needs to be fragmented|message too big", re.IGNORECASE
)
# Muvaffaqiyatli javob: "64 bytes from ..." / "Reply from ... bytes=..."
_REPLY_RE = re.compile(r"bytes from|bytes=|ttl=", re.IGNORECASE)


@dataclass(slots=True)
class MtuResult:
    """Path MTU o'lchash natijasi."""

    host: str
    path_mtu: int | None = None  # to'liq IP paket o'lchami (payload + overhead)
    max_payload: int | None = None
    probes: int = 0  # yuborilgan ping'lar soni (qayta urinishlar bilan birga)
    family: str = "ipv4"  # RESOLVE natijasidan olinadi, host satridan emas
    address: str | None = None  # aslida ping qilingan IP (zona bilan)
    error: str | None = None

    @property
    def is_reduced(self) -> bool:
        """Standart Ethernet MTU'dan kichikmi (tunnel/VPN belgisi)."""
        return self.path_mtu is not None and self.path_mtu < ETHERNET_MTU

    @property
    def likely_cause(self) -> str | None:
        """Topilgan MTU odatiy tunnel qiymatiga mos kelsa — nomi."""
        if self.path_mtu is None:
            return None
        exact = KNOWN_MTU.get(self.path_mtu)
        if exact:
            return exact
        # Eng yaqin tanilgan qiymat (±8 bayt oynada).
        for mtu, name in KNOWN_MTU.items():
            if abs(mtu - self.path_mtu) <= 8:
                return f"{name} ga yaqin"
        return None


def classify_ping_output(text: str, returncode_ok: bool = True) -> str:
    """Ping chiqishini `ok` | `too_big` | `no_reply` ga ajratadi — SOF funksiya.

    Uch holatni farqlash muhim: "juda katta" (MTU dan oshdi) va "javob yo'q"
    (host o'lik / ICMP bloklangan) butunlay boshqa xulosaga olib keladi. Ularni
    aralashtirsak, ICMP bloklangan hostda MTU 0 deb ko'rsatardik.
    """
    if _TOO_BIG_RE.search(text):
        return "too_big"
    if _REPLY_RE.search(text) and returncode_ok:
        return "ok"
    return "no_reply"


def _build_cmd(host: str, payload: int, is_v6: bool, timeout: float) -> list[str]:
    """Platformaga mos DF-bayrog'li ping buyrug'i."""
    if _platform.IS_WINDOWS:
        # -f = DF, -l = payload, -w = ms
        return ["ping", "-n", "1", "-f", "-l", str(payload), "-w", str(int(timeout * 1000)), host]
    wait = str(max(1, int(timeout)))
    if is_v6:
        # macOS ping6/Linux ping -6: DF IPv6'da doimiy (fragmentatsiya yo'q).
        return ["ping6", "-c", "1", "-s", str(payload), "-i", "1", host]
    if _platform.IS_MACOS:
        # macOS: -D = DF bayrog'i
        return ["ping", "-c", "1", "-D", "-s", str(payload), "-W", str(int(timeout * 1000)), host]
    # Linux (iputils): -M do = DF
    return ["ping", "-c", "1", "-M", "do", "-s", str(payload), "-W", wait, host]


async def _probe(host: str, payload: int, is_v6: bool, timeout: float) -> str:
    """Bitta o'lcham bilan probe — `ok`/`too_big`/`no_reply`.

    `host` — RESOLVE qilingan IP (zona bilan), nom emas: har probe'da qayta
    DNS so'rovi ketmasin va oila o'zgarib qolmasin.
    """
    cmd = _build_cmd(host, payload, is_v6, timeout)
    # stderr SHART: macOS `ping` "Message too long" ni aynan shu yerga yozadi.
    out = await _platform.run_command(cmd, timeout=timeout + 3.0, include_stderr=True)
    if not out:
        # `run_command` xatoda bo'sh satr qaytaradi (istisno ko'tarmaydi).
        return "no_reply"
    return classify_ping_output(out)


async def _resolve_failure_reason(host: str, family: str) -> str:
    """Resolve nega yiqilganini ROSTGO'YLIK bilan tushuntiradi.

    Nima uchun alohida funksiya: "DNS yozuvi yo'q" deyish eng ko'p uchraydigan
    holatda **noto'g'ri** va sysadminni butunlay boshqa tomonga yuboradi.

    `ipv6.google.com` da AAAA yozuvi DNS'da BOR, lekin hostda global IPv6
    manzil bo'lmasa OS uni `getaddrinfo` dan butunlay olib tashlaydi (RFC 6724
    manzil tanlash). Natijada "nom resolve bo'lmadi" chiqadi va odam DNS'ni
    tuzatgani ketadi — muammo esa IPv6 ulanishida.

    Shuning uchun yiqilganda `dig` bilan AAAA alohida so'raladi va javob
    ikkalasini ajratadi.
    """
    want = "" if family == FAMILY_AUTO else f" ({family})"
    base = f"'{host}' nomini IP ga aylantirib bo'lmadi{want}"

    from systop.core import netinfo
    from systop.core.dns import _pick_tool, _query_aaaa

    tool = _pick_tool()
    if not tool:
        return f"{base} — DNS yozuvi yo'q."
    try:
        aaaa = await _query_aaaa(host, tool, timeout=3.0)
    except Exception:  # noqa: BLE001 — tushuntirish uchun, asosiy natija emas
        aaaa = []
    if not aaaa:
        return f"{base} — DNS yozuvi yo'q."

    try:
        has_global6 = any(i.ipv6_global for i in netinfo.list_interfaces())
    except Exception:  # noqa: BLE001
        has_global6 = False
    if has_global6:
        return f"{base}, garchi DNS'da AAAA yozuvi bor bo'lsa ham ({aaaa[0]})."
    return (
        f"{base}. DNS ayb EMAS: AAAA yozuvi bor ({aaaa[0]}), lekin bu hostda "
        "global IPv6 manzil yo'q, shuning uchun OS AAAA'ni butunlay yashiradi "
        "(RFC 6724). IPv6 ulanishini yoqing yoki IPv4 nishon bering."
    )


async def discover_path_mtu(
    host: str,
    low: int = 1200,
    high: int = 1500,
    timeout: float = 2.0,
    family: str = FAMILY_AUTO,
    retries: int = 1,
) -> MtuResult:
    """DF-ping bilan ikkilik qidiruv orqali path MTU ni topadi.

    `low`/`high` — to'liq IP paket o'lchami chegaralari (payload emas). Default
    oyna 1200-1500: bundan pastda IPv6 minimal MTU (1280) va tunnel qiymatlari,
    yuqorisi esa standart Ethernet.

    Avval `high` sinaladi — o'tsa qidiruv shart emas (eng ko'p uchraydigan
    holat, bir probe'da tugaydi). `low` ham o'tmasa host ICMP'ni bloklayotgan
    bo'lishi mumkin — bunda `error` qaytadi, 0 emas (aks holda soxta "MTU juda
    kichik" xulosasi chiqardi).

    `family` — `auto` (OS tanlovi) yoki majburan `ipv4`/`ipv6`. Oila **resolve
    natijasidan** olinadi: sarlavha qo'shimchasi (28 yoki 48 bayt), ping
    buyrug'i va `res.family` shundan kelib chiqadi.

    `retries` — FAQAT `no_reply` javobsiz qolgan probe qayta yuboriladi.
    `too_big` qayta sinalmaydi: u yo'ldagi qurilmaning aniq javobi (ICMP
    "fragmentation needed"), takrorlash natijani o'zgartirmaydi. Bitta yo'qolgan
    echo esa MTU ni 143 baytgacha past ko'rsatib, `doctor` xulosasini
    medium'dan high'ga sakratardi.
    """
    res = MtuResult(host=host)
    # NB: `_resolve_failure_reason` quyida — u tarmoqqa chiqadi, shuning uchun
    # faqat resolve yiqilganda chaqiriladi.

    # 1) BIR MARTA resolve — oila shu yerdan aniqlanadi.
    resolved, resolved_family = await resolve_host(host, family)
    if resolved is None or resolved_family is None:
        res.error = await _resolve_failure_reason(host, family)
        return res
    # Ichki closure'lar uchun alohida `str` nom (None tekshiruvi allaqachon o'tdi).
    address: str = resolved
    is_v6 = resolved_family == FAMILY_V6
    overhead = IP6_ICMP_OVERHEAD if is_v6 else IP_ICMP_OVERHEAD
    res.family = resolved_family
    res.address = address

    lo_payload = max(low - overhead, 0)
    hi_payload = max(high - overhead, lo_payload)

    seen: dict[int, str] = {}  # payload -> oxirgi hukm (takroriy probe'ni tejaydi)

    async def probe(payload: int) -> str:
        """Probe + faqat `no_reply` uchun qayta urinish; `probes` ni sanaydi."""
        verdict = await _probe(address, payload, is_v6, timeout)
        res.probes += 1
        attempt = 0
        while verdict == "no_reply" and attempt < max(retries, 0):
            attempt += 1
            verdict = await _probe(address, payload, is_v6, timeout)
            res.probes += 1
        seen[payload] = verdict
        return verdict

    async def search(lo: int, hi: int) -> int | None:
        """Ikkilik qidiruv: [lo, hi] oynasidagi eng katta o'tadigan payload."""
        best: int | None = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if await probe(mid) == "ok":
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    # 2) Eng katta o'lcham o'tadimi?
    top = await probe(hi_payload)
    if top == "ok":
        res.max_payload = hi_payload
        res.path_mtu = hi_payload + overhead
        return res
    if top == "no_reply":
        # Kichik paket bilan tekshiramiz: host tirikmi? (o'sha resolve qilingan
        # manzilga — nomga emas, aks holda oila almashib ketishi mumkin edi.)
        if await probe(56) != "ok":
            res.error = (
                f"'{host}' ping'ga javob bermayapti — MTU o'lchab bo'lmadi "
                "(host o'lik yoki ICMP bloklangan)."
            )
            return res
        # Host tirik, lekin katta paket javobsiz => qora tuynuk (ICMP xabari yo'q).
        # Ikkilik qidiruvni davom ettiramiz: "no_reply" ni "juda katta" deb olamiz.

    # 3) Ikkilik qidiruv: eng katta o'tadigan payload.
    best = await search(lo_payload, hi_payload)

    # 4) Chegarani TASDIQLASH. `best` ni qayta sinash ma'nosiz — u ta'rifiga
    # ko'ra allaqachon javob bergan o'lcham. Chegarani `best + 1` isbotlaydi:
    # agar u ham o'tsa, demak qidiruv yo'qolgan paket tufayli past tushgan va
    # yuqoridagi oynani qayta ko'rib chiqamiz.
    # `too_big` bo'lgan o'lcham QAYTA sinalmaydi — u yo'ldagi qurilmaning aniq
    # javobi, ikkinchi probe faqat vaqt yeydi.
    if best is not None and best < hi_payload and seen.get(best + 1) != "too_big":
        if await probe(best + 1) == "ok":
            best += 1
            higher = await search(best + 1, hi_payload)
            if higher is not None:
                best = higher

    if best is None:
        res.error = (
            f"'{host}': {low} baytli paket ham o'tmadi — MTU {low} dan kichik "
            "yoki yo'lda ICMP butunlay bloklangan."
        )
        return res
    res.max_payload = best
    res.path_mtu = best + overhead
    return res
