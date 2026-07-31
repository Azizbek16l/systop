"""DNS diagnostika — nom resolve qilish + DNS serverlar latency'sini taqqoslash.

Qo'shimcha bog'liqliksiz: stdlib `socket` bilan tizim resolverdan A/AAAA
yozuvlarini olamiz, `subprocess` orqali `dig` (yoki `nslookup`) bilan aniq DNS
serverlarga (8.8.8.8, 1.1.1.1, ...) so'rov yuborib javob vaqtini o'lchaymiz.

`dig` mavjud bo'lmasa, har bir server uchun latency'ni o'lchab bo'lmaydi,
ammo tizim resolveri orqali asosiy resolve baribir ishlaydi.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

from systop.core import _platform

# Taqqoslanadigan ommaviy DNS serverlar.
PUBLIC_RESOLVERS: dict[str, str] = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

_DIG_ANSWER_RE = re.compile(r"^\S+\s+\d+\s+IN\s+(?:A|AAAA)\s+(\S+)", re.MULTILINE)
_NSLOOKUP_ADDR_RE = re.compile(r"^Address:\s*([0-9a-fA-F.:]+)", re.MULTILINE)

# macOS `scutil --dns`: "  nameserver[0] : 192.168.10.1"
_SCUTIL_NS_RE = re.compile(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", re.MULTILINE)
# Windows `ipconfig /all` — yorliq TILGA BOG'LIQ:
#   inglizcha: "   DNS Servers . . . . . . . . . . . : 192.168.1.1"
#   ruscha:    "   DNS-серверы. . . . . . . . . . . : 192.168.1.1"
#   nemischa:  "   DNS-Server  . . . . . . . . . . . : 192.168.1.1"
#
# Shuning uchun "DNS Servers" ni QIDIRMAYMIZ. Yorliqda `DNS` bo'lsa kifoya,
# qolganini QIYMAT SHAKLI hal qiladi (IP bo'lsa oladi). `DNS-суффикс` /
# `DNS Suffix` qatorlari tabiiy ravishda tushib qoladi — ularning qiymati
# IP emas.
_IPCONFIG_DNS_RE = re.compile(r"^\s*[^:]*DNS[^:]*:\s*(\S*)\s*$", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Tizim resolverlarini aniqlash — SOF parserlar + yupqa async qobiq
# --------------------------------------------------------------------------- #
#
# Nima uchun kerak: `doctor` ilgari faqat OMMAVIY serverlarni (8.8.8.8,
# 1.1.1.1...) sinardi. Korporativ tarmoqda tashqi 53-port ko'pincha ataylab
# yopiq bo'ladi — natijada sog'lom tarmoqda "Barcha DNS serverlar javob
# bermayapti / Firewall UDP/53 ni tekshiring" degan YOLG'ON xulosa va exit 2
# chiqardi. Aslida mashina o'zining ichki resolveridan bemalol foydalanadi.
#
# Endi avval mashina HAQIQATDA ishlatayotgan resolver so'raladi; ommaviylar
# faqat TAQQOSLASH guruhi bo'lib qoladi.


def _is_ip(value: str) -> bool:
    """Satr IP manzilmi (zona qo'shimchasi bilan ham) — SOF funksiya."""
    try:
        ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return False
    return True


def _dedupe_ips(values: list[str]) -> list[str]:
    """Takrorlarni olib tashlaydi, tartibni saqlaydi, IP bo'lmaganini tashlaydi."""
    out: list[str] = []
    for v in values:
        bare = v.strip().strip(",").split("%")[0]
        if not bare:
            continue
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            continue
        if bare not in out:
            out.append(bare)
    return out


def parse_resolv_conf(text: str) -> list[str]:
    """`/etc/resolv.conf` dan `nameserver` qatorlarini oladi — SOF funksiya.

    Linux uchun asosiy manba. **macOS'da bu fayl aldamchi** — u yerda
    "This file is not consulted for DNS hostname resolution" deb yozilgan
    va odatda `127.0.0.1` yoki umuman hech nima turadi. Shuning uchun
    macOS'da `parse_scutil_dns` ustun keladi.

    `systemd-resolved` ishlatilgan Linux'da bu yerda `127.0.0.53` turadi —
    bu ham to'g'ri javob: mashina haqiqatda o'sha stub'ga murojaat qiladi.
    """
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0].lower() == "nameserver":
            out.append(parts[1])
    return _dedupe_ips(out)


def parse_scutil_dns(text: str) -> list[str]:
    """macOS `scutil --dns` dan nameserver'larni oladi — SOF funksiya.

    Chiqishda `resolver #1`, `resolver #2`... bloklari bo'ladi; bizni faqat
    `nameserver[N] : IP` qatorlari qiziqtiradi. mDNS (`domain: local`) va
    teskari-qidiruv bloklarida nameserver bo'lmaydi, shuning uchun ular
    tabiiy ravishda tushib qoladi.

    Chiqish ikki marta takrorlanadi ("DNS configuration" va "(for scoped
    queries)") — takrorlar olib tashlanadi, tartib saqlanadi: birinchi
    resolver — asosiysi.
    """
    return _dedupe_ips(_SCUTIL_NS_RE.findall(text))


def parse_ipconfig_all_dns(text: str) -> list[str]:
    """Windows `ipconfig /all` dan DNS serverlarni oladi — SOF funksiya.

    Format tuzoqli: ikkinchi va keyingi serverlar **yorliqsiz**, faqat
    bo'shliq bilan surilgan davomiy qatorlarda keladi ::

        DNS Servers . . . . . . . . . . . : 192.168.1.1
                                            8.8.8.8
                                            fe80::1%12

    Shuning uchun "davomiy qator" ni yorliq yo'qligi bo'yicha emas, satrning
    o'zi IP manzil ekanligi bo'yicha aniqlaymiz — IPv6 tarkibida ikki nuqta
    borligi yorliq qidirishni ishonchsiz qiladi.
    """
    out: list[str] = []
    in_dns = False
    for line in text.splitlines():
        m = _IPCONFIG_DNS_RE.match(line)
        if m:
            # Yorliqda `DNS` bor — lekin bu `DNS-суффикс` ham bo'lishi mumkin.
            # Faqat qiymati IP bo'lgan qatorni ro'yxat boshi deb olamiz;
            # aks holda `DNS Suffix` qatoridan keyingi har qanday IP
            # (masalan `Default Gateway`) noto'g'ri yig'ilib ketardi.
            if _is_ip(m.group(1)):
                in_dns = True
                out.append(m.group(1))
            else:
                in_dns = False
            continue
        if not in_dns:
            continue
        stripped = line.strip()
        if not _is_ip(stripped):
            in_dns = False  # yorliqli yangi qator — ro'yxat tugadi
            continue
        out.append(stripped)
    return _dedupe_ips(out)


def _read_resolv_conf() -> str:
    """`/etc/resolv.conf` ni o'qiydi; yo'q/ruxsatsiz bo'lsa bo'sh satr."""
    try:
        return Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


async def system_resolvers() -> list[str]:
    """Mashina HAQIQATDA ishlatayotgan DNS serverlarni qaytaradi.

    Har OS uchun eng ishonchli manba:

    * **macOS** — `scutil --dns` (yagona to'g'ri manba; resolv.conf aldaydi)
    * **Windows** — `ipconfig /all`
    * **Linux** — `/etc/resolv.conf`, u bo'sh bo'lsa `resolvectl status`

    Hech narsa topilmasa bo'sh ro'yxat — istisno ko'tarilmaydi (config.py
    bilan bir xil "jim default" qoidasi).

    `dhcp.py` dan OLINMAYDI: DHCP e'lon qilgan server bilan tizim sozlangani
    boshqa narsa (foydalanuvchi qo'lda o'zgartirgan bo'lishi mumkin), ustiga
    Windows yo'li `dns` ro'yxatini umuman qaytarmaydi.
    """
    if _platform.IS_MACOS:
        out = await _platform.run_command(["scutil", "--dns"], timeout=5.0)
        return parse_scutil_dns(out) if out else []

    if _platform.IS_WINDOWS:
        # Avval PowerShell: `Get-DnsClientServerAddress` STRUKTURALI javob
        # beradi va tilga umuman bog'liq emas. `ipconfig` yorlig'i esa
        # lokalizatsiya qilinadi (`DNS-серверы`, `DNS-Server`) — v0.3.2 da
        # ping'da xuddi shu sabab RUS Windows'da hamma nishon "o'lik"
        # ko'rinardi. Bir xil xatoni ikkinchi marta qilmaymiz.
        out = await _platform.run_command(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4,IPv6"
                " -ErrorAction SilentlyContinue).ServerAddresses",
            ],
            timeout=15.0,
        )
        found = _dedupe_ips(out.splitlines()) if out else []
        if found:
            return found
        # PowerShell yo'q/cheklangan bo'lsa — matn yo'li (tildan mustaqil parse).
        out = await _platform.run_command(["ipconfig", "/all"], timeout=8.0)
        return parse_ipconfig_all_dns(out) if out else []

    # Fayl o'qish alohida oqimda: event loop'ni bloklamaslik uchun (NFS/autofs
    # ustidagi /etc sekin javob berishi mumkin).
    found = parse_resolv_conf(await asyncio.to_thread(_read_resolv_conf))
    if found:
        return found
    out = await _platform.run_command(["resolvectl", "status"], timeout=5.0)
    if not out:
        return []
    # `resolvectl status`: "  DNS Servers: 192.168.1.1 8.8.8.8"
    servers: list[str] = []
    for line in out.splitlines():
        label, sep, rest = line.partition(":")
        if sep and "dns server" in label.strip().lower():
            servers.extend(rest.split())
    return _dedupe_ips(servers)


@dataclass(slots=True)
class ResolverResult:
    """Bitta DNS server bo'yicha so'rov natijasi."""

    name: str
    server: str
    ok: bool = False
    rtt_ms: float = 0.0
    addresses: list[str] = field(default_factory=list)
    error: str | None = None
    is_system: bool = False
    """Bu server mashinaning O'ZI ishlatayotgan resolvermi.

    Baholashda hal qiluvchi farq: ommaviy serverga yetib bo'lmasligi ko'p
    tarmoqda **ataylab** (tashqi 53-port yopiq), tizim resolveriga yetib
    bo'lmasligi esa har doim haqiqiy nosozlik.
    """


@dataclass(slots=True)
class DnsResult:
    """Nom uchun to'liq DNS diagnostika natijasi."""

    name: str
    system_addresses: list[str] = field(default_factory=list)
    aaaa_addresses: list[str] = field(default_factory=list)
    system_error: str | None = None
    resolvers: list[ResolverResult] = field(default_factory=list)
    tool: str | None = None  # ishlatilgan tashqi vosita: "dig" | "nslookup" | None


async def _system_resolve(name: str) -> tuple[list[str], str | None]:
    """Tizim resolveri orqali A/AAAA manzillarni oladi (xato o'zbekcha)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return [], f"'{name}' nomi resolve bo'lmadi (NXDOMAIN yoki DNS yo'q)."
    except OSError as exc:
        return [], f"Resolve xatosi: {exc}"
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        # `::ffff:1.2.3.4` — IPv4-mapped IPv6. Bu HAQIQIY AAAA yozuvi EMAS:
        # tarmoqda global IPv6 bo'lmasa macOS AAAA'ni filtrlab, o'rniga shu
        # shaklni beradi. Diagnostikada uni IPv6 deb ko'rsatish chalg'ituvchi,
        # shuning uchun tashlanadi — haqiqiy AAAA `aaaa_addresses`da (dig orqali).
        if addr.startswith("::ffff:"):
            continue
        if addr not in seen:
            seen.append(addr)
    return seen, None


async def _query_aaaa(name: str, tool: str | None, timeout: float = 3.0) -> list[str]:
    """Haqiqiy AAAA yozuvlarini DNS'dan bevosita oladi (dig/nslookup orqali).

    Nima uchun `getaddrinfo` emas: OS'da global IPv6 marshruti bo'lmasa
    `getaddrinfo` AAAA'ni butunlay yashiradi (RFC 6724 manzil tanlash). Ammo
    diagnostika tooli DNS **nima deyotganini** ko'rsatishi kerak, OS nimani
    ishlatishga qaror qilganini emas.

    Tool topilmasa yoki xato bo'lsa bo'sh ro'yxat (istisno yo'q).
    """
    if not tool:
        return []
    if tool == "dig":
        cmd = ["dig", "+short", "AAAA", name]
    else:
        cmd = ["nslookup", "-type=AAAA", name]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=_platform.subprocess_flags(),
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
    except (TimeoutError, OSError, ValueError):
        return []
    out = _platform.decode_console(stdout)
    found: list[str] = []
    for line in out.splitlines():
        token = line.strip().split()[-1] if line.strip() else ""
        if ":" in token and not token.startswith("::ffff:"):
            try:
                ipaddress.IPv6Address(token)
            except ValueError:
                continue
            if token not in found:
                found.append(token)
    return found


def _parse_dig(out: str) -> list[str]:
    return _DIG_ANSWER_RE.findall(out)


def _parse_nslookup(out: str) -> list[str]:
    # Birinchi "Address:" qatori odatda serverning o'zi; qolganlari javob.
    addrs = _NSLOOKUP_ADDR_RE.findall(out)
    return addrs[1:] if len(addrs) > 1 else []


async def _query_resolver(
    name: str, server: str, tool: str, timeout: float, label: str | None = None
) -> ResolverResult:
    """Aniq DNS serverga so'rov yuborib, javob vaqtini o'lchaydi."""
    label = label or next((k for k, v in PUBLIC_RESOLVERS.items() if v == server), server)
    if tool == "dig":
        cmd = [
            "dig",
            f"@{server}",
            name,
            "+tries=1",
            f"+time={int(max(timeout, 1))}",
            "+nocomments",
        ]
    else:  # nslookup
        cmd = ["nslookup", name, server]

    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=_platform.subprocess_flags(),
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
    except TimeoutError:
        return ResolverResult(name=label, server=server, error="vaqt tugadi (timeout)")
    except (OSError, ValueError) as exc:
        return ResolverResult(name=label, server=server, error=str(exc))

    rtt = (time.perf_counter() - start) * 1000.0
    # Windows nslookup OEM codepage'da yozadi (RUS = cp866) -> decode_console.
    out = _platform.decode_console(stdout)
    addrs = _parse_dig(out) if tool == "dig" else _parse_nslookup(out)
    if not addrs:
        return ResolverResult(
            name=label, server=server, rtt_ms=rtt, error="javob bo'sh (yozuv topilmadi)"
        )
    return ResolverResult(name=label, server=server, ok=True, rtt_ms=rtt, addresses=addrs)


def _pick_tool() -> str | None:
    """Mavjud DNS so'rov vositasini tanlaydi: dig > nslookup > yo'q."""
    if shutil.which("dig"):
        return "dig"
    if shutil.which("nslookup"):
        return "nslookup"
    return None


async def diagnose_dns(
    name: str,
    resolvers: dict[str, str] | None = None,
    timeout: float = 3.0,
    include_system: bool = True,
) -> DnsResult:
    """Nomni tizim resolveri bilan resolve qiladi va DNS serverlarni taqqoslaydi.

    Argumentlar:
        name — resolve qilinadigan domen nomi.
        resolvers — {nom: server_ip} ko'rinishidagi taqqoslanadigan DNS serverlar
            lug'ati. None bo'lsa standart :data:`PUBLIC_RESOLVERS` ishlatiladi.
            Foydalanuvchi o'z serverlarini berishi mumkin (masalan config fayldan
            yoki korporativ ichki resolverlar) — funksiya tayyor lug'atni qabul
            qiladi; faylni o'qish Layer 2 (CLI/TUI) zimmasida.
        timeout — har bir server so'rovi uchun maksimal kutish (soniya).

    Agar `dig`/`nslookup` topilmasa, faqat tizim resolve qaytariladi
    (`resolvers` ro'yxati bo'sh bo'ladi, `tool` esa None).
    """
    servers = dict(resolvers) if resolvers else dict(PUBLIC_RESOLVERS)
    sys_addrs, sys_err = await _system_resolve(name)

    # Tizim resolverlarini ro'yxat BOSHIGA qo'shamiz. Ular bo'lmasa `doctor`
    # faqat ommaviy serverlarni ko'radi va tashqi 53-porti yopiq (mutlaqo
    # normal) korporativ tarmoqni "DNS butunlay o'lik" deb e'lon qiladi.
    system_ips: set[str] = set()
    if include_system:
        try:
            found = await system_resolvers()
        except Exception:  # noqa: BLE001 — aniqlash yiqilsa ommaviylar bilan davom
            found = []
        already = set(servers.values())
        ordered: dict[str, str] = {}
        for ip in found:
            system_ips.add(ip)
            if ip in already:
                continue  # foydalanuvchi ro'yxatida allaqachon bor — ikki marta so'ramaymiz
            ordered[f"Tizim ({ip})"] = ip
        servers = {**ordered, **servers}

    tool = _pick_tool()
    resolver_results: list[ResolverResult] = []
    aaaa: list[str] = []
    if tool is not None:
        tasks = [
            _query_resolver(name, srv, tool, timeout, label=lbl) for lbl, srv in servers.items()
        ]
        # AAAA so'rovi resolverlar bilan parallel ketadi — qo'shimcha vaqt olmaydi.
        resolver_results_and_aaaa = await asyncio.gather(
            asyncio.gather(*tasks), _query_aaaa(name, tool, timeout)
        )
        resolver_results = list(resolver_results_and_aaaa[0])
        aaaa = resolver_results_and_aaaa[1]
        for r in resolver_results:
            r.is_system = r.server in system_ips

    return DnsResult(
        name=name,
        system_addresses=sys_addrs,
        aaaa_addresses=aaaa,
        system_error=sys_err,
        resolvers=resolver_results,
        tool=tool,
    )
