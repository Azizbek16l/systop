"""DNS diagnostika — nom resolve qilish + DNS serverlar latency'sini taqqoslash.

Qo'shimcha bog'liqliksiz: stdlib `socket` bilan tizim resolverdan A/AAAA
yozuvlarini olamiz, `subprocess` orqali `dig` (yoki `nslookup`) bilan aniq DNS
serverlarga (8.8.8.8, 1.1.1.1, ...) so'rov yuborib javob vaqtini o'lchaymiz.

`dig` mavjud bo'lmasa, har bir server uchun latency'ni o'lchab bo'lmaydi,
ammo tizim resolveri orqali asosiy resolve baribir ishlaydi.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import socket
import time
from dataclasses import dataclass, field

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


@dataclass(slots=True)
class ResolverResult:
    """Bitta DNS server bo'yicha so'rov natijasi."""

    name: str
    server: str
    ok: bool = False
    rtt_ms: float = 0.0
    addresses: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class DnsResult:
    """Nom uchun to'liq DNS diagnostika natijasi."""

    name: str
    system_addresses: list[str] = field(default_factory=list)
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
        if addr not in seen:
            seen.append(addr)
    return seen, None


def _parse_dig(out: str) -> list[str]:
    return _DIG_ANSWER_RE.findall(out)


def _parse_nslookup(out: str) -> list[str]:
    # Birinchi "Address:" qatori odatda serverning o'zi; qolganlari javob.
    addrs = _NSLOOKUP_ADDR_RE.findall(out)
    return addrs[1:] if len(addrs) > 1 else []


async def _query_resolver(name: str, server: str, tool: str, timeout: float) -> ResolverResult:
    """Aniq DNS serverga so'rov yuborib, javob vaqtini o'lchaydi."""
    label = next((k for k, v in PUBLIC_RESOLVERS.items() if v == server), server)
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
    servers = resolvers or PUBLIC_RESOLVERS
    sys_addrs, sys_err = await _system_resolve(name)

    tool = _pick_tool()
    resolver_results: list[ResolverResult] = []
    if tool is not None:
        tasks = [_query_resolver(name, srv, tool, timeout) for srv in servers.values()]
        resolver_results = list(await asyncio.gather(*tasks))

    return DnsResult(
        name=name,
        system_addresses=sys_addrs,
        system_error=sys_err,
        resolvers=resolver_results,
        tool=tool,
    )
