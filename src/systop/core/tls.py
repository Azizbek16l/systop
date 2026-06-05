"""TLS sertifikat va HTTP holat tekshiruvi — monitoring/uptime diagnostikasi.

`check_tls` — stdlib `ssl` bilan TLS qo'l siqishuvi qilib, server sertifikatini
oladi: amal muddati (qancha kun qoldi), SAN ro'yxati, issuer/subject, TLS versiya.
Bloklamaslik uchun qo'l siqishuv `asyncio.to_thread` ichida bajariladi.

`check_http` — `httpx` bilan URL'ga so'rov yuboradi: status, redirect zanjiri,
o'tgan vaqt (ms), `Server` header.

Faqat stdlib + httpx; boshqa core modullarni import qilmaydi.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

# X.509 sertifikatdagi vaqt formati (ssl modul shu ko'rinishda qaytaradi):
#   "Jun  1 12:00:00 2026 GMT"
_CERT_TIME_FMT = "%b %d %H:%M:%S %Y %Z"


@dataclass(slots=True)
class TlsResult:
    """TLS sertifikat tekshiruvi natijasi."""

    host: str
    port: int = 443
    ok: bool = False
    days_left: int | None = None
    not_after: str | None = None  # ISO-8601 yoki xom sertifikat satri
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = field(default_factory=list)
    tls_version: str | None = None
    error: str | None = None


@dataclass(slots=True)
class HttpResult:
    """HTTP holat tekshiruvi natijasi."""

    url: str
    status: int | None = None
    final_url: str | None = None
    elapsed_ms: float = 0.0
    server: str | None = None
    redirects: list[str] = field(default_factory=list)
    error: str | None = None


def _flatten_name(name: Any) -> str | None:
    """ssl sertifikatining issuer/subject struktura'sini "K=V, ..." satriga yig'adi.

    Format: (((key, value),), ((key, value),), ...) — RDN'lar to'plami.
    """
    if not name:
        return None
    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def _parse_not_after(raw: str) -> tuple[str | None, int | None]:
    """notAfter satridan ISO sana va bugundan qolgan kunlar sonini hisoblaydi."""
    try:
        dt = datetime.strptime(raw, _CERT_TIME_FMT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return raw, None
    days = (dt - datetime.now(UTC)).days
    return dt.isoformat(), days


def _fetch_cert(host: str, port: int, timeout: float) -> TlsResult:
    """Bloklovchi TLS qo'l siqishuvi — `asyncio.to_thread` ichida chaqiriladi."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert: Any = ssock.getpeercert()
                version = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        return TlsResult(
            host=host,
            port=port,
            error=f"Sertifikat tekshiruvi muvaffaqiyatsiz: {exc.verify_message or exc}",
        )
    except (ssl.SSLError, TimeoutError, OSError) as exc:
        return TlsResult(host=host, port=port, error=f"TLS ulanish xatosi: {exc}")

    if not cert:
        return TlsResult(
            host=host,
            port=port,
            tls_version=version,
            error="Sertifikat ma'lumotini olib bo'lmadi (tekshiruv o'chirilgan bo'lishi mumkin).",
        )

    not_after_iso, days_left = _parse_not_after(cert.get("notAfter", ""))
    san = [value for typ, value in cert.get("subjectAltName", ()) if typ == "DNS"]

    return TlsResult(
        host=host,
        port=port,
        ok=True,
        days_left=days_left,
        not_after=not_after_iso,
        issuer=_flatten_name(cert.get("issuer")),
        subject=_flatten_name(cert.get("subject")),
        san=san,
        tls_version=version,
    )


async def check_tls(host: str, port: int = 443, timeout: float = 5.0) -> TlsResult:
    """Hostning TLS sertifikatini tekshiradi (amal muddati, SAN, issuer, versiya).

    Bloklovchi qo'l siqishuv `asyncio.to_thread` orqali alohida thread'da
    bajariladi — event loop bloklanmaydi. Xato bo'lsa natija `ok=False` va
    `error` to'ldiriladi (istisno ko'tarilmaydi).
    """
    return await asyncio.to_thread(_fetch_cert, host, port, timeout)


async def check_http(url: str, timeout: float = 5.0) -> HttpResult:
    """URL'ga HTTP so'rov yuboradi: status, redirect zanjiri, vaqt, Server header.

    Redirect'lar kuzatiladi; oraliq URL'lar `redirects` ro'yxatida. Xato bo'lsa
    natija `error` bilan qaytadi (istisno ko'tarilmaydi).
    """
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        elapsed = (time.perf_counter() - start) * 1000.0
        return HttpResult(url=url, elapsed_ms=elapsed, error=f"HTTP so'rov xatosi: {exc}")

    elapsed = (time.perf_counter() - start) * 1000.0
    redirects = [str(r.url) for r in resp.history]
    return HttpResult(
        url=url,
        status=resp.status_code,
        final_url=str(resp.url),
        elapsed_ms=elapsed,
        server=resp.headers.get("server"),
        redirects=redirects,
    )
