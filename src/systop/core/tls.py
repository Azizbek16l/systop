"""TLS certificate and HTTP status checks — monitoring/uptime diagnostics.

`check_tls` — performs a TLS handshake with the stdlib `ssl` and takes the
server certificate: the validity period (how many days are left), the SAN list,
the issuer/subject, the TLS version. To avoid blocking, the handshake runs
inside `asyncio.to_thread`.

`check_http` — sends a request to a URL with `httpx`: the status, the redirect
chain, the elapsed time (ms), the `Server` header.

Only stdlib + httpx; it imports no other core module.
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

# The time format in an X.509 certificate (the ssl module returns it like this):
#   "Jun  1 12:00:00 2026 GMT"
_CERT_TIME_FMT = "%b %d %H:%M:%S %Y %Z"


@dataclass(slots=True)
class TlsResult:
    """The result of a TLS certificate check."""

    host: str
    port: int = 443
    ok: bool = False
    days_left: int | None = None
    not_after: str | None = None  # ISO-8601, or the raw certificate string
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = field(default_factory=list)
    tls_version: str | None = None
    error: str | None = None


@dataclass(slots=True)
class HttpResult:
    """The result of an HTTP status check."""

    url: str
    status: int | None = None
    final_url: str | None = None
    elapsed_ms: float = 0.0
    server: str | None = None
    redirects: list[str] = field(default_factory=list)
    error: str | None = None


def _flatten_name(name: Any) -> str | None:
    """Collapses the issuer/subject structure of an ssl certificate into a "K=V, ..." string.

    The format: (((key, value),), ((key, value),), ...) — a collection of RDNs.
    """
    if not name:
        return None
    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


def _parse_not_after(raw: str) -> tuple[str | None, int | None]:
    """Computes the ISO date and the number of days left from today out of the notAfter string."""
    try:
        dt = datetime.strptime(raw, _CERT_TIME_FMT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return raw, None
    days = (dt - datetime.now(UTC)).days
    return dt.isoformat(), days


def _fetch_cert(host: str, port: int, timeout: float) -> TlsResult:
    """The blocking TLS handshake — called from inside `asyncio.to_thread`."""
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
            error=f"Certificate verification failed: {exc.verify_message or exc}",
        )
    except (ssl.SSLError, TimeoutError, OSError) as exc:
        return TlsResult(host=host, port=port, error=f"TLS connection error: {exc}")

    if not cert:
        return TlsResult(
            host=host,
            port=port,
            tls_version=version,
            error="Could not obtain the certificate details (verification may be disabled).",
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
    """Checks the host's TLS certificate (validity period, SAN, issuer, version).

    The blocking handshake runs in a separate thread through
    `asyncio.to_thread` — the event loop is never blocked. On an error the
    result comes back with `ok=False` and `error` filled in (no exception is
    raised).
    """
    return await asyncio.to_thread(_fetch_cert, host, port, timeout)


async def check_http(url: str, timeout: float = 5.0) -> HttpResult:
    """Sends an HTTP request to a URL: status, redirect chain, time, Server header.

    Redirects are followed; the intermediate URLs land in the `redirects` list.
    On an error the result comes back with `error` set (no exception is raised).
    """
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        elapsed = (time.perf_counter() - start) * 1000.0
        return HttpResult(url=url, elapsed_ms=elapsed, error=f"HTTP request error: {exc}")

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
