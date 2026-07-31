"""tls tests — OFFLINE.

``check_http`` is exercised (status/redirect/elapsed) through
``httpx.MockTransport``: the factory that wraps ``httpx.AsyncClient`` with a
transport is monkeypatched — there is NO real network. The blocking
``_fetch_cert`` part of ``check_tls`` is replaced with a mock; the certificate
parsing helpers (``_parse_not_after``/``_flatten_name``) are exercised directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from systop.core import tls
from systop.core.tls import (
    HttpResult,
    TlsResult,
    _flatten_name,
    _parse_not_after,
    check_http,
    check_tls,
)


def _install_mock_transport(monkeypatch, handler) -> None:
    """Wraps the ``httpx.AsyncClient`` used inside ``check_http`` with a mock transport."""
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(tls.httpx, "AsyncClient", factory)


# --- check_http: status / server / elapsed ----------------------------------


async def test_check_http_ok(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"server": "nginx"}, content=b"hello")

    _install_mock_transport(monkeypatch, handler)
    result = await check_http("https://example.test/")
    assert isinstance(result, HttpResult)
    assert result.status == 200
    assert result.server == "nginx"
    assert result.final_url == "https://example.test/"
    assert result.redirects == []
    assert result.error is None
    assert result.elapsed_ms >= 0.0


async def test_check_http_follows_redirects(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/old":
            return httpx.Response(301, headers={"location": "/new"})
        return httpx.Response(200, content=b"ok")

    _install_mock_transport(monkeypatch, handler)
    result = await check_http("https://example.test/old")
    assert result.status == 200
    assert str(result.final_url).endswith("/new")
    # The intermediate URL (the one that redirected) must be in the history.
    assert any(r.endswith("/old") for r in result.redirects)


async def test_check_http_4xx_is_not_error(monkeypatch):
    """4xx/5xx — this is not an HTTP error (the transport worked); the status comes back."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"nope")

    _install_mock_transport(monkeypatch, handler)
    result = await check_http("https://example.test/missing")
    assert result.status == 404
    assert result.error is None


async def test_check_http_connect_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    _install_mock_transport(monkeypatch, handler)
    result = await check_http("https://unreachable.test/")
    assert result.status is None
    assert result.error is not None
    assert "HTTP request error" in result.error
    assert result.elapsed_ms >= 0.0


# --- check_tls: _fetch_cert mock --------------------------------------------


async def test_check_tls_delegates_to_fetch(monkeypatch):
    sentinel = TlsResult(
        host="example.test", port=443, ok=True, days_left=30, tls_version="TLSv1.3"
    )

    def fake_fetch(host, port, timeout):
        assert host == "example.test"
        assert port == 443
        return sentinel

    monkeypatch.setattr(tls, "_fetch_cert", fake_fetch)
    result = await check_tls("example.test")
    assert result is sentinel
    assert result.ok is True
    assert result.days_left == 30
    assert result.tls_version == "TLSv1.3"


async def test_check_tls_error_result(monkeypatch):
    def fake_fetch(host, port, timeout):
        return TlsResult(host=host, port=port, error="TLS connection error: timeout")

    monkeypatch.setattr(tls, "_fetch_cert", fake_fetch)
    result = await check_tls("bad.test", port=8443)
    assert result.ok is False
    assert result.port == 8443
    assert result.error is not None


# --- _parse_not_after: date -> ISO + days -----------------------------------


def test_parse_not_after_future_positive_days():
    future = datetime.now(UTC) + timedelta(days=45)
    raw = future.strftime("%b %d %H:%M:%S %Y GMT")
    iso, days = _parse_not_after(raw)
    assert iso is not None
    assert iso.startswith(str(future.year))
    # The days are ~45 (44 or 45, because of rounding).
    assert days in (44, 45)


def test_parse_not_after_expired_negative_days():
    past = datetime.now(UTC) - timedelta(days=10)
    raw = past.strftime("%b %d %H:%M:%S %Y GMT")
    iso, days = _parse_not_after(raw)
    assert days is not None
    assert days < 0


def test_parse_not_after_malformed_returns_raw_and_none():
    iso, days = _parse_not_after("not-a-real-date")
    assert iso == "not-a-real-date"
    assert days is None


def test_parse_not_after_known_format():
    iso, days = _parse_not_after("Jun  1 12:00:00 2030 GMT")
    assert iso == "2030-06-01T12:00:00+00:00"
    assert days is not None and days > 0


# --- _flatten_name: the issuer/subject structure ----------------------------


def test_flatten_name_builds_kv_string():
    name = (
        (("countryName", "US"),),
        (("organizationName", "Let's Encrypt"),),
        (("commonName", "R3"),),
    )
    assert _flatten_name(name) == "countryName=US, organizationName=Let's Encrypt, commonName=R3"


def test_flatten_name_empty_returns_none():
    assert _flatten_name(()) is None
    assert _flatten_name(None) is None


# --- dataclass defaults -----------------------------------------------------


def test_tls_result_defaults():
    r = TlsResult(host="x.test")
    assert r.port == 443
    assert r.ok is False
    assert r.days_left is None
    assert r.san == []
    assert r.error is None


def test_http_result_defaults():
    r = HttpResult(url="https://x.test/")
    assert r.status is None
    assert r.elapsed_ms == 0.0
    assert r.redirects == []
    assert r.error is None
