"""dns testlari — OFFLINE.

``_parse_dig`` / ``_parse_nslookup`` regexlari real-dunyo chiqishlari bilan,
``_pick_tool`` ``shutil.which`` monkeypatch bilan, ``diagnose_dns`` esa
``_system_resolve`` va ``_query_resolver`` mock qilinib sinaladi. Hech qanday
DNS so'rovi yoki subprocess ishlamaydi.
"""

from __future__ import annotations

from systop.core import dns
from systop.core.dns import (
    PUBLIC_RESOLVERS,
    DnsResult,
    ResolverResult,
    _parse_dig,
    _parse_nslookup,
    _pick_tool,
    diagnose_dns,
)

# --- _parse_dig: `dig +nocomments` chiqishi ---------------------------------


def test_parse_dig_a_records():
    out = "example.com.\t\t236\tIN\tA\t93.184.216.34\nexample.com.\t\t236\tIN\tA\t93.184.216.35\n"
    assert _parse_dig(out) == ["93.184.216.34", "93.184.216.35"]


def test_parse_dig_aaaa_records():
    out = "ipv6.example.com.\t300\tIN\tAAAA\t2606:2800:220:1:248:1893:25c8:1946\n"
    assert _parse_dig(out) == ["2606:2800:220:1:248:1893:25c8:1946"]


def test_parse_dig_ignores_cname_and_question():
    out = (
        ";; QUESTION SECTION:\n"
        ";www.example.com.\t\tIN\tA\n"
        "www.example.com.\t300\tIN\tCNAME\texample.com.\n"
        "example.com.\t236\tIN\tA\t93.184.216.34\n"
    )
    # Faqat A/AAAA javoblari olinadi (CNAME e'tiborsiz).
    assert _parse_dig(out) == ["93.184.216.34"]


def test_parse_dig_empty():
    assert _parse_dig("") == []
    assert _parse_dig(";; no answers here\n") == []


# --- _parse_nslookup: birinchi Address: serverning o'zi ---------------------


def test_parse_nslookup_skips_server_address():
    out = (
        "Server:\t\t8.8.8.8\n"
        "Address:\t8.8.8.8#53\n"
        "\n"
        "Non-authoritative answer:\n"
        "Name:\texample.com\n"
        "Address: 93.184.216.34\n"
    )
    # Birinchi "Address:" — server (8.8.8.8), keyingisi — javob.
    assert _parse_nslookup(out) == ["93.184.216.34"]


def test_parse_nslookup_multiple_answers():
    out = (
        "Address:\t1.1.1.1#53\nName:\texample.com\nAddress: 93.184.216.34\nAddress: 93.184.216.35\n"
    )
    assert _parse_nslookup(out) == ["93.184.216.34", "93.184.216.35"]


def test_parse_nslookup_only_server_no_answer():
    # Faqat server manzili bor (javob yo'q) -> bo'sh.
    out = "Server:\t1.1.1.1\nAddress:\t1.1.1.1#53\n"
    assert _parse_nslookup(out) == []


def test_parse_nslookup_empty():
    assert _parse_nslookup("") == []


# --- _pick_tool: dig > nslookup > None --------------------------------------


def test_pick_tool_prefers_dig(monkeypatch):
    monkeypatch.setattr(dns.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert _pick_tool() == "dig"


def test_pick_tool_falls_back_to_nslookup(monkeypatch):
    monkeypatch.setattr(
        dns.shutil, "which", lambda name: "/usr/bin/nslookup" if name == "nslookup" else None
    )
    assert _pick_tool() == "nslookup"


def test_pick_tool_none_when_neither(monkeypatch):
    monkeypatch.setattr(dns.shutil, "which", lambda name: None)
    assert _pick_tool() is None


# --- diagnose_dns: tizim resolve + serverlar (mock) -------------------------


async def test_diagnose_dns_no_tool_only_system(monkeypatch):
    """`dig`/`nslookup` yo'q -> faqat tizim resolve, resolverlar bo'sh."""

    async def fake_system(name):
        return ["93.184.216.34"], None

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: None)

    result = await diagnose_dns("example.com")
    assert isinstance(result, DnsResult)
    assert result.system_addresses == ["93.184.216.34"]
    assert result.system_error is None
    assert result.resolvers == []
    assert result.tool is None


async def test_diagnose_dns_queries_each_resolver(monkeypatch):
    """Tool mavjud bo'lsa, har bir resolver uchun so'rov yuborilsin."""

    async def fake_system(name):
        return ["1.2.3.4"], None

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: "dig")

    seen_servers: list[str] = []

    async def fake_query(name, server, tool, timeout):
        seen_servers.append(server)
        assert tool == "dig"
        return ResolverResult(name=name, server=server, ok=True, rtt_ms=10.0, addresses=["1.2.3.4"])

    monkeypatch.setattr(dns, "_query_resolver", fake_query)

    resolvers = {"A": "10.0.0.1", "B": "10.0.0.2"}
    result = await diagnose_dns("example.com", resolvers=resolvers)
    assert result.tool == "dig"
    assert sorted(seen_servers) == ["10.0.0.1", "10.0.0.2"]
    assert len(result.resolvers) == 2
    assert all(r.ok for r in result.resolvers)


async def test_diagnose_dns_default_resolvers(monkeypatch):
    """resolvers=None -> PUBLIC_RESOLVERS ishlatiladi."""

    async def fake_system(name):
        return [], None

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: "dig")

    queried: list[str] = []

    async def fake_query(name, server, tool, timeout):
        queried.append(server)
        return ResolverResult(name=name, server=server)

    monkeypatch.setattr(dns, "_query_resolver", fake_query)
    await diagnose_dns("example.com")
    assert sorted(queried) == sorted(PUBLIC_RESOLVERS.values())


async def test_diagnose_dns_propagates_system_error(monkeypatch):
    async def fake_system(name):
        return [], "'nx.invalid' nomi resolve bo'lmadi (NXDOMAIN yoki DNS yo'q)."

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: None)

    result = await diagnose_dns("nx.invalid")
    assert result.system_addresses == []
    assert result.system_error is not None
    assert "resolve bo'lmadi" in result.system_error


# --- dataclass defaultlari --------------------------------------------------


def test_resolver_result_defaults():
    r = ResolverResult(name="Google", server="8.8.8.8")
    assert r.ok is False
    assert r.rtt_ms == 0.0
    assert r.addresses == []
    assert r.error is None


def test_dns_result_defaults():
    r = DnsResult(name="example.com")
    assert r.system_addresses == []
    assert r.system_error is None
    assert r.resolvers == []
    assert r.tool is None
