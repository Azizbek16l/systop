"""dns tests — OFFLINE.

The ``_parse_dig`` / ``_parse_nslookup`` regexes are exercised against
real-world output, ``_pick_tool`` with a ``shutil.which`` monkeypatch, and
``diagnose_dns`` with ``_system_resolve`` and ``_query_resolver`` mocked out. No
DNS query and no subprocess ever runs.
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

# --- _parse_dig: `dig +nocomments` output -----------------------------------


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
    # Only the A/AAAA answers are taken (CNAME is ignored).
    assert _parse_dig(out) == ["93.184.216.34"]


def test_parse_dig_empty():
    assert _parse_dig("") == []
    assert _parse_dig(";; no answers here\n") == []


# --- _parse_nslookup: the first Address: is the server itself ---------------


def test_parse_nslookup_skips_server_address():
    out = (
        "Server:\t\t8.8.8.8\n"
        "Address:\t8.8.8.8#53\n"
        "\n"
        "Non-authoritative answer:\n"
        "Name:\texample.com\n"
        "Address: 93.184.216.34\n"
    )
    # The first "Address:" is the server (8.8.8.8), the next one is the answer.
    assert _parse_nslookup(out) == ["93.184.216.34"]


def test_parse_nslookup_multiple_answers():
    out = (
        "Address:\t1.1.1.1#53\nName:\texample.com\nAddress: 93.184.216.34\nAddress: 93.184.216.35\n"
    )
    assert _parse_nslookup(out) == ["93.184.216.34", "93.184.216.35"]


def test_parse_nslookup_only_server_no_answer():
    # Only the server address is present (no answer) -> empty.
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


# --- diagnose_dns: system resolution + servers (mocked) ---------------------


async def test_diagnose_dns_no_tool_only_system(monkeypatch):
    """No `dig`/`nslookup` -> only the system resolution, the resolvers are empty."""

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
    """When a tool is available, a query must be sent to every resolver."""

    async def fake_system(name):
        return ["1.2.3.4"], None

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: "dig")

    seen_servers: list[str] = []

    async def fake_query(name, server, tool, timeout, label=None):
        seen_servers.append(server)
        assert tool == "dig"
        return ResolverResult(name=name, server=server, ok=True, rtt_ms=10.0, addresses=["1.2.3.4"])

    monkeypatch.setattr(dns, "_query_resolver", fake_query)

    # include_system=False — otherwise the test would ask the machine for its
    # real resolvers and would no longer be offline.
    resolvers = {"A": "10.0.0.1", "B": "10.0.0.2"}
    result = await diagnose_dns("example.com", resolvers=resolvers, include_system=False)
    assert result.tool == "dig"
    assert sorted(seen_servers) == ["10.0.0.1", "10.0.0.2"]
    assert len(result.resolvers) == 2
    assert all(r.ok for r in result.resolvers)


async def test_diagnose_dns_default_resolvers(monkeypatch):
    """resolvers=None -> PUBLIC_RESOLVERS is used."""

    async def fake_system(name):
        return [], None

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: "dig")

    queried: list[str] = []

    async def fake_query(name, server, tool, timeout, label=None):
        queried.append(server)
        return ResolverResult(name=name, server=server)

    monkeypatch.setattr(dns, "_query_resolver", fake_query)
    await diagnose_dns("example.com", include_system=False)
    assert sorted(queried) == sorted(PUBLIC_RESOLVERS.values())


async def test_diagnose_dns_propagates_system_error(monkeypatch):
    async def fake_system(name):
        return [], "The name 'nx.invalid' did not resolve (NXDOMAIN, or no DNS)."

    monkeypatch.setattr(dns, "_system_resolve", fake_system)
    monkeypatch.setattr(dns, "_pick_tool", lambda: None)

    result = await diagnose_dns("nx.invalid")
    assert result.system_addresses == []
    assert result.system_error is not None
    assert "did not resolve" in result.system_error


# --- dataclass defaults -----------------------------------------------------


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


# --- _query_resolver: decoding the Windows OEM codepage (cp866) -------------


class _FakeProc:
    """A minimal stand-in for the `asyncio.create_subprocess_exec` result (bytes stdout)."""

    def __init__(self, stdout: bytes) -> None:
        self._stdout = stdout

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""


async def test_query_resolver_decodes_oem_codepage(monkeypatch):
    """RUSSIAN nslookup output is decoded from cp866 bytes and parsed correctly.

    What this asserts: the subprocess stdout is taken as BYTES and decoded with
    `_platform.decode_console` using the OEM codepage (cp866) — not as UTF-8.
    """
    # Simulating Windows + a cp866 console.
    monkeypatch.setattr(dns._platform, "IS_WINDOWS", True)
    monkeypatch.setattr(dns._platform, "_console_output_cp", lambda: 866)

    # The nslookup result: the server plus the answer address (ascii IPs), but
    # with Cyrillic text (cp866) around them — decoding as UTF-8 would produce
    # mojibake.
    ns_out = (
        "Сервер:  dns.google\nAddress:  8.8.8.8\n\nИмя:     example.com\nAddress: 93.184.216.34\n"
    )
    raw = ns_out.encode("cp866")

    captured = {}

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        captured["creationflags"] = kwargs.get("creationflags")
        return _FakeProc(raw)

    monkeypatch.setattr(dns.asyncio, "create_subprocess_exec", fake_exec)

    result = await dns._query_resolver("example.com", "8.8.8.8", "nslookup", timeout=2.0)
    assert result.ok is True
    # The first Address (the server) is dropped, the second one is the answer.
    assert result.addresses == ["93.184.216.34"]
    # CREATE_NO_WINDOW (or 0) must have been passed (no window should flash up).
    assert captured["creationflags"] == dns._platform.subprocess_flags()


# --------------------------------------------------------------------------- #
# AAAA (IPv6) — 0.5.0. `getaddrinfo` hides the AAAA when there is no global
# IPv6, so the real AAAA is fetched via dig/nslookup.
# --------------------------------------------------------------------------- #


def test_dns_result_has_aaaa_field():
    from systop.core.dns import DnsResult

    assert DnsResult(name="x").aaaa_addresses == []


def test_dns_result_stores_aaaa():
    from systop.core.dns import DnsResult

    r = DnsResult(name="x", aaaa_addresses=["2606:4700::1"])
    assert r.aaaa_addresses == ["2606:4700::1"]


def test_dig_regex_matches_aaaa_record():
    """The existing dig regex has to catch AAAA as well."""
    from systop.core.dns import _parse_dig

    out = "cloudflare.com.\t300\tIN\tAAAA\t2606:4700::6810:84e5\n"
    assert _parse_dig(out) == ["2606:4700::6810:84e5"]


def test_dig_regex_matches_both_a_and_aaaa():
    from systop.core.dns import _parse_dig

    out = (
        "example.com.\t300\tIN\tA\t93.184.216.34\n"
        "example.com.\t300\tIN\tAAAA\t2606:2800:220:1:248:1893:25c8:1946\n"
    )
    assert _parse_dig(out) == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]


# --------------------------------------------------------------------------- #
# Detecting the system resolvers — all three operating systems
# (pure parsers, offline)
# --------------------------------------------------------------------------- #

from systop.core.dns import (  # noqa: E402
    parse_ipconfig_all_dns,
    parse_resolv_conf,
    parse_scutil_dns,
)

RESOLV_CONF = """# Generated by NetworkManager
search example.local
nameserver 192.168.1.1
nameserver 8.8.8.8
# nameserver 1.1.1.1  (commented out — must not be counted)
options edns0
"""

SCUTIL_DNS = """DNS configuration

resolver #1
  nameserver[0] : 192.168.10.1
  nameserver[1] : 192.168.10.2
  if_index : 11 (en0)
  flags    : Request A records

resolver #2
  domain   : local
  options  : mdns
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.10.1
  if_index : 11 (en0)
"""

IPCONFIG_ALL = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-ABC

Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Intel(R) Ethernet
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
                                       fe80::1%12
   NetBIOS over Tcpip. . . . . . . . : Enabled
"""


def test_resolv_conf_drops_comments():
    assert parse_resolv_conf(RESOLV_CONF) == ["192.168.1.1", "8.8.8.8"]


def test_resolv_conf_empty_file():
    assert parse_resolv_conf("") == []
    assert parse_resolv_conf("# comment only\nsearch local\n") == []


def test_scutil_dedupes_and_preserves_order():
    """`scutil --dns` prints the list TWICE (the scoped section) — not a duplicate.

    The first resolver is the primary one, so the order matters.
    """
    assert parse_scutil_dns(SCUTIL_DNS) == ["192.168.10.1", "192.168.10.2"]


def test_scutil_takes_no_nameserver_from_mdns_block():
    """The `domain: local` + `options: mdns` block has no nameserver — do not add one."""
    assert "local" not in parse_scutil_dns(SCUTIL_DNS)


def test_ipconfig_takes_unlabelled_continuation_lines():
    """Windows prints the second and third server on UNLABELLED lines.

    A parser that only reads the `DNS Servers` line loses 2 of the 3.
    """
    got = parse_ipconfig_all_dns(IPCONFIG_ALL)
    assert got == ["192.168.1.1", "8.8.8.8", "fe80::1"]


def test_ipconfig_list_ends_at_the_next_label():
    """The `NetBIOS over Tcpip` line must not get swept into the list."""
    got = parse_ipconfig_all_dns(IPCONFIG_ALL)
    assert all(not g.startswith("Enabled") for g in got)
    assert len(got) == 3


def test_parsers_reject_non_ip_values():
    """All three parsers end with the same IP check."""
    assert parse_resolv_conf("nameserver not-an-ip\n") == []
    assert parse_scutil_dns("  nameserver[0] : hostname.local\n") == []


# --------------------------------------------------------------------------- #
# Windows ipconfig — INDEPENDENT OF THE LANGUAGE
# --------------------------------------------------------------------------- #

# This bug was found on a Russian Windows 10 server: `systop doctor` reported a
# false HIGH, "No DNS server is responding", because the `DNS Servers` label was
# never found. In v0.3.2 EXACTLY the same cause made ping show every target as
# "dead" on a RUSSIAN Windows — the same mistake for the second time.

IPCONFIG_RU = """
Настройка протокола IP для Windows

   Основной DNS-суффикс  . . . . . . :
   DNS-суффикс подключения . . . . . : corp.local
   IPv4-адрес. . . . . . . . . . . . : 192.168.10.2(Основной)
   Основной шлюз. . . . . . . . . : 192.168.10.1
   DNS-серверы. . . . . . . . . . . : 192.168.10.1
                                       8.8.8.8
   NetBios через TCP/IP. . . . . . . : Включен
"""

IPCONFIG_DE = """   DNS-Suffixsuchliste . . . . . . . : example.local
   DNS-Server  . . . . . . . . . . . : 192.168.1.1
                                       1.1.1.1
   NetBIOS uber TCP/IP . . . . . . . : Aktiviert
"""


def test_russian_windows_dns_is_found():
    """`DNS-серверы` — a regex looking for the English label never sees this."""
    assert parse_ipconfig_all_dns(IPCONFIG_RU) == ["192.168.10.1", "8.8.8.8"]


def test_german_windows_dns_is_found():
    assert parse_ipconfig_all_dns(IPCONFIG_DE) == ["192.168.1.1", "1.1.1.1"]


def test_dns_suffix_line_does_not_start_the_list():
    """The `DNS-суффикс` label also contains `DNS`, but its value is not an IP.

    If we treated it as the start of the list, the following `Основной шлюз`
    (the gateway) would be collected as DNS — that is, we would present the
    gateway as a resolver.
    """
    got = parse_ipconfig_all_dns(IPCONFIG_RU)
    assert "corp.local" not in got
    # 192.168.10.1 here is BOTH the gateway AND the DNS — but it has to come
    # from the DNS line, not from the gateway line.
    assert got[0] == "192.168.10.1"
    assert len(got) == 2


def test_all_three_languages_behave_identically():
    """The tool's verdict must not change with the Windows LANGUAGE."""
    en = parse_ipconfig_all_dns(IPCONFIG_ALL)
    ru = parse_ipconfig_all_dns(IPCONFIG_RU)
    de = parse_ipconfig_all_dns(IPCONFIG_DE)
    assert all(len(x) >= 2 for x in (en, ru, de))
    assert all(all(_is_ip_like(v) for v in x) for x in (en, ru, de))


def _is_ip_like(v: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(v.split("%")[0])
    except ValueError:
        return False
    return True
