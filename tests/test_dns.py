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

    async def fake_query(name, server, tool, timeout, label=None):
        seen_servers.append(server)
        assert tool == "dig"
        return ResolverResult(name=name, server=server, ok=True, rtt_ms=10.0, addresses=["1.2.3.4"])

    monkeypatch.setattr(dns, "_query_resolver", fake_query)

    # include_system=False — aks holda test mashinaning haqiqiy resolverini
    # so'rab, offline bo'lmay qoladi.
    resolvers = {"A": "10.0.0.1", "B": "10.0.0.2"}
    result = await diagnose_dns("example.com", resolvers=resolvers, include_system=False)
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

    async def fake_query(name, server, tool, timeout, label=None):
        queried.append(server)
        return ResolverResult(name=name, server=server)

    monkeypatch.setattr(dns, "_query_resolver", fake_query)
    await diagnose_dns("example.com", include_system=False)
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


# --- _query_resolver: Windows OEM codepage (cp866) dekodlash ----------------


class _FakeProc:
    """`asyncio.create_subprocess_exec` natijasining minimal o'rni (bytes stdout)."""

    def __init__(self, stdout: bytes) -> None:
        self._stdout = stdout

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""


async def test_query_resolver_decodes_oem_codepage(monkeypatch):
    """RUS nslookup chiqishi cp866 baytlardan to'g'ri dekodlanib parse qilinadi.

    Tasdiqlash: subprocess stdout BAYT sifatida olinadi va `_platform.
    decode_console` orqali OEM codepage (cp866) bilan dekodlanadi — UTF-8 emas.
    """
    # Windows + cp866 konsol simulyatsiyasi.
    monkeypatch.setattr(dns._platform, "IS_WINDOWS", True)
    monkeypatch.setattr(dns._platform, "_console_output_cp", lambda: 866)

    # nslookup natijasi: server + javob manzili (ascii IP'lar), lekin atrofda
    # kirill matn (cp866) — UTF-8 dekodlash mojibake qilardi.
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
    # Birinchi Address (server) tashlanadi, ikkinchisi javob.
    assert result.addresses == ["93.184.216.34"]
    # CREATE_NO_WINDOW (yoki 0) uzatilgan bo'lishi kerak (oyna miltillamasin).
    assert captured["creationflags"] == dns._platform.subprocess_flags()


# --------------------------------------------------------------------------- #
# AAAA (IPv6) — 0.5.0. `getaddrinfo` global IPv6 yo'q bo'lsa AAAA'ni yashiradi,
# shuning uchun haqiqiy AAAA dig/nslookup orqali olinadi.
# --------------------------------------------------------------------------- #


def test_dns_result_has_aaaa_field():
    from systop.core.dns import DnsResult

    assert DnsResult(name="x").aaaa_addresses == []


def test_dns_result_stores_aaaa():
    from systop.core.dns import DnsResult

    r = DnsResult(name="x", aaaa_addresses=["2606:4700::1"])
    assert r.aaaa_addresses == ["2606:4700::1"]


def test_dig_regex_matches_aaaa_record():
    """Mavjud dig regexi AAAA'ni ham tutishi kerak."""
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
# Tizim resolverlarini aniqlash — uchala OS (SOF parserlar, offline)
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
# nameserver 1.1.1.1  (izohga olingan — hisobga olinmasin)
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


def test_resolv_conf_izohlarni_tashlaydi():
    assert parse_resolv_conf(RESOLV_CONF) == ["192.168.1.1", "8.8.8.8"]


def test_resolv_conf_bosh_fayl():
    assert parse_resolv_conf("") == []
    assert parse_resolv_conf("# faqat izoh\nsearch local\n") == []


def test_scutil_takrorlarni_yigadi_tartib_saqlanadi():
    """`scutil --dns` ro'yxatni IKKI marta beradi (scoped bo'limi) — takror emas.

    Birinchi resolver asosiysi, shuning uchun tartib muhim.
    """
    assert parse_scutil_dns(SCUTIL_DNS) == ["192.168.10.1", "192.168.10.2"]


def test_scutil_mdns_blokidan_nameserver_olinmaydi():
    """`domain: local` + `options: mdns` blokida nameserver yo'q — qo'shilmasin."""
    assert "local" not in parse_scutil_dns(SCUTIL_DNS)


def test_ipconfig_yorliqsiz_davomiy_qatorlarni_oladi():
    """Windows ikkinchi va uchinchi serverni YORLIQSIZ qatorda beradi.

    Faqat `DNS Servers` qatorini o'qigan parser 3 tadan 2 tasini yo'qotadi.
    """
    got = parse_ipconfig_all_dns(IPCONFIG_ALL)
    assert got == ["192.168.1.1", "8.8.8.8", "fe80::1"]


def test_ipconfig_royxat_keyingi_yorliqda_tugaydi():
    """`NetBIOS over Tcpip` qatori ro'yxatga qo'shilib ketmasligi kerak."""
    got = parse_ipconfig_all_dns(IPCONFIG_ALL)
    assert all(not g.startswith("Enabled") for g in got)
    assert len(got) == 3


def test_parserlar_ip_bolmagan_qiymatni_rad_etadi():
    """Har uchala parser oxirida bir xil IP tekshiruvidan o'tadi."""
    assert parse_resolv_conf("nameserver not-an-ip\n") == []
    assert parse_scutil_dns("  nameserver[0] : hostname.local\n") == []


# --------------------------------------------------------------------------- #
# Windows ipconfig — TILGA BOG'LIQ EMAS
# --------------------------------------------------------------------------- #

# Bu bug ruscha Windows serverida (ruscha Windows 10) topildi: `systop doctor`
# "Barcha DNS serverlar javob bermayapti" degan soxta HIGH bergan edi, chunki
# `DNS Servers` yorlig'i topilmagan. v0.3.2 da ping'da AYNAN shu sabab RUS
# Windows'da hamma nishonni "o'lik" ko'rsatgandi — bir xil xato ikkinchi marta.

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


def test_ruscha_windows_dns_topiladi():
    """`DNS-серверы` — inglizcha yorliqni izlagan regex buni ko'rmaydi."""
    assert parse_ipconfig_all_dns(IPCONFIG_RU) == ["192.168.10.1", "8.8.8.8"]


def test_nemischa_windows_dns_topiladi():
    assert parse_ipconfig_all_dns(IPCONFIG_DE) == ["192.168.1.1", "1.1.1.1"]


def test_dns_suffiks_qatori_royxatni_boshlamaydi():
    """`DNS-суффикс` yorlig'ida ham `DNS` bor, lekin qiymati IP emas.

    Uni ro'yxat boshi deb olsak, keyingi `Основной шлюз` (gateway) DNS deb
    yig'ilib ketardi — ya'ni gateway'ni resolver deb ko'rsatardik.
    """
    got = parse_ipconfig_all_dns(IPCONFIG_RU)
    assert "corp.local" not in got
    # 192.168.10.1 bu yerda HAM gateway, HAM DNS — lekin u DNS qatoridan
    # olingan bo'lishi kerak, gateway qatoridan emas.
    assert got[0] == "192.168.10.1"
    assert len(got) == 2


def test_uchala_til_bir_xil_ishlaydi():
    """Tool xulosasi Windows TILIGA qarab o'zgarmasligi kerak."""
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
