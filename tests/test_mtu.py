"""`core/mtu.py` uchun offline testlar — tarmoqqa chiqmaydi.

Ping ham, DNS ham soxtalashtiriladi: `mtu.resolve_host` (umumiy resolver) va
`mtu._probe` (bitta DF-ping) monkeypatch qilinadi. Shu tufayli path MTU
mantiqining o'zi — oila tanlash, qayta urinish, ikkilik qidiruv va chegarani
tasdiqlash — tarmoqsiz to'liq sinaladi (loyihaning "testlar offline" qoidasi).
"""

from __future__ import annotations

import pytest

from systop.core import mtu
from systop.core.mtu import (
    IP6_ICMP_OVERHEAD,
    IP_ICMP_OVERHEAD,
    MtuResult,
    classify_ping_output,
    discover_path_mtu,
)

# --------------------------------------------------------------------------- #
# Soxta muhit
# --------------------------------------------------------------------------- #


class FakeNet:
    """Soxta tarmoq: `limit` baytgacha payload o'tadi, kattasi o'tmaydi.

    `over` — chegaradan katta paketga javob: `too_big` (yo'lda ICMP xabari
    qaytadi) yoki `no_reply` (PMTUD qora tuynugi — hech narsa qaytmaydi).
    `drop_once` — shu payload'lar BIR MARTA yo'qoladi (tasodifiy paket
    yo'qolishini modellashtiradi), keyingi urinishda normal javob beradi.
    """

    def __init__(
        self,
        limit: int = 10_000,
        over: str = "too_big",
        drop_once: set[int] | None = None,
        dead: bool = False,
    ) -> None:
        self.limit = limit
        self.over = over
        self.drop_once = set(drop_once or ())
        self.dead = dead
        self.calls: list[tuple[str, int, bool]] = []
        self.results: list[str] = []

    async def probe(self, host: str, payload: int, is_v6: bool, timeout: float) -> str:
        self.calls.append((host, payload, is_v6))
        if payload in self.drop_once:
            self.drop_once.discard(payload)
            verdict = "no_reply"
        elif self.dead:
            verdict = "no_reply"
        else:
            verdict = "ok" if payload <= self.limit else self.over
        self.results.append(verdict)
        return verdict

    @property
    def payloads(self) -> list[int]:
        return [p for _, p, _ in self.calls]

    def immediate_repeats(self) -> list[tuple[int, str]]:
        """Ketma-ket bir xil payload = QAYTA URINISH (retry) belgisi."""
        pairs = list(zip(self.payloads, self.results, strict=True))
        return [(p1, v1) for (p1, v1), (p2, _) in zip(pairs, pairs[1:], strict=False) if p1 == p2]


def _install(monkeypatch, net: FakeNet, address: str = "1.1.1.1", family: str = "ipv4"):
    """Resolver va probe'ni soxta versiyalar bilan almashtiradi."""

    async def fake_resolve(host: str, fam: str = "auto") -> tuple[str | None, str | None]:
        return address, family

    monkeypatch.setattr(mtu, "resolve_host", fake_resolve)
    monkeypatch.setattr(mtu, "_probe", net.probe)
    return net


# --------------------------------------------------------------------------- #
# classify_ping_output — sof funksiya
# --------------------------------------------------------------------------- #


def test_classify_ok_reply():
    assert classify_ping_output("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=9 ms") == "ok"


def test_classify_macos_message_too_long():
    """macOS `ping` buni STDERR ga yozadi — shuning uchun stderr ham o'qiladi."""
    assert classify_ping_output("ping: sendto: Message too long") == "too_big"


def test_classify_linux_frag_needed():
    text = "ping: local error: message too long, mtu=1420"
    assert classify_ping_output(text) == "too_big"


def test_classify_windows_df_message():
    text = "Packet needs to be fragmented but DF set."
    assert classify_ping_output(text) == "too_big"


def test_classify_timeout_is_no_reply():
    assert classify_ping_output("Request timeout for icmp_seq 0") == "no_reply"


def test_classify_empty_output_is_no_reply():
    assert classify_ping_output("") == "no_reply"


def test_classify_too_big_wins_over_reply_text():
    """Chiqishda ikkalasi ham bo'lsa 'juda katta' ustun — u aniq sabab."""
    text = "64 bytes from 1.1.1.1: ttl=57\nping: sendto: Message too long"
    assert classify_ping_output(text) == "too_big"


# --------------------------------------------------------------------------- #
# Manzil oilasi RESOLVE dan olinadi (host satridan emas)
# --------------------------------------------------------------------------- #


async def test_family_from_resolver_not_from_hostname(monkeypatch):
    """AAAA-only nomda ikki nuqta yo'q — oila baribir IPv6 bo'lishi kerak.

    Ilgari `":" in host` ishlatilardi: `ipv6.google.com` IPv4 deb belgilanib,
    natijada `--json` da `"family": "ipv4"` va SOXTA "host o'lik yoki ICMP
    bloklangan" xulosasi chiqardi.
    """
    net = _install(monkeypatch, FakeNet(), address="2a00:1450:4001:80f::200e", family="ipv6")
    res = await discover_path_mtu("ipv6.google.com")

    assert res.family == "ipv6"
    assert res.error is None
    assert res.address == "2a00:1450:4001:80f::200e"
    # Sarlavha qo'shimchasi ham oiladan kelib chiqadi: 1500 - 48 = 1452.
    assert res.max_payload == 1500 - IP6_ICMP_OVERHEAD
    assert res.path_mtu == 1500
    assert all(is_v6 for _, _, is_v6 in net.calls)


async def test_ipv4_uses_28_byte_overhead(monkeypatch):
    net = _install(monkeypatch, FakeNet())
    res = await discover_path_mtu("example.com")

    assert res.family == "ipv4"
    assert res.max_payload == 1500 - IP_ICMP_OVERHEAD
    assert res.path_mtu == 1500
    assert not any(is_v6 for _, _, is_v6 in net.calls)


async def test_ipv6_literal_host_still_v6(monkeypatch):
    """Xom IPv6 manzil ham resolver orqali o'tadi (zona saqlanadi)."""
    net = _install(monkeypatch, FakeNet(), address="fe80::1%en0", family="ipv6")
    res = await discover_path_mtu("fe80::1%en0")

    assert res.family == "ipv6"
    assert res.address == "fe80::1%en0"
    assert {host for host, _, _ in net.calls} == {"fe80::1%en0"}


async def test_probe_targets_resolved_address_not_hostname(monkeypatch):
    """Ping RESOLVE qilingan IP ga ketadi — har probe'da qayta DNS bo'lmasin."""
    net = _install(monkeypatch, FakeNet(limit=1300), address="93.184.216.34")
    await discover_path_mtu("example.com")

    assert net.calls, "hech qanday probe yuborilmadi"
    assert {host for host, _, _ in net.calls} == {"93.184.216.34"}


async def test_liveness_probe_also_uses_resolved_address(monkeypatch):
    """56 baytli 'tirikmi?' probe'i ham o'sha manzilga ketadi."""
    net = _install(monkeypatch, FakeNet(limit=1000, over="no_reply"), address="10.0.0.1")
    await discover_path_mtu("router.lan")

    assert (("10.0.0.1", 56, False)) in net.calls


async def test_resolve_failure_returns_error(monkeypatch):
    """Resolve bo'lmasa — mazmunli xato, 0 MTU emas va bitta ham probe yo'q."""

    async def no_resolve(host: str, fam: str = "auto") -> tuple[str | None, str | None]:
        return None, None

    net = FakeNet()
    monkeypatch.setattr(mtu, "resolve_host", no_resolve)
    monkeypatch.setattr(mtu, "_probe", net.probe)

    res = await discover_path_mtu("mavjud-emas.invalid")
    assert res.path_mtu is None
    assert res.error is not None
    assert "mavjud-emas.invalid" in res.error
    assert res.probes == 0
    assert net.calls == []


async def test_forced_family_passed_to_resolver(monkeypatch):
    """`family="ipv6"` resolverga uzatiladi (majburan AAAA)."""
    seen: list[str] = []

    async def fake_resolve(host: str, fam: str = "auto") -> tuple[str | None, str | None]:
        seen.append(fam)
        return "2606:4700:4700::1111", "ipv6"

    monkeypatch.setattr(mtu, "resolve_host", fake_resolve)
    monkeypatch.setattr(mtu, "_probe", FakeNet().probe)

    res = await discover_path_mtu("one.one.one.one", family="ipv6")
    assert seen == ["ipv6"]
    assert res.family == "ipv6"


# --------------------------------------------------------------------------- #
# Qayta urinish: FAQAT `no_reply`
# --------------------------------------------------------------------------- #


async def test_lost_echo_is_retried(monkeypatch):
    """Bitta yo'qolgan echo natijani pasaytirmasligi kerak."""
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu == 1500  # qayta urinish tiklandi
    assert res.probes == 2  # yo'qolgani + qaytasi
    assert net.payloads == [1472, 1472]


async def test_too_big_is_never_retried(monkeypatch):
    """`too_big` — yo'ldagi qurilmaning ANIQ javobi, takrorlash ortiqcha.

    (Qayta urinish faqat javobsizlikni tuzatadi; "juda katta" o'zgarmaydi va
    har bir qayta urinish skanni sekinlashtiradi.)
    """
    net = _install(monkeypatch, FakeNet(limit=1392))  # haqiqiy MTU 1420
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu == 1420
    assert [v for _, v in net.immediate_repeats() if v == "too_big"] == []


async def test_no_reply_verdict_is_the_only_retried_one(monkeypatch):
    """Qayta urinish AYNAN javobsiz probe'dan keyin bo'ladi."""
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    await discover_path_mtu("1.1.1.1")

    assert net.immediate_repeats() == [(1472, "no_reply")]


async def test_retries_zero_costs_a_full_search(monkeypatch):
    """`retries=0` — eski xatti-harakat: bitta yo'qotish butun qidiruvni keltiradi."""
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    res = await discover_path_mtu("1.1.1.1", retries=0)

    assert res.path_mtu == 1500
    assert res.probes > 2  # qayta urinish o'rniga ~10 probe
    assert net.immediate_repeats() == []


async def test_single_loss_at_boundary_does_not_underreport(monkeypatch):
    """Qora tuynukda chegara payload'i yo'qolsa ham MTU pasayib ketmaydi.

    Ilgari har probe aynan bir marta yuborilardi: shu bitta yo'qolgan echo
    MTU ni 143 baytgacha past ko'rsatib, `doctor` xulosasini medium'dan
    high'ga sakratardi.
    """
    _install(monkeypatch, FakeNet(limit=1392, over="no_reply", drop_once={1392}))
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu == 1420


async def test_probes_counted_including_retries(monkeypatch):
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    res = await discover_path_mtu("1.1.1.1")
    assert res.probes == len(net.calls)


# --------------------------------------------------------------------------- #
# Ikkilik qidiruv va chegarani tasdiqlash (`best + 1`)
# --------------------------------------------------------------------------- #


async def test_high_passes_in_one_probe(monkeypatch):
    """Eng ko'p uchraydigan holat: 1500 o'tadi — bitta probe yetarli."""
    net = _install(monkeypatch, FakeNet())
    res = await discover_path_mtu("1.1.1.1")
    assert res.probes == 1
    assert net.payloads == [1472]
    assert res.path_mtu == 1500


async def test_binary_search_finds_tunnel_mtu(monkeypatch):
    """WireGuard tunneli ortidagi 1420 aniq topiladi."""
    _install(monkeypatch, FakeNet(limit=1420 - IP_ICMP_OVERHEAD))
    res = await discover_path_mtu("1.1.1.1")
    assert res.path_mtu == 1420
    assert res.max_payload == 1392
    assert res.likely_cause == "WireGuard (tipik)"


async def test_black_hole_still_measured_when_host_alive(monkeypatch):
    """ICMP xabari yo'q (qora tuynuk), lekin kichik paket o'tadi — MTU topiladi."""
    _install(monkeypatch, FakeNet(limit=1372, over="no_reply"))
    res = await discover_path_mtu("1.1.1.1")
    assert res.error is None
    assert res.path_mtu == 1400


async def test_boundary_reverified_at_best_plus_one(monkeypatch):
    """Chegara `best + 1` bilan tasdiqlanadi — `best` ni sinash no-op edi.

    Bu yerda haqiqiy chegara payload = 1400, lekin AYNAN 1400 baytli probe bir
    marta yo'qoladi va (`retries=0` da) qidiruv 1399 da tugaydi. `best + 1`
    qayta sinalgani uchun natija 1400 ga tiklanadi.
    """
    net = _install(monkeypatch, FakeNet(limit=1400, drop_once={1400}))
    res = await discover_path_mtu("1.1.1.1", retries=0)

    assert res.max_payload == 1400
    assert res.path_mtu == 1400 + IP_ICMP_OVERHEAD
    assert net.payloads.count(1400) == 2, "best+1 qayta sinalmagan"


async def test_reverify_does_not_run_when_best_is_high(monkeypatch):
    """`best` allaqachon yuqori chegara bo'lsa qo'shimcha probe kerak emas."""
    net = _install(monkeypatch, FakeNet())
    await discover_path_mtu("1.1.1.1")
    assert net.payloads == [1472]  # ortiqcha tasdiqlash probe'i yo'q


async def test_dead_host_gives_error_not_zero_mtu(monkeypatch):
    """Host javob bermasa — mazmunli xato; MTU 0 emas."""
    _install(monkeypatch, FakeNet(dead=True))
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu is None
    assert res.error is not None
    assert "javob bermayapti" in res.error


async def test_all_sizes_too_big_gives_error(monkeypatch):
    """Hatto `low` ham o'tmasa — 'MTU low dan kichik' xatosi."""
    _install(monkeypatch, FakeNet(limit=100))
    res = await discover_path_mtu("1.1.1.1", low=1200, high=1500)

    assert res.path_mtu is None
    assert res.error is not None
    assert "1200" in res.error


# --------------------------------------------------------------------------- #
# Buyruq qurish va MtuResult property'lari
# --------------------------------------------------------------------------- #


def test_build_cmd_v6_uses_ping6(monkeypatch):
    monkeypatch.setattr(mtu._platform, "IS_WINDOWS", False)
    monkeypatch.setattr(mtu._platform, "IS_MACOS", True)
    cmd = mtu._build_cmd("2606:4700:4700::1111", 1452, True, 2.0)
    assert cmd[0] == "ping6"
    assert "1452" in cmd


def test_build_cmd_v4_macos_sets_df(monkeypatch):
    monkeypatch.setattr(mtu._platform, "IS_WINDOWS", False)
    monkeypatch.setattr(mtu._platform, "IS_MACOS", True)
    cmd = mtu._build_cmd("1.1.1.1", 1472, False, 2.0)
    assert cmd[0] == "ping"
    assert "-D" in cmd  # Don't Fragment


def test_build_cmd_linux_sets_mtu_discover(monkeypatch):
    monkeypatch.setattr(mtu._platform, "IS_WINDOWS", False)
    monkeypatch.setattr(mtu._platform, "IS_MACOS", False)
    cmd = mtu._build_cmd("1.1.1.1", 1472, False, 2.0)
    assert "-M" in cmd and "do" in cmd


def test_build_cmd_windows_sets_f_flag(monkeypatch):
    monkeypatch.setattr(mtu._platform, "IS_WINDOWS", True)
    cmd = mtu._build_cmd("1.1.1.1", 1472, False, 2.0)
    assert cmd[0] == "ping"
    assert "-f" in cmd


@pytest.mark.parametrize(
    ("path_mtu", "expected"),
    [(1500, False), (1492, True), (1420, True), (None, False)],
)
def test_is_reduced(path_mtu, expected):
    assert MtuResult(host="h", path_mtu=path_mtu).is_reduced is expected


def test_likely_cause_exact_match():
    assert MtuResult(host="h", path_mtu=1492).likely_cause == "PPPoE"


def test_likely_cause_near_match():
    cause = MtuResult(host="h", path_mtu=1418).likely_cause
    assert cause is not None and "WireGuard" in cause


def test_likely_cause_unknown_mtu():
    assert MtuResult(host="h", path_mtu=1337).likely_cause is None


def test_default_family_field_is_ipv4():
    """Resolve bo'lmagan (xato) natijada ham maydon aniq qiymatga ega."""
    assert MtuResult(host="h").family == "ipv4"


# --------------------------------------------------------------------------- #
# Resolve yiqilganda ROSTGO'Y sabab
# --------------------------------------------------------------------------- #


async def test_aaaa_bor_lekin_ipv6_yoq_dns_ayblanmaydi(monkeypatch):
    """SOXTA DIAGNOZ REGRESSIYASI.

    `ipv6.google.com` da AAAA yozuvi DNS'da BOR, lekin hostda global IPv6
    manzil bo'lmasa OS uni `getaddrinfo` dan butunlay olib tashlaydi
    (RFC 6724). Eski xabar "DNS yozuvi yo'q" derdi va sysadmin DNS'ni
    tuzatgani ketardi — muammo esa IPv6 ulanishida edi.
    """
    from systop.core import mtu as mtu_mod

    async def fake_aaaa(name, tool, timeout=3.0):
        return ["2a00:1450:4025:800::8b"]

    monkeypatch.setattr("systop.core.dns._pick_tool", lambda: "dig")
    monkeypatch.setattr("systop.core.dns._query_aaaa", fake_aaaa)
    monkeypatch.setattr(
        "systop.core.netinfo.list_interfaces",
        lambda: [],  # global IPv6 yo'q
    )
    msg = await mtu_mod._resolve_failure_reason("ipv6.google.com", "auto")
    assert "DNS ayb EMAS" in msg
    assert "2a00:1450:4025:800::8b" in msg
    assert "RFC 6724" in msg


async def test_haqiqatan_yoq_nom_dns_deb_aytiladi(monkeypatch):
    """AAAA ham, A ham bo'lmasa — bu CHINDAN DNS muammosi."""
    from systop.core import mtu as mtu_mod

    async def yoq(name, tool, timeout=3.0):
        return []

    monkeypatch.setattr("systop.core.dns._pick_tool", lambda: "dig")
    monkeypatch.setattr("systop.core.dns._query_aaaa", yoq)
    msg = await mtu_mod._resolve_failure_reason("yoq.invalid", "auto")
    assert "DNS yozuvi yo'q" in msg


async def test_dig_bolmasa_eski_xabar(monkeypatch):
    """`dig`/`nslookup` yo'q bo'lsa ajratib bo'lmaydi — ehtiyotkor xabar."""
    from systop.core import mtu as mtu_mod

    monkeypatch.setattr("systop.core.dns._pick_tool", lambda: None)
    msg = await mtu_mod._resolve_failure_reason("host.example", "auto")
    assert "DNS yozuvi yo'q" in msg
