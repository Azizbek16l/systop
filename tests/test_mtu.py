"""Offline tests for `core/mtu.py` — nothing here touches the network.

Both ping and DNS are faked: `mtu.resolve_host` (the shared resolver) and
`mtu._probe` (a single DF-ping) are monkeypatched. That makes the path MTU
logic itself — family selection, retries, the binary search and the boundary
verification — fully testable without a network (the project's "tests are
offline" rule).
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
# The fake environment
# --------------------------------------------------------------------------- #


class FakeNet:
    """A fake network: payloads up to `limit` bytes pass, larger ones do not.

    `over` — the answer to a packet above the limit: `too_big` (an ICMP message
    comes back from the path) or `no_reply` (a PMTUD black hole — nothing comes
    back at all).
    `drop_once` — these payloads are lost EXACTLY ONCE (modelling random packet
    loss); the next attempt answers normally.
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
        """The same payload twice in a row = the sign of a RETRY."""
        pairs = list(zip(self.payloads, self.results, strict=True))
        return [(p1, v1) for (p1, v1), (p2, _) in zip(pairs, pairs[1:], strict=False) if p1 == p2]


def _install(monkeypatch, net: FakeNet, address: str = "1.1.1.1", family: str = "ipv4"):
    """Replace the resolver and the probe with fake versions."""

    async def fake_resolve(host: str, fam: str = "auto") -> tuple[str | None, str | None]:
        return address, family

    monkeypatch.setattr(mtu, "resolve_host", fake_resolve)
    monkeypatch.setattr(mtu, "_probe", net.probe)
    return net


# --------------------------------------------------------------------------- #
# classify_ping_output — a pure function
# --------------------------------------------------------------------------- #


def test_classify_ok_reply():
    assert classify_ping_output("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=9 ms") == "ok"


def test_classify_macos_message_too_long():
    """macOS `ping` writes this to STDERR — which is why stderr is read too."""
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
    """When the output holds both, 'too big' wins — it is the definite cause."""
    text = "64 bytes from 1.1.1.1: ttl=57\nping: sendto: Message too long"
    assert classify_ping_output(text) == "too_big"


# --------------------------------------------------------------------------- #
# The address family comes from the RESOLVE (not from the host string)
# --------------------------------------------------------------------------- #


async def test_family_from_resolver_not_from_hostname(monkeypatch):
    """An AAAA-only name has no colon in it — the family must still be IPv6.

    `":" in host` used to be used: `ipv6.google.com` was labelled IPv4, which
    produced `"family": "ipv4"` in `--json` and the FALSE conclusion "the host
    is dead or ICMP is blocked".
    """
    net = _install(monkeypatch, FakeNet(), address="2a00:1450:4001:80f::200e", family="ipv6")
    res = await discover_path_mtu("ipv6.google.com")

    assert res.family == "ipv6"
    assert res.error is None
    assert res.address == "2a00:1450:4001:80f::200e"
    # The header overhead follows from the family too: 1500 - 48 = 1452.
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
    """A raw IPv6 address goes through the resolver as well (the zone is preserved)."""
    net = _install(monkeypatch, FakeNet(), address="fe80::1%en0", family="ipv6")
    res = await discover_path_mtu("fe80::1%en0")

    assert res.family == "ipv6"
    assert res.address == "fe80::1%en0"
    assert {host for host, _, _ in net.calls} == {"fe80::1%en0"}


async def test_probe_targets_resolved_address_not_hostname(monkeypatch):
    """The ping goes to the RESOLVED IP — no fresh DNS lookup on every probe."""
    net = _install(monkeypatch, FakeNet(limit=1300), address="93.184.216.34")
    await discover_path_mtu("example.com")

    assert net.calls, "no probe was sent at all"
    assert {host for host, _, _ in net.calls} == {"93.184.216.34"}


async def test_liveness_probe_also_uses_resolved_address(monkeypatch):
    """The 56-byte 'is it alive?' probe goes to that same address."""
    net = _install(monkeypatch, FakeNet(limit=1000, over="no_reply"), address="10.0.0.1")
    await discover_path_mtu("router.lan")

    assert (("10.0.0.1", 56, False)) in net.calls


async def test_resolve_failure_returns_error(monkeypatch):
    """If the resolve fails — a meaningful error, not a 0 MTU, and not one probe."""

    async def no_resolve(host: str, fam: str = "auto") -> tuple[str | None, str | None]:
        return None, None

    net = FakeNet()
    monkeypatch.setattr(mtu, "resolve_host", no_resolve)
    monkeypatch.setattr(mtu, "_probe", net.probe)

    res = await discover_path_mtu("does-not-exist.invalid")
    assert res.path_mtu is None
    assert res.error is not None
    assert "does-not-exist.invalid" in res.error
    assert res.probes == 0
    assert net.calls == []


async def test_forced_family_passed_to_resolver(monkeypatch):
    """`family="ipv6"` is handed to the resolver (AAAA is forced)."""
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
# Retries: ONLY on `no_reply`
# --------------------------------------------------------------------------- #


async def test_lost_echo_is_retried(monkeypatch):
    """A single lost echo must not lower the result."""
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu == 1500  # the retry recovered it
    assert res.probes == 2  # the lost one plus the retry
    assert net.payloads == [1472, 1472]


async def test_too_big_is_never_retried(monkeypatch):
    """`too_big` is the DEFINITIVE answer of a device along the path; repeating is waste.

    (A retry only fixes a missing answer; "too big" will not change, and every
    retry slows the scan down.)
    """
    net = _install(monkeypatch, FakeNet(limit=1392))  # the real MTU is 1420
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu == 1420
    assert [v for _, v in net.immediate_repeats() if v == "too_big"] == []


async def test_no_reply_verdict_is_the_only_retried_one(monkeypatch):
    """The retry happens after EXACTLY the unanswered probe."""
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    await discover_path_mtu("1.1.1.1")

    assert net.immediate_repeats() == [(1472, "no_reply")]


async def test_retries_zero_costs_a_full_search(monkeypatch):
    """`retries=0` — the old behaviour: one loss drags in a whole search."""
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    res = await discover_path_mtu("1.1.1.1", retries=0)

    assert res.path_mtu == 1500
    assert res.probes > 2  # ~10 probes instead of one retry
    assert net.immediate_repeats() == []


async def test_single_loss_at_boundary_does_not_underreport(monkeypatch):
    """Even if the boundary payload is lost in a black hole, the MTU does not drop.

    Each probe used to be sent exactly once: that single lost echo
    under-reported the MTU by up to 143 bytes and pushed the `doctor` verdict
    from medium to high.
    """
    _install(monkeypatch, FakeNet(limit=1392, over="no_reply", drop_once={1392}))
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu == 1420


async def test_probes_counted_including_retries(monkeypatch):
    net = _install(monkeypatch, FakeNet(drop_once={1472}))
    res = await discover_path_mtu("1.1.1.1")
    assert res.probes == len(net.calls)


# --------------------------------------------------------------------------- #
# Binary search and boundary verification (`best + 1`)
# --------------------------------------------------------------------------- #


async def test_high_passes_in_one_probe(monkeypatch):
    """The most common case: 1500 gets through — one probe is enough."""
    net = _install(monkeypatch, FakeNet())
    res = await discover_path_mtu("1.1.1.1")
    assert res.probes == 1
    assert net.payloads == [1472]
    assert res.path_mtu == 1500


async def test_binary_search_finds_tunnel_mtu(monkeypatch):
    """The 1420 behind a WireGuard tunnel is found exactly."""
    _install(monkeypatch, FakeNet(limit=1420 - IP_ICMP_OVERHEAD))
    res = await discover_path_mtu("1.1.1.1")
    assert res.path_mtu == 1420
    assert res.max_payload == 1392
    assert res.likely_cause == "WireGuard (typical)"


async def test_black_hole_still_measured_when_host_alive(monkeypatch):
    """No ICMP message (a black hole), but small packets pass — the MTU is found."""
    _install(monkeypatch, FakeNet(limit=1372, over="no_reply"))
    res = await discover_path_mtu("1.1.1.1")
    assert res.error is None
    assert res.path_mtu == 1400


async def test_boundary_reverified_at_best_plus_one(monkeypatch):
    """The boundary is verified with `best + 1` — testing `best` was a no-op.

    Here the real boundary payload is 1400, but the probe of EXACTLY 1400 bytes
    is lost once and (with `retries=0`) the search finishes at 1399. Because
    `best + 1` is re-tested, the result is restored to 1400.
    """
    net = _install(monkeypatch, FakeNet(limit=1400, drop_once={1400}))
    res = await discover_path_mtu("1.1.1.1", retries=0)

    assert res.max_payload == 1400
    assert res.path_mtu == 1400 + IP_ICMP_OVERHEAD
    assert net.payloads.count(1400) == 2, "best+1 was not re-tested"


async def test_reverify_does_not_run_when_best_is_high(monkeypatch):
    """When `best` is already the upper bound no extra probe is needed."""
    net = _install(monkeypatch, FakeNet())
    await discover_path_mtu("1.1.1.1")
    assert net.payloads == [1472]  # no superfluous verification probe


async def test_dead_host_gives_error_not_zero_mtu(monkeypatch):
    """If the host does not answer — a meaningful error; not an MTU of 0."""
    _install(monkeypatch, FakeNet(dead=True))
    res = await discover_path_mtu("1.1.1.1")

    assert res.path_mtu is None
    assert res.error is not None
    assert "is not answering pings" in res.error


async def test_all_sizes_too_big_gives_error(monkeypatch):
    """If not even `low` gets through — the 'MTU is below low' error."""
    _install(monkeypatch, FakeNet(limit=100))
    res = await discover_path_mtu("1.1.1.1", low=1200, high=1500)

    assert res.path_mtu is None
    assert res.error is not None
    assert "1200" in res.error


# --------------------------------------------------------------------------- #
# Command building and the MtuResult properties
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
    """Even in a failed (unresolved) result the field has a definite value."""
    assert MtuResult(host="h").family == "ipv4"


# --------------------------------------------------------------------------- #
# The TRUTHFUL reason when a resolve fails
# --------------------------------------------------------------------------- #


async def test_aaaa_exists_but_no_ipv6_so_dns_is_not_blamed(monkeypatch):
    """FALSE-DIAGNOSIS REGRESSION.

    For `ipv6.google.com` the AAAA record DOES exist in DNS, but if the host has
    no global IPv6 address the OS removes it from `getaddrinfo` altogether
    (RFC 6724). The old message said "no DNS record" and the sysadmin went off
    to fix DNS — while the problem was IPv6 connectivity.
    """
    from systop.core import mtu as mtu_mod

    async def fake_aaaa(name, tool, timeout=3.0):
        return ["2a00:1450:4025:800::8b"]

    monkeypatch.setattr("systop.core.dns._pick_tool", lambda: "dig")
    monkeypatch.setattr("systop.core.dns._query_aaaa", fake_aaaa)
    monkeypatch.setattr(
        "systop.core.netinfo.list_interfaces",
        lambda: [],  # no global IPv6
    )
    msg = await mtu_mod._resolve_failure_reason("ipv6.google.com", "auto")
    assert "DNS is NOT to blame" in msg
    assert "2a00:1450:4025:800::8b" in msg
    assert "RFC 6724" in msg


async def test_a_genuinely_missing_name_is_reported_as_dns(monkeypatch):
    """With neither an AAAA nor an A record — this REALLY is a DNS problem."""
    from systop.core import mtu as mtu_mod

    async def none_found(name, tool, timeout=3.0):
        return []

    monkeypatch.setattr("systop.core.dns._pick_tool", lambda: "dig")
    monkeypatch.setattr("systop.core.dns._query_aaaa", none_found)
    msg = await mtu_mod._resolve_failure_reason("nothing.invalid", "auto")
    assert "there is no DNS record" in msg


async def test_without_dig_the_cautious_message_is_used(monkeypatch):
    """Without `dig`/`nslookup` the two cannot be told apart — a cautious message."""
    from systop.core import mtu as mtu_mod

    monkeypatch.setattr("systop.core.dns._pick_tool", lambda: None)
    msg = await mtu_mod._resolve_failure_reason("host.example", "auto")
    assert "there is no DNS record" in msg
