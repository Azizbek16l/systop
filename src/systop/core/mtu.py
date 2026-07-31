"""Path MTU discovery — the cause behind "some sites don't load". No root required.

Why this matters for a sysadmin: an MTU black hole (**PMTUD black hole**) is
one of the most misleading network faults there is —

  * ping works (small packet), DNS works, SSH connects too;
  * but sites that return a large response **hang half-loaded**;
  * it is especially common on hosts behind a VPN/GRE/PPPoE tunnel (the tunnel
    header brings 1500 down to 1420-1472);
  * the cause: a device along the path needs to split the large packet, but the
    DF (Don't Fragment) flag is set and it **blocks** the ICMP "fragmentation
    needed" message — so the sender never learns the MTU.

The method: send pings of various sizes with the DF flag and find the largest
payload that gets through by **binary search**. The system `ping` binary is
used (macOS `-D`, Linux `-M do`, Windows `-f`) — no root needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The address family is NOT guessed from the hostname STRING — it is determined
# ONCE by the shared resolver in `ports` (`resolve_host`). `":" in host` used to
# be used: an AAAA-only name (`ipv6.google.com`) was labelled IPv4, its IPv4
# ping went unanswered and the tool produced the FALSE conclusion "the host is
# dead or ICMP is blocked". A second resolver IS NOT WRITTEN — the one in
# `ports` rejects `::ffff:` (IPv4-mapped) forms and preserves `%zone`.
from systop.core import _platform
from systop.core.ports import FAMILY_AUTO, FAMILY_V6
from systop.core.ports import _resolve as resolve_host

# IPv4 header (20) + ICMP header (8) = 28 bytes on top of the payload.
IP_ICMP_OVERHEAD = 28
IP6_ICMP_OVERHEAD = 48  # IPv6 header (40) + ICMPv6 (8)

ETHERNET_MTU = 1500
# Common tunnel MTUs — used to explain the value that was found.
KNOWN_MTU: dict[int, str] = {
    1500: "Ethernet (standard)",
    1492: "PPPoE",
    1480: "GRE tunnel",
    1476: "GRE + PPPoE",
    1472: "IPSec/L2TP (typical)",
    1450: "VXLAN / some VPNs",
    1420: "WireGuard (typical)",
    1400: "IPSec (conservative)",
    1280: "IPv6 minimum MTU",
}

# "fragmentation needed", "message too long", "Packet needs to be fragmented"
_TOO_BIG_RE = re.compile(
    r"too long|frag(?:ment)?|needs to be fragmented|message too big", re.IGNORECASE
)
# A successful reply: "64 bytes from ..." / "Reply from ... bytes=..."
_REPLY_RE = re.compile(r"bytes from|bytes=|ttl=", re.IGNORECASE)


@dataclass(slots=True)
class MtuResult:
    """The result of a path MTU measurement."""

    host: str
    path_mtu: int | None = None  # the full IP packet size (payload + overhead)
    max_payload: int | None = None
    probes: int = 0  # how many pings were sent (retries included)
    family: str = "ipv4"  # taken from the RESOLVE result, not from the host string
    address: str | None = None  # the IP actually pinged (with its zone)
    error: str | None = None

    @property
    def is_reduced(self) -> bool:
        """Is it below the standard Ethernet MTU (a sign of a tunnel/VPN)."""
        return self.path_mtu is not None and self.path_mtu < ETHERNET_MTU

    @property
    def likely_cause(self) -> str | None:
        """If the MTU found matches a common tunnel value — its name."""
        if self.path_mtu is None:
            return None
        exact = KNOWN_MTU.get(self.path_mtu)
        if exact:
            return exact
        # The nearest known value (within a ±8 byte window).
        for mtu, name in KNOWN_MTU.items():
            if abs(mtu - self.path_mtu) <= 8:
                return f"close to {name}"
        return None


def classify_ping_output(text: str, returncode_ok: bool = True) -> str:
    """Classify ping output as `ok` | `too_big` | `no_reply` — pure function.

    Telling the three apart matters: "too big" (over the MTU) and "no reply"
    (host dead / ICMP blocked) lead to completely different conclusions. Mixing
    them up made us report an MTU of 0 on a host that blocks ICMP.
    """
    if _TOO_BIG_RE.search(text):
        return "too_big"
    if _REPLY_RE.search(text) and returncode_ok:
        return "ok"
    return "no_reply"


def _build_cmd(host: str, payload: int, is_v6: bool, timeout: float) -> list[str]:
    """The DF-flagged ping command for this platform."""
    if _platform.IS_WINDOWS:
        # -f = DF, -l = payload, -w = ms
        return ["ping", "-n", "1", "-f", "-l", str(payload), "-w", str(int(timeout * 1000)), host]
    wait = str(max(1, int(timeout)))
    if is_v6:
        # macOS ping6 / Linux ping -6: DF is permanent on IPv6 (no fragmentation).
        return ["ping6", "-c", "1", "-s", str(payload), "-i", "1", host]
    if _platform.IS_MACOS:
        # macOS: -D = the DF flag
        return ["ping", "-c", "1", "-D", "-s", str(payload), "-W", str(int(timeout * 1000)), host]
    # Linux (iputils): -M do = DF
    return ["ping", "-c", "1", "-M", "do", "-s", str(payload), "-W", wait, host]


async def _probe(host: str, payload: int, is_v6: bool, timeout: float) -> str:
    """A single-size probe — `ok`/`too_big`/`no_reply`.

    `host` is the RESOLVED IP (with its zone), not a name: so that no fresh DNS
    query goes out on every probe and the family cannot change underneath us.
    """
    cmd = _build_cmd(host, payload, is_v6, timeout)
    # stderr is REQUIRED: macOS `ping` writes "Message too long" precisely there.
    out = await _platform.run_command(cmd, timeout=timeout + 3.0, include_stderr=True)
    if not out:
        # `run_command` returns an empty string on error (it never raises).
        return "no_reply"
    return classify_ping_output(out)


async def _resolve_failure_reason(host: str, family: str) -> str:
    """Explain TRUTHFULLY why the resolve failed.

    Why this is a separate function: saying "no DNS record" is **wrong** in the
    most common case and sends the sysadmin off in an entirely wrong direction.

    For `ipv6.google.com` the AAAA record DOES exist in DNS, but if the host has
    no global IPv6 address the OS removes it from `getaddrinfo` altogether
    (RFC 6724 address selection). The result was "the name could not be
    resolved" and the operator went off to fix DNS — while the problem was IPv6
    connectivity.

    So on failure the AAAA record is queried separately with `dig` and the
    answer distinguishes the two cases.
    """
    want = "" if family == FAMILY_AUTO else f" ({family})"
    base = f"could not turn the name '{host}' into an IP{want}"

    from systop.core import netinfo
    from systop.core.dns import _pick_tool, _query_aaaa

    tool = _pick_tool()
    if not tool:
        return f"{base} — there is no DNS record."
    try:
        aaaa = await _query_aaaa(host, tool, timeout=3.0)
    except Exception:  # noqa: BLE001 — for the explanation only, not the main result
        aaaa = []
    if not aaaa:
        return f"{base} — there is no DNS record."

    try:
        has_global6 = any(i.ipv6_global for i in netinfo.list_interfaces())
    except Exception:  # noqa: BLE001
        has_global6 = False
    if has_global6:
        return f"{base}, even though DNS does have an AAAA record ({aaaa[0]})."
    return (
        f"{base}. DNS is NOT to blame: an AAAA record exists ({aaaa[0]}), but this host "
        "has no global IPv6 address, so the OS hides the AAAA completely "
        "(RFC 6724). Enable IPv6 connectivity or give an IPv4 target."
    )


async def discover_path_mtu(
    host: str,
    low: int = 1200,
    high: int = 1500,
    timeout: float = 2.0,
    family: str = FAMILY_AUTO,
    retries: int = 1,
) -> MtuResult:
    """Find the path MTU by binary search with DF-flagged pings.

    `low`/`high` are bounds on the full IP packet size (not the payload). The
    default window 1200-1500 covers the IPv6 minimum MTU (1280) and tunnel
    values below, and standard Ethernet above.

    `high` is tried first — if it gets through no search is needed (the most
    common case, done in one probe). If `low` does not get through either, the
    host may be blocking ICMP — in that case an `error` is returned rather than
    0 (otherwise the false conclusion "the MTU is very small" came out).

    `family` is `auto` (the OS choice) or a forced `ipv4`/`ipv6`. The family is
    taken **from the resolve result**: the header overhead (28 or 48 bytes), the
    ping command and `res.family` all follow from it.

    `retries` — ONLY a probe left unanswered (`no_reply`) is sent again.
    `too_big` is never retried: it is the definitive answer of a device along
    the path (ICMP "fragmentation needed"), and repeating it does not change the
    result. A single lost echo, meanwhile, under-reported the MTU by up to 143
    bytes and pushed the `doctor` verdict from medium to high.
    """
    res = MtuResult(host=host)
    # NB: `_resolve_failure_reason` below goes out to the network, so it is
    # only called when the resolve fails.

    # 1) Resolve ONCE — the family is determined here.
    resolved, resolved_family = await resolve_host(host, family)
    if resolved is None or resolved_family is None:
        res.error = await _resolve_failure_reason(host, family)
        return res
    # A separate `str` name for the inner closures (the None check already passed).
    address: str = resolved
    is_v6 = resolved_family == FAMILY_V6
    overhead = IP6_ICMP_OVERHEAD if is_v6 else IP_ICMP_OVERHEAD
    res.family = resolved_family
    res.address = address

    lo_payload = max(low - overhead, 0)
    hi_payload = max(high - overhead, lo_payload)

    seen: dict[int, str] = {}  # payload -> last verdict (saves a repeat probe)

    async def probe(payload: int) -> str:
        """Probe, retrying only on `no_reply`; counts into `probes`."""
        verdict = await _probe(address, payload, is_v6, timeout)
        res.probes += 1
        attempt = 0
        while verdict == "no_reply" and attempt < max(retries, 0):
            attempt += 1
            verdict = await _probe(address, payload, is_v6, timeout)
            res.probes += 1
        seen[payload] = verdict
        return verdict

    async def search(lo: int, hi: int) -> int | None:
        """Binary search: the largest payload in the [lo, hi] window that passes."""
        best: int | None = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if await probe(mid) == "ok":
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    # 2) Does the largest size get through?
    top = await probe(hi_payload)
    if top == "ok":
        res.max_payload = hi_payload
        res.path_mtu = hi_payload + overhead
        return res
    if top == "no_reply":
        # Check with a small packet: is the host alive? (Against that same
        # resolved address — not the name, otherwise the family could switch.)
        if await probe(56) != "ok":
            res.error = (
                f"'{host}' is not answering pings — the MTU could not be measured "
                "(the host is dead or ICMP is blocked)."
            )
            return res
        # The host is alive but large packets go unanswered => a black hole (no
        # ICMP message). Continue the binary search, treating "no_reply" as
        # "too big".

    # 3) Binary search: the largest payload that gets through.
    best = await search(lo_payload, hi_payload)

    # 4) VERIFY the boundary. Re-testing `best` is pointless — by definition it
    # is a size that already answered. The boundary is proved by `best + 1`: if
    # that also gets through, the search was dragged down by a lost packet and
    # we re-examine the window above.
    # A size that came back `too_big` is NOT re-tested — that is the definitive
    # answer of a device along the path, and a second probe only costs time.
    if best is not None and best < hi_payload and seen.get(best + 1) != "too_big":
        if await probe(best + 1) == "ok":
            best += 1
            higher = await search(best + 1, hi_payload)
            if higher is not None:
                best = higher

    if best is None:
        res.error = (
            f"'{host}': not even a {low}-byte packet got through — the MTU is below "
            f"{low}, or ICMP is blocked completely along the path."
        )
        return res
    res.max_payload = best
    res.path_mtu = best + overhead
    return res
