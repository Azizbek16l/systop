"""Network topology: the global path (traceroute) + local hosts (LAN discovery).

traceroute   — `icmplib.traceroute` (synchronous) is run in a thread; every
               "hop" is a router along the path.
discover_lan — ping-sweeps the local /24 to find the alive hosts, then fills in
               the MAC addresses from the OS ARP table. No root required.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import subprocess
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from icmplib import async_multiping
from icmplib import traceroute as _sync_traceroute
from icmplib.exceptions import ICMPLibError, NameLookupError

from systop.core import _platform, netinfo, oui

_ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")
_NEIGH_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+)")
# Windows `arp -a`: "  192.168.1.1    00-11-22-33-44-55     dynamic"
# The MAC uses dashes (-), 6 octets; the "static"/"dynamic" type is on the line.
# The header ("Internet Address ... Physical Address") and invalid entries
# (the "ff-ff-ff-ff-ff-ff" broadcast MAC, or ones with no address) do not match.
_ARP_WIN_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
)

# --- Regexes for the IPv6 neighbour table ---
# macOS `ndp -an`:  "fe80::1%en0   aa:bb:cc:dd:ee:ff   en0   23h59m58s  S  R"
_NDP_RE = re.compile(
    r"^([0-9a-fA-F:]+(?:%\w+)?)\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s+\S+",
)
# Linux `ip -6 neigh`: "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router STALE"
_NEIGH6_RE = re.compile(
    r"^([0-9a-fA-F:]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})",
)
# Windows `netsh interface ipv6 show neighbors`:
#   "fe80::1     aa-bb-cc-dd-ee-ff    Stale"
_NEIGH6_WIN_RE = re.compile(
    r"^\s*([0-9a-fA-F:]+(?:%\d+)?)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
)

# The link-local "all nodes" multicast address. Sweeping a /64 is impossible in
# IPv6 (2^64 addresses), so the standard approach is to ping this address and
# collect whoever answers (RFC 4291).
ALL_NODES_MULTICAST = "ff02::1"


@runtime_checkable
class _HostLike(Protocol):
    """The minimal interface of a ping host object (what `discover_lan` reads).

    Both `icmplib`'s Host and the Windows `_WinHost` fit this shape (duck typing)
    — which is exactly why `discover_lan` works identically from either source.
    """

    @property
    def address(self) -> str: ...

    @property
    def is_alive(self) -> bool: ...

    @property
    def avg_rtt(self) -> float: ...


@runtime_checkable
class _HopLike(Protocol):
    """The minimal interface of the hop object `icmplib.traceroute` returns.

    Only the attributes this module reads. The Protocol keeps the typing
    mypy-clean: `icmplib` does not export concrete types and we rely on duck
    typing (the tests' `FakeRawHop` fits the same shape).
    """

    @property
    def distance(self) -> int: ...

    @property
    def address(self) -> str | None: ...

    @property
    def avg_rtt(self) -> float: ...

    @property
    def is_alive(self) -> bool: ...


@dataclass(slots=True)
class Hop:
    """A single hop (router) in a traceroute."""

    index: int
    address: str | None
    hostname: str | None = None
    rtt_ms: float = 0.0
    alive: bool = False


@dataclass(slots=True)
class TraceResult:
    """The result of a traceroute: the hops + an error message, if there was one."""

    address: str
    hops: list[Hop]
    error: str | None = None


@dataclass(slots=True)
class LanHost:
    """A single host discovered on the local network."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    rtt_ms: float = 0.0
    is_gateway: bool = False
    vendor: str | None = None  # vendor derived from the MAC OUI
    family: str = "ipv4"  # ipv4 | ipv6
    source: str = "ping"  # ping | arp | ndp | multicast — how it was found

    @property
    def is_link_local(self) -> bool:
        """True for IPv6 link-local (fe80::/10) — an address that never crosses a router."""
        try:
            return ipaddress.ip_address(self.ip.split("%")[0]).is_link_local
        except ValueError:
            return False


@dataclass(slots=True)
class HopStat:
    """Cumulative per-hop statistics for `trace_stream` (mtr style).

    The path is probed over and over; the sent/received packet counts and the
    RTT statistics (last/average/best/worst) for each hop are updated live.
    """

    index: int
    address: str | None = None
    hostname: str | None = None
    sent: int = 0
    recv: int = 0
    last_rtt: float = 0.0
    avg_rtt: float = 0.0
    best_rtt: float = 0.0
    worst_rtt: float = 0.0
    _rtt_sum: float = 0.0  # internal: used to compute avg

    @property
    def loss_pct(self) -> float:
        """Packet loss percentage (0..100)."""
        if self.sent == 0:
            return 0.0
        return (self.sent - self.recv) / self.sent * 100.0

    def update(self, address: str | None, alive: bool, rtt: float) -> None:
        """Updates the hop statistics with the result of a single probe."""
        self.sent += 1
        if address and self.address is None:
            self.address = address
        if not alive or rtt <= 0:
            return
        self.recv += 1
        self.last_rtt = rtt
        self._rtt_sum += rtt
        self.avg_rtt = self._rtt_sum / self.recv
        self.worst_rtt = max(self.worst_rtt, rtt)
        self.best_rtt = rtt if self.best_rtt == 0.0 else min(self.best_rtt, rtt)


async def traceroute(
    address: str,
    first_hop: int = 1,
    max_hops: int = 30,
    timeout: float = 2.0,
    privileged: bool = False,
    resolve: bool = True,
) -> list[Hop]:
    """Returns the path (the hops) to the given address.

    `icmplib.traceroute` is synchronous, so we run it in a thread and the event
    loop is never blocked. Fault-tolerant: if the name does not resolve, or the
    path breaks somewhere, it returns an empty or partial list (it never raises).
    """
    result = await trace_path(
        address,
        first_hop=first_hop,
        max_hops=max_hops,
        timeout=timeout,
        privileged=privileged,
        resolve=resolve,
    )
    return result.hops


async def trace_path(
    address: str,
    first_hop: int = 1,
    max_hops: int = 30,
    timeout: float = 2.0,
    privileged: bool = False,
    resolve: bool = True,
) -> TraceResult:
    """The error-reporting variant of `traceroute`: returns a TraceResult.

    If the name does not resolve or ICMP fails, the `error` field is filled in
    with a message and `hops` comes back empty (so the CLI can display it).
    """
    if _platform.IS_WINDOWS:
        raw_hops: list[_HopLike] = await _win_traceroute(
            address, max_hops=max_hops, timeout=timeout
        )
        if not raw_hops:
            return TraceResult(
                address=address,
                hops=[],
                error=(
                    "Traceroute returned nothing (host unreachable, or the name did not resolve)."
                ),
            )
        hops = await _map_hops(raw_hops, resolve=resolve)
        return TraceResult(address=address, hops=hops)

    try:
        raw_hops = await asyncio.to_thread(
            _sync_traceroute,
            address,
            first_hop=first_hop,
            max_hops=max_hops,
            timeout=timeout,
            privileged=privileged,
        )
    except NameLookupError:
        return TraceResult(
            address=address,
            hops=[],
            error=f"Could not resolve the name '{address}' to an IP address (DNS error).",
        )
    except ICMPLibError as exc:
        # `SocketPermissionError` (inherits from ICMPLibError) — on macOS/Linux
        # setting the TTL needs a raw socket, which `privileged=False` cannot
        # give us. Ping, on the other hand, works over a datagram socket, so you
        # land in the "ping works but traceroute does not" state. The system
        # `traceroute` binary ships setuid/CAP_NET_RAW and demands no sudo — so
        # we fall back to it.
        raw_hops = await _posix_traceroute(address, max_hops=max_hops, timeout=timeout)
        if not raw_hops:
            return TraceResult(
                address=address,
                hops=[],
                error=(
                    f"Traceroute failed: {exc}. The system `traceroute` command "
                    "returned nothing either — check that it is installed."
                ),
            )
    except OSError as exc:
        return TraceResult(address=address, hops=[], error=f"Network error: {exc}")

    hops = await _map_hops(raw_hops, resolve=resolve)
    return TraceResult(address=address, hops=hops)


async def _map_hops(raw_hops: list[_HopLike], resolve: bool) -> list[Hop]:
    """Converts raw hop objects (icmplib or Windows) into a list of `Hop`.

    If `resolve` is True, reverse DNS is also done for the hops that have an
    address.
    """
    hops: list[Hop] = []
    for h in raw_hops:
        hop = Hop(
            index=h.distance,
            address=h.address,
            rtt_ms=h.avg_rtt,
            alive=h.is_alive,
        )
        if resolve and hop.address:
            hop.hostname = await _reverse_dns(hop.address)
        hops.append(hop)
    return hops


async def _probe_path(
    address: str,
    first_hop: int,
    max_hops: int,
    timeout: float,
    privileged: bool,
) -> list[_HopLike]:
    """One probe: calls `icmplib.traceroute` in a thread and returns the raw hops.

    On error (DNS/ICMP/OS) it returns an empty list — it never raises, because it
    must not break `trace_stream` (the stream has to keep going). On Windows this
    is `tracert` (no admin needed); on macOS/Linux it is `icmplib`, and if that is
    refused permission, the system `traceroute` binary (setuid/CAP_NET_RAW — no
    sudo needed).
    """
    if _platform.IS_WINDOWS:
        return await _win_traceroute(address, max_hops=max_hops, timeout=timeout)
    try:
        raw_hops = await asyncio.to_thread(
            _sync_traceroute,
            address,
            first_hop=first_hop,
            max_hops=max_hops,
            timeout=timeout,
            privileged=privileged,
        )
    except ICMPLibError:
        # Setting the TTL needs a raw socket (macOS) — fall back to the system
        # binary, otherwise the live mtr returned an empty result on every cycle
        # and the panel just sat there empty.
        return await _posix_traceroute(address, max_hops=max_hops, timeout=timeout)
    except OSError:
        return []
    return list(raw_hops)


@dataclass(slots=True)
class _WinRawHop:
    """A Windows `tracert` hop — the same shape as `_HopLike` (the icmplib hop).

    `_map_hops`/`trace_stream` only read `distance`/`address`/`avg_rtt`/
    `is_alive`, so these four attributes are enough (duck typing).
    """

    distance: int
    address: str | None
    avg_rtt: float
    is_alive: bool


# POSIX `traceroute` output: " 1  192.168.10.1  3.590 ms  4.1 ms  3.9 ms"
# or an unanswered hop: " 3  * * *". With `-n` no names are resolved.
_POSIX_TR_RE = re.compile(
    r"^\s*(\d+)\s+(?:(\*[\s*]*)$|([0-9a-fA-F.:]+)(?:\s+\(([^)]+)\))?\s+([\d.]+)\s*ms)"
)


def parse_posix_traceroute(text: str) -> list[tuple[int, str | None, float, bool]]:
    """Parses the system `traceroute` output — a pure function (offline test).

    Returns tuples of `(hop_number, address, rtt_ms, alive)`.
    An unanswered hop (`* * *`) becomes `(n, None, 0.0, False)`.
    """
    hops: list[tuple[int, str | None, float, bool]] = []
    for line in text.splitlines():
        m = _POSIX_TR_RE.match(line)
        if not m:
            continue
        idx = int(m.group(1))
        if m.group(2):  # "* * *"
            hops.append((idx, None, 0.0, False))
            continue
        addr = m.group(3)
        rtt = float(m.group(5))
        hops.append((idx, addr, rtt, True))
    return hops


async def _posix_traceroute(
    address: str,
    max_hops: int = 30,
    timeout: float = 2.0,
) -> list[_HopLike]:
    """Measures the path via the system `traceroute` on macOS/Linux (root NOT needed).

    Why it is needed: on macOS `icmplib.traceroute(privileged=False)` raises
    `SocketPermissionError` — changing the TTL requires a **raw socket**, and a
    plain ICMP datagram socket cannot do it. Ping does work over a datagram, so
    ping kept working while traceroute stayed broken (the TUI said "No path
    found." — the state the user actually saw).

    The fix: on macOS `/usr/sbin/traceroute` is **setuid root**, and on Linux it
    normally ships with `CAP_NET_RAW` — both run without sudo. For IPv6,
    `traceroute6` is used.

    If the command is missing or fails — an empty list (no exception).
    """
    is_v6 = ":" in address
    wait = max(1, int(timeout))
    # `-n` skips name resolution (fast), `-q 1` sends one probe per hop.
    base_args = ["-n", "-m", str(max_hops), "-w", str(wait), "-q", "1", address]
    candidates = (
        [["traceroute6", *base_args], ["/usr/sbin/traceroute6", *base_args]]
        if is_v6
        else [["traceroute", *base_args], ["/usr/sbin/traceroute", *base_args]]
    )

    overall = timeout * max_hops + 5.0
    for cmd in candidates:
        out = await _platform.run_command(cmd, timeout=overall)
        if not out:
            continue
        parsed = parse_posix_traceroute(out)
        if parsed:
            return [
                _WinRawHop(distance=idx, address=addr, avg_rtt=rtt, is_alive=alive)
                for (idx, addr, rtt, alive) in parsed
            ]
    return []


async def _win_traceroute(
    address: str,
    max_hops: int = 30,
    timeout: float = 2.0,
) -> list[_HopLike]:
    """Measures the path on Windows (no admin needed).

    Primary path: Win32 `IcmpSendEcho` + TTL (`_platform.win_icmp_traceroute`) —
    independent of language/codepage, with no text parsing (IPv4).

    Fallback path: if `IcmpSendEcho` is unavailable, or the address does not
    resolve to IPv4, we parse the output of
    `tracert -d -h <max_hops> -w <ms> <address>` with the LANGUAGE-INDEPENDENT
    `parse_windows_tracert`. Either way a list of `_WinRawHop` comes back
    (`_map_hops`/`trace_stream` read that shape). If neither works — an empty
    list.
    """
    # 1) Primary path: IcmpSendEcho + TTL (IPv4, independent of language/codepage).
    icmp = await asyncio.to_thread(_platform.win_icmp_traceroute, address, max_hops, timeout)
    if icmp is not None:
        return [
            _WinRawHop(distance=idx, address=addr, avg_rtt=rtt, is_alive=alive)
            for (idx, addr, rtt, alive) in icmp
        ]

    # 2) Fallback path: the system `tracert.exe` + language-independent parsing.
    wait_ms = max(1, int(timeout * 1000))
    cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(wait_ms), address]
    # tracert may wait `-w` on every hop -> the overall timeout is wider.
    overall = timeout * max_hops + 5.0
    out = await _platform.run_command(cmd, timeout=overall)
    if not out:
        return []
    parsed = _platform.parse_windows_tracert(out)
    return [
        _WinRawHop(distance=idx, address=addr, avg_rtt=rtt, is_alive=alive)
        for (idx, addr, rtt, alive) in parsed
    ]


@dataclass(slots=True)
class _WinHost:
    """A Windows LAN sweep host result — fits the `_HostLike` shape (duck typing)."""

    address: str
    is_alive: bool
    avg_rtt: float = 0.0


# Number of parallel `ping` processes in a Windows LAN sweep (resource cap).
_WIN_SWEEP_CONCURRENCY = 64


async def _win_multiping(hosts: list[str], timeout: float) -> list[_HostLike]:
    """A /24 ping sweep on Windows: one `ping -n 1` per host (bounded concurrency).

    Stands in for `async_multiping` on Windows. Checks each host separately via
    `_win_ping` (ping.py); the semaphore caps how many processes run at once
    (which stops a large network from blowing up resource usage).
    """
    # Late import: prevents the circular ping <-> topology import.
    from systop.core.ping import _win_ping

    sem = asyncio.Semaphore(_WIN_SWEEP_CONCURRENCY)

    async def probe(host: str) -> _WinHost:
        async with sem:
            alive, rtts, _loss = await _win_ping(host, count=1, timeout=timeout)
        avg = (sum(rtts) / len(rtts)) if rtts else 0.0
        return _WinHost(address=host, is_alive=alive, avg_rtt=avg)

    if not hosts:
        return []
    return await asyncio.gather(*(probe(h) for h in hosts))


async def trace_stream(
    address: str,
    first_hop: int = 1,
    max_hops: int = 30,
    timeout: float = 2.0,
    privileged: bool = False,
    resolve: bool = True,
    interval: float = 1.0,
    cycles: int | None = None,
) -> AsyncIterator[list[HopStat]]:
    """A live traceroute in the style of mtr/trippy: it probes the path over and over.

    Every `interval` seconds the whole path is measured again, and the
    cumulative `HopStat` for each hop (sent, recv, loss%, last/avg/best/worst
    rtt) is updated and `yield`ed as a list. The caller gets the very latest
    state on each iteration.

    `cycles` — how many times to probe (None means endless; stopping is the
    caller's business, via CancelledError). The stats are keyed stably by `index`
    (the hop distance) — so they keep accumulating even if the path changes.

    Note: one full probe is awaited before the first `yield` (so the path can be
    determined). Reverse DNS is only done for an address the first time it is
    seen.
    """
    stats: dict[int, HopStat] = {}
    cycle = 0
    while cycles is None or cycle < cycles:
        start = asyncio.get_running_loop().time()
        raw_hops = await _probe_path(address, first_hop, max_hops, timeout, privileged)
        for h in raw_hops:
            idx = h.distance
            stat = stats.get(idx)
            if stat is None:
                stat = HopStat(index=idx)
                stats[idx] = stat
            had_address = stat.address is not None
            stat.update(h.address, h.is_alive, h.avg_rtt)
            if resolve and stat.address and not had_address and stat.hostname is None:
                stat.hostname = await _reverse_dns(stat.address)
        ordered = [stats[i] for i in sorted(stats)]
        yield ordered

        cycle += 1
        if cycles is not None and cycle >= cycles:
            break
        elapsed = asyncio.get_running_loop().time() - start
        sleep_for = interval - elapsed
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


async def lan_cidrs(all_interfaces: bool = True) -> list[str]:
    """The list of IPv4 networks to scan — a near-pure helper.

    With `all_interfaces=True` the network of **every active interface** is
    returned (Wi-Fi + Ethernet + VPN can all be connected at once, and scanning
    just one of them makes the rest invisible). With `False`, only the primary
    interface.

    Duplicates are removed: if two interfaces sit on the same network there is
    no need to scan it twice.
    """
    ifaces = netinfo.list_interfaces()
    if not all_interfaces:
        primary = netinfo.primary_interface()
        ifaces = [primary] if primary else []
    out: list[str] = []
    for iface in ifaces:
        if iface and iface.cidr and iface.cidr not in out:
            out.append(iface.cidr)
    return out


async def discover_lan(
    cidr: str | None = None,
    timeout: float = 1.0,
    max_hosts: int = 256,
    resolve: bool = False,
    all_interfaces: bool = False,
) -> list[LanHost]:
    """Finds the alive hosts on the local network (a ping sweep + the ARP table).

    `all_interfaces=True` — the networks of every active interface are scanned
    (when no `cidr` is given). That matters on a machine attached to several
    networks (Wi-Fi + cable + VPN): scanning one network and concluding "that is
    all of them" would be wrong.
    """
    if cidr is None and all_interfaces:
        cidrs = await lan_cidrs(all_interfaces=True)
        if not cidrs:
            return []
        seen: dict[str, LanHost] = {}
        for net in cidrs:
            for host in await discover_lan(
                cidr=net, timeout=timeout, max_hosts=max_hosts, resolve=resolve
            ):
                seen.setdefault(host.ip, host)
        return sorted(seen.values(), key=lambda h: ipaddress.ip_address(h.ip))

    if cidr is None:
        iface = netinfo.primary_interface()
        cidr = iface.cidr if iface else None
    if not cidr:
        return []

    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()][:max_hosts]
    if not hosts:
        return []

    gateway = netinfo.default_gateway()
    if _platform.IS_WINDOWS:
        results: list[_HostLike] = await _win_multiping(hosts, timeout=timeout)
    else:
        results = await async_multiping(hosts, count=1, timeout=timeout, privileged=False)
    arp_table = _parse_arp_table()

    found: list[LanHost] = []
    for host in results:
        if not host.is_alive:
            continue
        mac = arp_table.get(host.address)
        entry = LanHost(
            ip=host.address,
            mac=mac,
            rtt_ms=host.avg_rtt,
            is_gateway=(host.address == gateway),
            vendor=oui.lookup_vendor(mac),
        )
        if resolve:
            entry.hostname = await _reverse_dns(host.address)
        found.append(entry)

    # We also add the hosts that are in the ARP table but did not answer the ping.
    seen = {h.ip for h in found}
    for ip, mac in arp_table.items():
        if ip not in seen and ipaddress.ip_address(ip) in network:
            found.append(
                LanHost(
                    ip=ip,
                    mac=mac,
                    is_gateway=(ip == gateway),
                    vendor=oui.lookup_vendor(mac),
                )
            )

    found.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return found


def parse_ndp_output(text: str, windows: bool = False) -> dict[str, str]:
    """{ip: mac} from the IPv6 neighbour table output — a pure function (offline test).

    Three formats are supported: macOS `ndp -an`, Linux `ip -6 neigh`, and
    Windows `netsh interface ipv6 show neighbors`. In every case the MAC is
    normalised to lower case with a ':' separator (the same look as the IPv4
    ARP table).

    The zone suffix (`fe80::1%en0`) is **preserved** — a link-local address is
    unusable without its zone (pinging/connecting needs the interface).

    Incomplete entries (MAC "incomplete"/empty) are dropped.
    """
    table: dict[str, str] = {}
    for line in text.splitlines():
        if windows:
            m = _NEIGH6_WIN_RE.match(line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
        else:
            m = _NEIGH6_RE.match(line.strip()) or _NDP_RE.match(line.strip())
            if not m:
                continue
            ip, mac = m.group(1), m.group(2).lower()
        # We skip the header lines and the invalid entries.
        if ip.lower() in ("neighbor", "internet") or ":" not in ip:
            continue
        table[ip] = _normalize_mac(mac)
    return table


def _read_ndp_table() -> dict[str, str]:
    """Reads the OS IPv6 neighbour table (macOS/Linux/Windows). Errors are swallowed."""
    if _platform.IS_WINDOWS:
        try:
            raw = subprocess.run(
                ["netsh", "interface", "ipv6", "show", "neighbors"],
                capture_output=True,
                timeout=5,
                creationflags=_platform.subprocess_flags(),
            ).stdout
        except (subprocess.SubprocessError, OSError):
            return {}
        return parse_ndp_output(_platform.decode_console(raw), windows=True)

    for cmd in (["ip", "-6", "neigh"], ["ndp", "-an"]):
        try:
            raw = subprocess.run(cmd, capture_output=True, timeout=5).stdout
        except (subprocess.SubprocessError, OSError):
            continue
        table = parse_ndp_output(_platform.decode_console(raw))
        if table:
            return table
    return {}


async def _ping_all_nodes(timeout: float = 2.0) -> None:
    """Sends a multicast ping to `ff02::1` — to "fill up" the neighbour table.

    The replies are not read (each OS prints them differently); the point is to
    force the hosts to answer and then read the neighbour table. That is why
    errors are swallowed entirely: even without ping6 the discovery still works
    off the ARP/NDP table (a graceful degrade).

    The interface zone is mandatory — the OS does not know by itself which
    interface a link-local multicast should go out of.
    """
    iface = netinfo.primary_interface()
    zone = f"%{iface.name}" if iface and iface.name else ""
    target = f"{ALL_NODES_MULTICAST}{zone}"

    if _platform.IS_WINDOWS:
        cmds = [["ping", "-6", "-n", "2", "-w", "1000", target]]
    else:
        # macOS: ping6; Linux (a recent iputils): ping -6. We try both.
        cmds = [
            ["ping6", "-c", "2", "-i", "0.3", target],
            ["ping", "-6", "-c", "2", "-i", "0.3", target],
        ]

    for cmd in cmds:
        try:
            await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                timeout=timeout + 1.0,
                **({"creationflags": _platform.subprocess_flags()} if _platform.IS_WINDOWS else {}),
            )
            return
        except (subprocess.SubprocessError, OSError):
            continue


async def discover_lan6(
    timeout: float = 2.0,
    resolve: bool = False,
    include_link_local: bool = True,
) -> list[LanHost]:
    """Finds the IPv6 hosts on the local network (a multicast ping + the NDP table).

    **Why this differs from IPv4:** an IPv6 network is normally a /64 — that is
    18 quintillion addresses, so a ping sweep is impossible. The standard
    approach (RFC 4291): ping `ff02::1` (the "all nodes" link-local multicast)
    and read whoever answered out of the OS neighbour table.

    With `include_link_local=False` the fe80::/10 addresses are dropped (only
    global/ULA remain — the addresses that cross a router).

    No root needed: the multicast ping goes out through the system `ping6`/
    `ping -6`, and the table is read from `ip -6 neigh`/`ndp -an`/`netsh`.
    """
    await _ping_all_nodes(timeout=timeout)
    table = _read_ndp_table()

    gateway = netinfo.default_gateway()
    found: list[LanHost] = []
    for ip, mac in table.items():
        host = LanHost(
            ip=ip,
            mac=mac,
            is_gateway=(ip.split("%")[0] == gateway),
            vendor=oui.lookup_vendor(mac),
            family="ipv6",
            source="ndp",
        )
        if not include_link_local and host.is_link_local:
            continue
        if resolve:
            host.hostname = await _reverse_dns(ip.split("%")[0])
        found.append(host)

    found.sort(key=_ipv6_sort_key)
    return found


def _ipv6_sort_key(host: LanHost) -> tuple[int, object]:
    """A stable sort order for IPv6 hosts (an invalid address lands at the end)."""
    try:
        return (0, ipaddress.ip_address(host.ip.split("%")[0]))
    except ValueError:
        return (1, host.ip)


def _parse_arp_table() -> dict[str, str]:
    """Reads an {ip: mac} dict out of the OS ARP table (Windows/macOS/Linux).

    macOS/Linux: `arp -a` (the IP in brackets, the MAC with ':'), or `ip neigh`
    as the fallback. Windows: `arp -a` (the MAC with dashes, a
    "dynamic/static" type). In every case the MAC is normalised to lower case
    with a ':' separator (oui.lookup_vendor accepts either separator, but what
    we store should be uniform).

    If the command is missing (`FileNotFoundError`) or fails, that is swallowed
    cleanly and we move on to the next command (a graceful degrade on every
    platform).
    """
    if _platform.IS_WINDOWS:
        return _parse_arp_table_windows()

    table: dict[str, str] = {}
    # `-n` (numeric) is MANDATORY: `arp -a` does a reverse DNS lookup for every
    # entry, and on a large network (a /23 with ~280 entries, say) that takes 5+
    # seconds — it hit the timeout and returned an EMPTY table, so the
    # MAC/vendor columns came out completely blank. `arp -an` gives exactly the
    # same data in ~9 ms.
    for cmd in (["arp", "-an"], ["ip", "-4", "neigh"]):
        try:
            raw = subprocess.run(cmd, capture_output=True, timeout=10).stdout
        except (subprocess.SubprocessError, OSError):
            continue
        out = _platform.decode_console(raw)
        for line in out.splitlines():
            m = _ARP_RE.search(line) or _NEIGH_RE.search(line)
            if m:
                table[m.group(1)] = _normalize_mac(m.group(2))
        if table:
            break
    return table


def _normalize_mac(mac: str) -> str:
    """Brings a MAC to lower case with two-digit octets.

    macOS `arp` writes them short (`0:15:5d:27:40:3`), whereas the OUI table
    expects the full form — without the padding the vendor is **never** found
    (`c0:6:c3:2:63:55` -> None, `c0:06:c3:02:63:55` -> TP-Link).
    """
    return ":".join(part.zfill(2) for part in mac.lower().split(":"))


def _parse_arp_table_windows() -> dict[str, str]:
    """{ip: mac} from Windows `arp -a` output (the MAC with ':', lower case).

    The output is taken as bytes and decoded with `decode_console` (the OEM
    codepage) — so the IP/MAC are read correctly on a Russian console too.
    CREATE_NO_WINDOW keeps the console window from flashing up.
    """
    table: dict[str, str] = {}
    try:
        raw = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            timeout=3,
            creationflags=_platform.subprocess_flags(),
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return table
    out = _platform.decode_console(raw)
    for line in out.splitlines():
        m = _ARP_WIN_RE.search(line)
        if m:
            # "00-11-22-33-44-55" -> "00:11:22:33:44:55" (so storage is uniform).
            table[m.group(1)] = m.group(2).replace("-", ":").lower()
    return table


async def _reverse_dns(address: str, timeout: float = 1.0) -> str | None:
    """Best-effort reverse DNS (PTR) — errors are swallowed."""
    try:
        result = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, address), timeout)
        return result[0]
    except (TimeoutError, socket.herror, socket.gaierror, OSError):
        return None
