"""Route table and next-hop reachability. No root required.

Why this is needed: part of every "the internet is down" complaint is really a
routing problem, and ping/DNS never show it —

  * **no default route** — everything stays on the local LAN;
  * **two default routes** (Wi-Fi + VPN, or two NICs, for example) — traffic
    goes one way sometimes and the other way at other times. The symptom is
    misleading: "sometimes it works, sometimes it doesn't";
  * **a dead next hop** — the table is correct but the gateway does not answer;
  * **a VPN that grabbed everything** (the 0.0.0.0/1 + 128.0.0.0/1 trick) —
    LAN resources disappear.

The table is read from an OS command (`netstat -rn` / `ip route` /
`route print`); the parsers are pure functions and are tested offline.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from systop.core import _platform

# macOS/BSD `netstat -rn` columns:
#   Destination  Gateway  Flags  Netif  [Expire]
# Splitting on columns DELIBERATELY, not a regex: the trailing "Expire" column
# may be empty, a number or `!`, and a strict regex could not accommodate that
# — as a result 75 of 93 lines were SILENTLY dropped (the route table looked
# almost empty). Splitting on columns tolerates such subtleties.

# Link-layer entries in the Gateway column (not a real next hop):
#   "link#11", "0:15:5d:27:40:3" (MAC), "52:73:db:7e:48:af"
_LINK_LAYER_RE = re.compile(r"^(link#\d+|[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})$")
# Linux `ip route`: "default via 10.0.0.1 dev eth0 proto dhcp metric 100"
#                   "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5"
_IPROUTE_RE = re.compile(
    r"^(default|[0-9a-fA-F.:/]+)"
    r"(?:\s+via\s+(\S+))?"
    r"\s+dev\s+(\S+)"
    r"(?:.*?\bmetric\s+(\d+))?"
)
# The IPv4 section of Windows `route print`:
#   "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25"
_ROUTE_WIN_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$"
)


@dataclass(slots=True)
class Route:
    """A single entry of the route table."""

    destination: str  # "default" or a CIDR
    gateway: str | None = None  # next hop (None on a link-local route)
    interface: str | None = None
    metric: int | None = None
    family: str = "ipv4"

    @property
    def is_default(self) -> bool:
        return self.destination in ("default", "0.0.0.0/0", "::/0", "0.0.0.0")

    @property
    def is_vpn_split_hack(self) -> bool:
        """`0.0.0.0/1` + `128.0.0.0/1` — the VPN trick for "beating" the default.

        Together these two routes cover the whole IPv4 space and, being more
        specific than the default (a longer prefix), they win. Even with a
        default route in the table the traffic goes to the VPN — which is why
        this is flagged separately.
        """
        return self.destination in ("0.0.0.0/1", "128.0.0.0/1")


@dataclass(slots=True)
class RouteTable:
    """The route table plus conclusions."""

    routes: list[Route] = field(default_factory=list)
    error: str | None = None

    @property
    def defaults(self) -> list[Route]:
        return [r for r in self.routes if r.is_default]

    @property
    def default_gateways(self) -> list[str]:
        """Unique default next-hop addresses (all of them, link-local included)."""
        out: list[str] = []
        for r in self.defaults:
            if r.gateway and r.gateway not in out:
                out.append(r.gateway)
        return out

    @property
    def routable_defaults(self) -> list[Route]:
        """Only MEANINGFUL default routes — empty placeholders are dropped.

        On macOS there are always several `utun*` interfaces (for VPN/relay
        services) and their IPv6 default sits there as a **bare**
        `fe80::%utunN` — that is, with the interface-ID part entirely zero.
        This is not a real neighbour but a placeholder entry; it never answers
        a ping. Counting them as "a dead gateway" or as "multiple default
        routes" produces a **false signal**.

        IMPORTANT: the discriminator is NOT **link-local-ness**, it is a
        **zero interface-ID**. Because in a normal IPv6 network the default
        gateway *is* link-local — the router announces its own `fe80::1%en0`
        address in an RA. Dropping every link-local next hop produced a
        CRITICAL false conclusion "no default route" on IPv6-only hosts, and
        the "multiple defaults" check did not work for IPv6 at all.
        """
        out: list[Route] = []
        for r in self.defaults:
            if not r.gateway:
                continue
            bare = r.gateway.split("%")[0]
            try:
                ip = ipaddress.ip_address(bare)
            except ValueError:
                out.append(r)
                continue
            if ip.version == 6 and ip.packed[8:] == b"\x00" * 8:
                continue  # bare fe80:: / :: — not a real next hop
            if ip.is_unspecified:
                continue
            out.append(r)
        return out

    @property
    def routable_default_gateways(self) -> list[str]:
        """Next-hop addresses in a pingable form.

        A link-local address **cannot be used without a zone** — `ping6 fe80::1`
        returns "No route to host", because the OS does not know which
        interface to leave through. macOS `netstat` appends the zone itself
        (`fe80::1%en0`), whereas Linux `ip -6 route` supplies it in a separate
        `dev eth0` column. So when the zone is missing we build it from the
        interface name — otherwise a healthy IPv6 gateway was marked "dead".
        """
        out: list[str] = []
        for r in self.routable_defaults:
            gw = r.gateway
            if gw is None:
                continue
            if "%" not in gw and r.interface:
                try:
                    if ipaddress.ip_address(gw).is_link_local:
                        gw = f"{gw}%{r.interface}"
                except ValueError:
                    pass
            if gw not in out:
                out.append(gw)
        return out

    def routable_defaults_for(self, family: str) -> list[Route]:
        """Meaningful defaults for a single family (`ipv4`/`ipv6`)."""
        return [r for r in self.routable_defaults if r.family == family]

    @property
    def has_vpn_split_hack(self) -> bool:
        return any(r.is_vpn_split_hack for r in self.routes)


def _norm_dest(dest: str) -> str:
    """Expand a macOS abbreviated network into a full CIDR ("192.168.10/23")."""
    if dest == "default":
        return "default"
    if "/" not in dest:
        return dest
    net, _, prefix = dest.partition("/")
    parts = net.split(".")
    if len(parts) < 4 and parts[0].isdigit():
        net = ".".join(parts + ["0"] * (4 - len(parts)))
    return f"{net}/{prefix}"


def parse_netstat(text: str) -> list[Route]:
    """Parse macOS/BSD `netstat -rn` output — pure function.

    Columns: `Destination Gateway Flags Netif [Expire]`. The last column is
    optional and comes in various shapes (a number, `!`, empty) — which is why
    we split on columns instead of using a strict regex.

    The Gateway column may hold `link#11` or a MAC — that is NOT a next hop but
    a marker of direct reachability on this segment. Such entries get
    `gateway=None`.
    """
    routes: list[Route] = []
    family = "ipv4"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith("internet6"):
            family = "ipv6"
            continue
        if low.startswith("internet"):
            family = "ipv4"
            continue
        if low.startswith(("destination", "routing tables")):
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue
        dest, gw = parts[0], parts[1]

        # Netif is the column after flags. The Expire column may or may not be
        # present, so we take the 4th column (when there is one).
        iface = parts[3] if len(parts) >= 4 else None

        gateway: str | None = None
        if not _LINK_LAYER_RE.match(gw) and ("." in gw or ":" in gw):
            gateway = gw

        is_v6 = family == "ipv6" or (":" in dest and not _LINK_LAYER_RE.match(dest))
        routes.append(
            Route(
                destination=_norm_dest(dest),
                gateway=gateway,
                interface=iface,
                family="ipv6" if is_v6 else "ipv4",
            )
        )
    return routes


def parse_ip_route(text: str, family: str = "ipv4") -> list[Route]:
    """Parse Linux `ip route` / `ip -6 route` output — pure function."""
    routes: list[Route] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("broadcast", "local", "unreachable")):
            continue
        m = _IPROUTE_RE.match(stripped)
        if not m:
            continue
        routes.append(
            Route(
                destination=m.group(1),
                gateway=m.group(2),
                interface=m.group(3),
                metric=int(m.group(4)) if m.group(4) else None,
                family=family,
            )
        )
    return routes


def parse_route_print(text: str) -> list[Route]:
    """Parse the IPv4 table of Windows `route print` — pure function."""
    routes: list[Route] = []
    for line in text.splitlines():
        m = _ROUTE_WIN_RE.match(line)
        if not m:
            continue
        dest, mask, gw, iface, metric = m.groups()
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        except ValueError:
            continue
        gateway = gw if gw.count(".") == 3 else None  # "On-link" -> None
        routes.append(
            Route(
                destination="default" if dest == "0.0.0.0" and prefix == 0 else f"{dest}/{prefix}",
                gateway=gateway,
                interface=iface,
                metric=int(metric),
            )
        )
    return routes


async def list_routes() -> RouteTable:
    """Read the OS route table (macOS/Linux/Windows). Never raises."""
    if _platform.IS_WINDOWS:
        out = await _platform.run_command(["route", "print", "-4"], timeout=8.0)
        if not out:
            return RouteTable(error="`route print` returned nothing")
        return RouteTable(routes=parse_route_print(out))

    # Linux: `ip route` is more precise (metric/dev), `netstat -rn` otherwise.
    out = await _platform.run_command(["ip", "route"], timeout=8.0)
    if out:
        routes = parse_ip_route(out, "ipv4")
        out6 = await _platform.run_command(["ip", "-6", "route"], timeout=8.0)
        if out6:
            routes += parse_ip_route(out6, "ipv6")
        if routes:
            return RouteTable(routes=routes)

    out = await _platform.run_command(["netstat", "-rn"], timeout=8.0)
    if not out:
        return RouteTable(error="could not read the route table")
    return RouteTable(routes=parse_netstat(out))


async def check_next_hops(table: RouteTable, timeout: float = 2.0) -> dict[str, bool]:
    """Check the reachability of the default next hops with a ping.

    Returns: {gateway_ip: alive}. The table can be correct while the gateway
    is dead — that situation only shows up in this check.

    Only `routable_default_gateways` are checked (so that link-local `utun*`
    routes do not produce a false "dead" result).
    """
    gws = table.routable_default_gateways
    if not gws:
        return {}
    from systop.core.ping import ping_many

    results = await ping_many({gw: gw for gw in gws}, count=2, timeout=timeout)
    return {r.address: r.alive for r in results}
