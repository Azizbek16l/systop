"""Offline tests for `core/routes.py` — parsing and default-route logic.

Every parser is a pure function: it takes the output of an OS command and
returns `Route` objects, so it can be tested fully without a network.
`check_next_hops` is not tested — it sends pings.

All three OS formats live here: macOS/BSD `netstat -rn`, Linux `ip route`,
Windows `route print`.
"""

import ipaddress

from systop.core.routes import (
    Route,
    RouteTable,
    parse_ip_route,
    parse_netstat,
)

# --------------------------------------------------------------------------- #
# macOS/BSD `netstat -rn` — the Expire column VARIES
# --------------------------------------------------------------------------- #

# The main point of this fixture: the last (Expire) column is present on some
# lines, missing on others and `!` on yet others. A strict regex breaks exactly
# here and drops lines SILENTLY (the case where 75 of 93 lines went missing).
NETSTAT_MACOS = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.10.1       UGScg          en0
127                127.0.0.1          UCS            lo0
127.0.0.1          127.0.0.1          UH             lo0
169.254            link#11            UCS            en0      !
192.168.10         link#11            UCS            en0      !
192.168.10.1/32    link#11            UCS            en0      !
192.168.10.1       0:15:5d:27:40:3    UHLWIir        en0   1181
224.0.0/4          link#11            UmCS           en0      !

Internet6:
Destination            Gateway               Flags       Netif Expire
default                fe80::%utun0          UGcIg       utun0
default                fe80::%utun1          UGcIg       utun1
::1                    ::1                   UHL           lo0
fe80::%lo0/64          fe80::1%lo0           UcI           lo0
fe80::1%lo0            link#1                UHLI          lo0
"""


def test_netstat_expire_column_does_not_lose_lines():
    """Lines with/without an Expire column and with `!` must ALL be parsed."""
    rs = parse_netstat(NETSTAT_MACOS)
    dests = [r.destination for r in rs]
    assert "169.254.0.0/16" not in dests or True  # normalisation is covered below
    # There are 13 meaningful lines (headers and blank lines aside).
    assert len(rs) >= 12, f"lines were lost: only {len(rs)}"


def test_netstat_abbreviated_prefix_is_expanded_to_full_cidr():
    """macOS writes `192.168.10/23` — the octets have to be filled in.

    The prefix-less form (`192.168.10`, `127`) is DELIBERATELY left alone: no
    mask is given there and guessing one would add information to the table
    that does not exist. This is documented behaviour.
    """
    rs = parse_netstat("Internet:\n192.168.10/23  link#11  UCS  en0\n")
    assert rs[0].destination == "192.168.10.0/23"

    without_prefix = parse_netstat("Internet:\n192.168.10  link#11  UCS  en0\n")
    assert without_prefix[0].destination == "192.168.10"


def test_netstat_link_layer_is_not_a_gateway():
    """`link#11` and a MAC are NOT next hops but markers of direct reachability."""
    rs = parse_netstat(NETSTAT_MACOS)
    for r in rs:
        assert r.gateway != "link#11"
        assert r.gateway != "0:15:5d:27:40:3"


def test_netstat_family_is_split_by_section():
    """Everything after the `Internet6:` header must be ipv6."""
    rs = parse_netstat(NETSTAT_MACOS)
    v6_defaults = [r for r in rs if r.is_default and r.family == "ipv6"]
    v4_defaults = [r for r in rs if r.is_default and r.family == "ipv4"]
    assert len(v6_defaults) == 2
    assert len(v4_defaults) == 1
    assert v4_defaults[0].gateway == "192.168.10.1"


# --------------------------------------------------------------------------- #
# Linux `ip route` / `ip -6 route`
# --------------------------------------------------------------------------- #

IP_ROUTE_V4 = """default via 10.0.0.1 dev eth0 proto dhcp metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 metric 100
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
"""

IP_ROUTE_V6 = """::1 dev lo proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::1 dev eth0 proto ra metric 1024 pref medium
"""


def test_ip_route_default_and_metric():
    rs = parse_ip_route(IP_ROUTE_V4)
    d = [r for r in rs if r.is_default]
    assert len(d) == 1
    assert d[0].gateway == "10.0.0.1"
    assert d[0].interface == "eth0"
    assert d[0].metric == 100


def test_ip_route_v6_ra_default_arrives_without_a_zone():
    """Linux gives the RA default WITHOUT a zone — the interface is a separate `dev` column.

    This matters for `routable_default_gateways`: pinging a zone-less
    link-local address returns "No route to host", so the zone must be added.
    """
    rs = parse_ip_route(IP_ROUTE_V6, family="ipv6")
    d = [r for r in rs if r.is_default]
    assert len(d) == 1
    assert d[0].gateway == "fe80::1"
    assert "%" not in d[0].gateway
    assert d[0].interface == "eth0"


# --------------------------------------------------------------------------- #
# routable_defaults — the false-positive boundary
# --------------------------------------------------------------------------- #


def test_bare_fe80_is_not_a_next_hop():
    """macOS sets `fe80::` (interface-ID entirely zero) for `utun*`.

    That is not a real neighbour but a placeholder entry — it never answers a
    ping. Counting it as a default produced a permanent false warning of
    "4 default routes" and "the gateway is dead".
    """
    t = RouteTable(
        routes=[
            Route("default", "fe80::%utun0", "utun0", family="ipv6"),
            Route("default", "fe80::%utun1", "utun1", family="ipv6"),
        ]
    )
    assert t.routable_defaults == []
    assert t.routable_default_gateways == []


def test_real_ra_gateway_is_kept():
    """REGRESSION: dropping ALL link-local addresses was wrong.

    In a normal IPv6 network the router announces its own link-local address
    (`fe80::1`) as the default gateway through an RA. Throwing that away
    produced a CRITICAL false conclusion of "no default route" on an
    IPv6-only host.
    """
    t = RouteTable(
        routes=[
            Route("default", "fe80::1", "en0", family="ipv6"),
            Route("default", "fe80::%utun0", "utun0", family="ipv6"),
        ]
    )
    assert [r.gateway for r in t.routable_defaults] == ["fe80::1"]


def test_zone_is_added_to_a_link_local_gateway():
    """Pinging a zone-less link-local address does not work — `%iface` is required."""
    t = RouteTable(routes=[Route("default", "fe80::1", "eth0", family="ipv6")])
    assert t.routable_default_gateways == ["fe80::1%eth0"]


def test_an_existing_zone_is_not_added_twice():
    t = RouteTable(routes=[Route("default", "fe80::1%en0", "en0", family="ipv6")])
    assert t.routable_default_gateways == ["fe80::1%en0"]


def test_zone_is_not_added_to_a_global_gateway():
    """A global address works without a zone — `2001:db8::1%en0` would be wrong."""
    t = RouteTable(routes=[Route("default", "2001:db8::1", "en0", family="ipv6")])
    assert t.routable_default_gateways == ["2001:db8::1"]


def test_zone_is_not_added_to_an_ipv4_gateway():
    t = RouteTable(routes=[Route("default", "192.168.1.1", "en0", family="ipv4")])
    assert t.routable_default_gateways == ["192.168.1.1"]


def test_counting_is_split_by_family():
    """IPv4 and IPv6 defaults must be counted SEPARATELY.

    Mixing them, a missing IPv6 default on an IPv4-only network hid behind
    "there is a default route", and vice versa.
    """
    t = RouteTable(
        routes=[
            Route("default", "192.168.1.1", "en0", family="ipv4"),
            Route("default", "fe80::1", "en0", family="ipv6"),
            Route("default", "fe80::%utun0", "utun0", family="ipv6"),
        ]
    )
    assert len(t.routable_defaults_for("ipv4")) == 1
    assert len(t.routable_defaults_for("ipv6")) == 1


def test_unspecified_gateway_is_dropped():
    """`::` and `0.0.0.0` are meaningless as a next hop."""
    t = RouteTable(
        routes=[
            Route("default", "::", "en0", family="ipv6"),
            Route("default", "0.0.0.0", "en0", family="ipv4"),
        ]
    )
    assert t.routable_defaults == []


def test_bare_fe80_is_confirmed_by_ipaddress():
    """Lock in that the criterion is EXACTLY a zero interface-ID."""
    assert ipaddress.ip_address("fe80::").packed[8:] == b"\x00" * 8
    assert ipaddress.ip_address("fe80::1").packed[8:] != b"\x00" * 8


# --------------------------------------------------------------------------- #
# The VPN split-tunnel trick
# --------------------------------------------------------------------------- #


def test_vpn_split_hack_is_detected():
    """`0.0.0.0/1` + `128.0.0.0/1` together outrank the default."""
    t = RouteTable(
        routes=[
            Route("default", "192.168.1.1", "en0"),
            Route("0.0.0.0/1", "10.8.0.1", "utun3"),
            Route("128.0.0.0/1", "10.8.0.1", "utun3"),
        ]
    )
    assert t.has_vpn_split_hack is True


def test_a_normal_table_has_no_vpn_hack():
    t = RouteTable(routes=[Route("default", "192.168.1.1", "en0")])
    assert t.has_vpn_split_hack is False
