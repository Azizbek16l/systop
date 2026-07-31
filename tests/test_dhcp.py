"""Offline tests for `core/dhcp.py` — lease parsing and rogue-server detection.

Every parser is pure: it takes OS output or a raw packet and returns a
`DhcpOffer`. `discover_servers` is not tested — it sends a UDP broadcast.

All three operating systems are covered: macOS `ipconfig getpacket`, Linux
`dhclient.leases`, and a raw DHCP packet (the Windows route goes through
`netsh`, but the shape of the data is the same `DhcpOffer`).
"""

import struct

from systop.core.dhcp import (
    DhcpOffer,
    DhcpReport,
    build_discover,
    parse_dhclient_lease,
    parse_ipconfig_getpacket,
    parse_offer,
)

# --------------------------------------------------------------------------- #
# The DISCOVER packet
# --------------------------------------------------------------------------- #


def test_discover_packet_core_fields():
    packet, xid = build_discover()
    assert len(packet) >= 240
    assert packet[0] == 1  # op = BOOTREQUEST
    # The magic cookie 99.130.83.99 starts at byte 236 (RFC 2131).
    assert packet[236:240] == bytes([99, 130, 83, 99])
    # The xid must sit in bytes 4:8 of the packet.
    assert struct.unpack("!I", packet[4:8])[0] == xid


def test_discover_xid_differs_every_time():
    """The xid is the only thing tying a reply to a request; a fixed one is pointless."""
    xids = {build_discover()[1] for _ in range(20)}
    assert len(xids) > 15


def test_a_supplied_xid_is_used():
    _, xid = build_discover(xid=0xDEADBEEF)
    assert xid == 0xDEADBEEF


# --------------------------------------------------------------------------- #
# A raw reply packet — the xid check
# --------------------------------------------------------------------------- #


def _reply(xid: int, server_id: str = "192.168.1.1") -> bytes:
    """A minimal DHCPOFFER packet."""
    p = bytearray(240)
    p[0] = 2  # BOOTREPLY
    p[4:8] = struct.pack("!I", xid)
    p[16:20] = bytes(int(x) for x in "192.168.1.50".split("."))  # yiaddr
    p[236:240] = bytes([99, 130, 83, 99])
    opts = bytearray()
    opts += bytes([53, 1, 2])  # option 53: DHCPOFFER
    opts += bytes([54, 4]) + bytes(int(x) for x in server_id.split("."))
    opts += bytes([255])
    return bytes(p + opts)


def test_reply_with_a_different_xid_is_rejected():
    """A reply to some other request (or a forged one) must not be accepted."""
    assert parse_offer(_reply(0x1111), "192.168.1.1", expect_xid=0x2222) is None


def test_reply_with_the_matching_xid_is_accepted():
    o = parse_offer(_reply(0x1234), "192.168.1.1", expect_xid=0x1234)
    assert o is not None
    assert o.server_id == "192.168.1.1"
    assert o.offered_ip == "192.168.1.50"


def test_xid_check_is_optional():
    """With expect_xid=None nothing is checked (passive listening mode)."""
    assert parse_offer(_reply(0x1234), "192.168.1.1") is not None


# --------------------------------------------------------------------------- #
# macOS `ipconfig getpacket en0`
# --------------------------------------------------------------------------- #

GETPACKET = """op = BOOTREPLY
htype = 1
yiaddr = 192.168.11.43
siaddr = 0.0.0.0
options:
server_identifier (ip): 192.168.11.1
subnet_mask (ip): 255.255.255.0
router (ip_mult): {192.168.11.1}
domain_name_server (ip_mult): {192.168.10.1, 8.8.8.8}
domain_name (string): example.local
lease_time (uint32): 0x15180
"""


def test_getpacket_core_fields():
    o = parse_ipconfig_getpacket(GETPACKET)
    assert o is not None
    assert o.server_id == "192.168.11.1"
    assert o.offered_ip == "192.168.11.43"
    assert o.subnet_mask == "255.255.255.0"
    assert o.routers == ["192.168.11.1"]
    assert o.dns == ["192.168.10.1", "8.8.8.8"]
    assert o.domain == "example.local"


def test_getpacket_lease_is_hexadecimal():
    """macOS gives lease_time as `0x15180` — that is 86400 seconds."""
    o = parse_ipconfig_getpacket(GETPACKET)
    assert o.lease_seconds == 86400


def test_getpacket_without_server_identifier_is_none():
    """Without a server ID the offer is meaningless — None, not an empty object."""
    assert parse_ipconfig_getpacket("yiaddr = 1.2.3.4\n") is None


# --------------------------------------------------------------------------- #
# Linux `dhclient.leases` — the MOST RECENT block
# --------------------------------------------------------------------------- #

LEASES = """
lease {
  interface "eth0";
  fixed-address 10.0.0.99;
  option subnet-mask 255.255.0.0;
  option routers 10.0.0.254;
  option domain-name-servers 10.0.0.254;
  option dhcp-server-identifier 10.0.0.254;
  option dhcp-lease-time 3600;
  renew 1 2026/07/01 10:00:00;
}
lease {
  interface "eth0";
  fixed-address 192.168.5.20;
  option subnet-mask 255.255.255.0;
  option routers 192.168.5.1;
  option domain-name-servers 192.168.5.1, 1.1.1.1;
  option domain-name "corp.local";
  option dhcp-server-identifier 192.168.5.1;
  option dhcp-lease-time 43200;
  renew 2 2026/07/31 12:00:00;
}
"""


def test_the_most_recent_lease_is_taken():
    """The file appends blocks ONE AFTER ANOTHER — the current lease is the LAST.

    Taking the first one showed an old (already expired) network and gave the
    completely wrong answer "your DHCP server is 10.0.0.254".
    """
    o = parse_dhclient_lease(LEASES)
    assert o is not None
    assert o.server_id == "192.168.5.1"
    assert o.offered_ip == "192.168.5.20"
    assert o.lease_seconds == 43200


def test_lease_list_fields():
    o = parse_dhclient_lease(LEASES)
    assert o.dns == ["192.168.5.1", "1.1.1.1"]
    assert o.routers == ["192.168.5.1"]


def test_lease_domain_is_unquoted():
    o = parse_dhclient_lease(LEASES)
    assert o.domain == "corp.local"


def test_empty_lease_file_is_none():
    assert parse_dhclient_lease("") is None
    assert parse_dhclient_lease("# comment\n") is None


def test_lease_without_server_identifier_is_none():
    assert parse_dhclient_lease("lease {\n  fixed-address 1.2.3.4;\n}\n") is None


# --------------------------------------------------------------------------- #
# Rogue DHCP detection
# --------------------------------------------------------------------------- #


def test_a_single_server_is_not_rogue():
    r = DhcpReport(
        offers=[
            DhcpOffer(server_ip="192.168.1.1", server_id="192.168.1.1"),
            DhcpOffer(server_ip="192.168.1.1", server_id="192.168.1.1"),  # a repeated reply
        ]
    )
    assert r.servers == ["192.168.1.1"]
    assert r.is_rogue_suspected is False


def test_two_different_servers_raise_a_rogue_suspicion():
    """Two DHCP servers — the classic cause of "the internet keeps cutting out"."""
    r = DhcpReport(
        offers=[
            DhcpOffer(server_ip="192.168.1.1", server_id="192.168.1.1"),
            DhcpOffer(server_ip="192.168.1.77", server_id="192.168.1.77"),
        ]
    )
    assert len(r.servers) == 2
    assert r.is_rogue_suspected is True


def test_identity_prefers_the_server_id():
    """In a packet via a relay the source IP is the relay's, the server ID the original.

    Distinguishing by source IP made a single server behind a relay look like
    two and produced a false "rogue DHCP" warning.
    """
    o = DhcpOffer(server_ip="10.0.0.254", server_id="192.168.1.1")
    assert o.identity == "192.168.1.1"
    r = DhcpReport(
        offers=[
            DhcpOffer(server_ip="10.0.0.254", server_id="192.168.1.1"),
            DhcpOffer(server_ip="10.0.9.254", server_id="192.168.1.1"),
        ]
    )
    assert r.is_rogue_suspected is False


def test_no_reply_does_not_mean_no_server():
    """`partial` means "listening finished, no reply arrived". That is NOT "no server".

    On many networks the DHCP reply goes to the client port (68), which cannot
    be bound without root. Presenting that as "no DHCP server found" would be a
    false signal.
    """
    r = DhcpReport(offers=[], partial=True)
    assert r.servers == []
    assert r.is_rogue_suspected is False
