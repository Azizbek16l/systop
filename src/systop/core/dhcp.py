"""DHCP server detection — finding a "rogue DHCP". No root required (with limits).

Why this matters for a sysadmin: a **second DHCP server** appearing on the
network is one of the most common and most misleading causes of an outage —

  * someone plugs a home router into a LAN port and it starts handing out DHCP;
  * devices randomly pick up the **wrong gateway/DNS**;
  * the symptom: "some computers have internet, others don't", and reconnecting
    fixes it — because which server answers first is random;
  * ping/DNS diagnostics do not show this, because the problem is in the
    **configuration source**, not in connectivity.

## The honest limitation (without root)

A proper DHCP client binds to port 68, but a port below 1024 requires root.
This module therefore sends its DISCOVER to `255.255.255.255:67` **from an
ephemeral port** (`dhcping` uses the same technique). Most servers (ISC dhcpd,
dnsmasq, Windows DHCP) return the reply **to the port the request came from**
and we see it. A server that follows RFC 2131 strictly, however, sends the
reply only to port 68 — and then we see nothing. In other words: **a reply is
conclusive, the absence of one does NOT mean "no server".** That state is
reported distinctly (`replies` empty + `partial=True`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from systop.core import _platform

DHCP_SERVER_PORT = 67
BOOTP_REPLY = 2
MAGIC_COOKIE = b"\x63\x82\x53\x63"

# The DHCP options we care about (RFC 2132).
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_DOMAIN = 15

MSG_DISCOVER = 1
MSG_OFFER = 2

_MSG_NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}


@dataclass(slots=True)
class DhcpOffer:
    """An offer received from a single DHCP server."""

    server_ip: str  # the address the packet came from
    server_id: str | None = None  # option 54 (the real server identifier)
    offered_ip: str | None = None
    subnet_mask: str | None = None
    routers: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    domain: str | None = None
    lease_seconds: int | None = None
    msg_type: str | None = None
    elapsed_ms: float = 0.0

    @property
    def identity(self) -> str:
        """The key that distinguishes servers — server_id if present, else source IP."""
        return self.server_id or self.server_ip


@dataclass(slots=True)
class DhcpReport:
    """All replies plus the conclusion."""

    offers: list[DhcpOffer] = field(default_factory=list)
    listened_s: float = 0.0
    partial: bool = False  # no reply arrived, but that does not mean "no server"
    error: str | None = None

    @property
    def servers(self) -> list[str]:
        """Unique server identifiers."""
        out: list[str] = []
        for o in self.offers:
            if o.identity not in out:
                out.append(o.identity)
        return out

    @property
    def is_rogue_suspected(self) -> bool:
        """If several different servers replied — a rogue DHCP is likely."""
        return len(self.servers) > 1


def build_discover(mac: bytes | None = None, xid: int | None = None) -> tuple[bytes, int]:
    """Build a DHCPDISCOVER packet. Returns `(packet, xid)` — pure function.

    `xid` is the transaction identifier; it is needed to check that a reply is
    ours (so that another client's broadcast reply is not counted as our own).
    """
    if mac is None:
        # A locally-administered random MAC (first byte: unicast + local bit).
        mac = bytes([0x02]) + bytes(random.randrange(256) for _ in range(5))
    if xid is None:
        xid = random.randrange(1, 0xFFFFFFFF)

    pkt = bytearray()
    pkt += struct.pack("!BBBB", 1, 1, 6, 0)  # op=BOOTREQUEST, htype=Ethernet, hlen=6, hops=0
    pkt += struct.pack("!I", xid)
    pkt += struct.pack("!HH", 0, 0x8000)  # secs=0, flags=BROADCAST
    pkt += b"\x00" * 16  # ciaddr, yiaddr, siaddr, giaddr
    pkt += mac + b"\x00" * (16 - len(mac))  # chaddr
    pkt += b"\x00" * 64  # sname
    pkt += b"\x00" * 128  # file
    pkt += MAGIC_COOKIE
    pkt += bytes([OPT_MSG_TYPE, 1, MSG_DISCOVER])
    # Which options we ask for (option 55).
    pkt += bytes([55, 4, OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_DOMAIN])
    pkt += b"\xff"  # END
    return bytes(pkt), xid


def parse_offer(data: bytes, source_ip: str, expect_xid: int | None = None) -> DhcpOffer | None:
    """Parse a DHCP reply packet — pure function (offline test).

    If `expect_xid` is given and does not match, `None` is returned (so that
    another client's reply is not counted as our own).
    """
    if len(data) < 240 or data[0] != BOOTP_REPLY:
        return None
    xid = struct.unpack("!I", data[4:8])[0]
    if expect_xid is not None and xid != expect_xid:
        return None
    if data[236:240] != MAGIC_COOKIE:
        return None

    offer = DhcpOffer(server_ip=source_ip)
    yiaddr = data[16:20]
    if yiaddr != b"\x00\x00\x00\x00":
        offer.offered_ip = str(ipaddress.IPv4Address(yiaddr))

    i = 240
    while i < len(data):
        code = data[i]
        if code == 0xFF:  # END
            break
        if code == 0:  # PAD
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        val = data[i + 2 : i + 2 + length]
        if len(val) < length:
            break
        if code == OPT_MSG_TYPE and length == 1:
            offer.msg_type = _MSG_NAMES.get(val[0], str(val[0]))
        elif code == OPT_SERVER_ID and length == 4:
            offer.server_id = str(ipaddress.IPv4Address(val))
        elif code == OPT_SUBNET_MASK and length == 4:
            offer.subnet_mask = str(ipaddress.IPv4Address(val))
        elif code == OPT_ROUTER:
            offer.routers = [
                str(ipaddress.IPv4Address(val[j : j + 4])) for j in range(0, length - 3, 4)
            ]
        elif code == OPT_DNS:
            offer.dns = [
                str(ipaddress.IPv4Address(val[j : j + 4])) for j in range(0, length - 3, 4)
            ]
        elif code == OPT_DOMAIN:
            offer.domain = val.decode("utf-8", "replace").rstrip("\x00") or None
        elif code == OPT_LEASE_TIME and length == 4:
            offer.lease_seconds = struct.unpack("!I", val)[0]
        i += 2 + length
    return offer


async def discover_servers(listen_s: float = 4.0) -> DhcpReport:
    """Send a DHCPDISCOVER and collect every reply that arrives.

    If several replies arrive there are several DHCP servers on the network (a
    rogue is likely). If no reply arrives, `partial=True` — see the limitation
    in the module docstring, that does not mean "no server".
    """
    report = DhcpReport(listened_s=listen_s)
    loop = asyncio.get_running_loop()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))  # an ephemeral port — 68 would require root
        sock.setblocking(False)

        packet, xid = build_discover()
        start = time.perf_counter()
        await loop.sock_sendto(sock, packet, ("255.255.255.255", DHCP_SERVER_PORT))

        deadline = start + listen_s
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), timeout=remaining
                )
            except TimeoutError:
                break
            offer = parse_offer(data, addr[0], expect_xid=xid)
            if offer is not None:
                offer.elapsed_ms = (time.perf_counter() - start) * 1000.0
                report.offers.append(offer)
    except OSError as exc:
        report.error = f"socket error: {exc.strerror or exc}"
        return report
    finally:
        if sock is not None:
            sock.close()

    report.partial = not report.offers
    return report


# ===========================================================================
# Reading the active lease — the RELIABLE route without root
# ===========================================================================
#
# The broadcast probe (above) gets no reply from a strict RFC 2131 server. But
# the OS ITSELF has already taken an address from DHCP, and **which server**
# gave it is stored in the lease data. Reading that does not require root.
#
# The practical benefit: "did I get my address from the server I expected?" —
# that is the single most important sign of a rogue DHCP. It will not find a
# rogue server that stayed silent, but it does show precisely when the address
# ALREADY came from the wrong server.

_GETPACKET_RE = re.compile(r"^\s*(\w+)\s*(?:\([^)]*\))?\s*[:=]\s*(.+?)\s*$")


def parse_ipconfig_getpacket(text: str) -> DhcpOffer | None:
    """Parse macOS `ipconfig getpacket <iface>` output — pure function."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        m = _GETPACKET_RE.match(line)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip()
    server = fields.get("server_identifier")
    if not server:
        return None

    def _ips(raw: str | None) -> list[str]:
        if not raw:
            return []
        return [p for p in re.findall(r"\d+\.\d+\.\d+\.\d+", raw)]

    lease_raw = fields.get("lease_time")
    lease: int | None = None
    if lease_raw:
        try:
            lease = int(lease_raw, 16) if lease_raw.lower().startswith("0x") else int(lease_raw)
        except ValueError:
            lease = None

    return DhcpOffer(
        server_ip=server,
        server_id=server,
        offered_ip=(_ips(fields.get("yiaddr")) or [None])[0],
        subnet_mask=(_ips(fields.get("subnet_mask")) or [None])[0],
        routers=_ips(fields.get("router")),
        dns=_ips(fields.get("domain_name_server")),
        domain=fields.get("domain_name") or None,
        lease_seconds=lease,
        msg_type="ACK (active lease)",
    )


def parse_dhclient_lease(text: str) -> DhcpOffer | None:
    """Take the MOST RECENT lease from a Linux `dhclient.leases` file — pure function.

    The file appends lease blocks one after another; the last one counts as
    current.
    """
    blocks = re.findall(r"lease\s*\{(.*?)\}", text, re.DOTALL)
    if not blocks:
        return None
    body = blocks[-1]

    def opt(name: str) -> str | None:
        m = re.search(rf"option\s+{name}\s+([^;]+);", body)
        return m.group(1).strip() if m else None

    server = opt("dhcp-server-identifier")
    if not server:
        return None
    fixed = re.search(r"fixed-address\s+([^;]+);", body)
    lease_raw = opt("dhcp-lease-time")
    return DhcpOffer(
        server_ip=server,
        server_id=server,
        offered_ip=fixed.group(1).strip() if fixed else None,
        subnet_mask=opt("subnet-mask"),
        routers=re.findall(r"\d+\.\d+\.\d+\.\d+", opt("routers") or ""),
        dns=re.findall(r"\d+\.\d+\.\d+\.\d+", opt("domain-name-servers") or ""),
        domain=(opt("domain-name") or "").strip('"') or None,
        lease_seconds=int(lease_raw) if lease_raw and lease_raw.isdigit() else None,
        msg_type="ACK (active lease)",
    )


async def current_lease(interface: str | None = None) -> DhcpOffer | None:
    """Tell WHICH DHCP server this host got its address from (no root needed).

    macOS: `ipconfig getpacket <iface>`. Linux: dhclient lease files.
    Windows: the "DHCP Server" line of `ipconfig /all`.
    None if nothing is found (a static IP, or no lease data).
    """
    if interface is None:
        from systop.core import netinfo

        iface = netinfo.primary_interface()
        interface = iface.name if iface else None
    if not interface:
        return None

    if _platform.IS_MACOS:
        out = await _platform.run_command(["ipconfig", "getpacket", interface], timeout=5.0)
        return parse_ipconfig_getpacket(out) if out else None

    if _platform.IS_WINDOWS:
        out = await _platform.run_command(["ipconfig", "/all"], timeout=8.0)
        if not out:
            return None
        m = re.search(r"DHCP Server[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
        return (
            DhcpOffer(server_ip=m.group(1), server_id=m.group(1), msg_type="ACK (active lease)")
            if m
            else None
        )

    # Linux — the widely used lease paths.
    for path in (
        "/var/lib/dhcp/dhclient.leases",
        f"/var/lib/dhcp/dhclient.{interface}.leases",
        "/var/lib/dhclient/dhclient.leases",
    ):
        try:
            # Reading a file blocks — we do it in a thread so the event loop is
            # not held up (lease files are small, but the loop must not stall
            # on a slow disk either).
            text = await asyncio.to_thread(
                lambda p=path: Path(p).read_text(encoding="utf-8", errors="replace")
            )
            parsed = parse_dhclient_lease(text)
        except OSError:
            continue
        if parsed:
            return parsed
    return None
