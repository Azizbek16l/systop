"""`core/dhcp.py` uchun offline testlar — lease parse va rogue-server aniqlash.

Barcha parserlar sof: OS chiqishini yoki xom paketni oladi, `DhcpOffer` beradi.
`discover_servers` sinalmaydi — u UDP broadcast yuboradi.

Uchala OS ham qamrab olinadi: macOS `ipconfig getpacket`, Linux
`dhclient.leases`, va xom DHCP paketi (Windows yo'li `netsh` orqali boradi,
lekin ma'lumot shakli bir xil `DhcpOffer`).
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
# DISCOVER paketi
# --------------------------------------------------------------------------- #


def test_discover_paketi_asosiy_maydonlari():
    packet, xid = build_discover()
    assert len(packet) >= 240
    assert packet[0] == 1  # op = BOOTREQUEST
    # Magic cookie 99.130.83.99 — 236-baytdan boshlanadi (RFC 2131).
    assert packet[236:240] == bytes([99, 130, 83, 99])
    # xid paketning 4:8 baytida bo'lishi kerak.
    assert struct.unpack("!I", packet[4:8])[0] == xid


def test_discover_xid_har_safar_boshqacha():
    """xid — javobni so'rovga bog'lovchi yagona narsa; qat'iy bo'lsa ma'nosiz."""
    xids = {build_discover()[1] for _ in range(20)}
    assert len(xids) > 15


def test_berilgan_xid_ishlatiladi():
    _, xid = build_discover(xid=0xDEADBEEF)
    assert xid == 0xDEADBEEF


# --------------------------------------------------------------------------- #
# Xom javob paketi — xid tekshiruvi
# --------------------------------------------------------------------------- #


def _reply(xid: int, server_id: str = "192.168.1.1") -> bytes:
    """Minimal DHCPOFFER paketi."""
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


def test_boshqa_xid_li_javob_rad_etiladi():
    """Boshqa so'rovga (yoki soxta) javob qabul qilinmasligi kerak."""
    assert parse_offer(_reply(0x1111), "192.168.1.1", expect_xid=0x2222) is None


def test_togri_xid_li_javob_qabul_qilinadi():
    o = parse_offer(_reply(0x1234), "192.168.1.1", expect_xid=0x1234)
    assert o is not None
    assert o.server_id == "192.168.1.1"
    assert o.offered_ip == "192.168.1.50"


def test_xid_tekshiruvi_ixtiyoriy():
    """expect_xid=None bo'lsa tekshirilmaydi (passiv tinglash rejimi)."""
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


def test_getpacket_asosiy_maydonlar():
    o = parse_ipconfig_getpacket(GETPACKET)
    assert o is not None
    assert o.server_id == "192.168.11.1"
    assert o.offered_ip == "192.168.11.43"
    assert o.subnet_mask == "255.255.255.0"
    assert o.routers == ["192.168.11.1"]
    assert o.dns == ["192.168.10.1", "8.8.8.8"]
    assert o.domain == "example.local"


def test_getpacket_lease_16lik_sanoqda():
    """macOS lease_time'ni `0x15180` ko'rinishida beradi — 86400 soniya."""
    o = parse_ipconfig_getpacket(GETPACKET)
    assert o.lease_seconds == 86400


def test_getpacket_server_identifier_siz_none():
    """Server ID bo'lmasa taklif ma'nosiz — None qaytishi kerak, bo'sh obyekt emas."""
    assert parse_ipconfig_getpacket("yiaddr = 1.2.3.4\n") is None


# --------------------------------------------------------------------------- #
# Linux `dhclient.leases` — ENG OXIRGI blok
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


def test_eng_oxirgi_lease_olinadi():
    """Fayl bloklarni KETMA-KET yozadi — joriy lease OXIRGISI.

    Birinchisini olish eski (allaqachon tugagan) tarmoqni ko'rsatardi va
    "DHCP serveringiz 10.0.0.254" degan mutlaqo noto'g'ri javob berardi.
    """
    o = parse_dhclient_lease(LEASES)
    assert o is not None
    assert o.server_id == "192.168.5.1"
    assert o.offered_ip == "192.168.5.20"
    assert o.lease_seconds == 43200


def test_lease_royxatli_maydonlar():
    o = parse_dhclient_lease(LEASES)
    assert o.dns == ["192.168.5.1", "1.1.1.1"]
    assert o.routers == ["192.168.5.1"]


def test_lease_domen_qoshtirnoqsiz():
    o = parse_dhclient_lease(LEASES)
    assert o.domain == "corp.local"


def test_bosh_lease_fayli_none():
    assert parse_dhclient_lease("") is None
    assert parse_dhclient_lease("# izoh\n") is None


def test_server_identifiersiz_lease_none():
    assert parse_dhclient_lease("lease {\n  fixed-address 1.2.3.4;\n}\n") is None


# --------------------------------------------------------------------------- #
# Rogue DHCP aniqlash
# --------------------------------------------------------------------------- #


def test_bitta_server_rogue_emas():
    r = DhcpReport(offers=[
        DhcpOffer(server_ip="192.168.1.1", server_id="192.168.1.1"),
        DhcpOffer(server_ip="192.168.1.1", server_id="192.168.1.1"),  # takror javob
    ])
    assert r.servers == ["192.168.1.1"]
    assert r.is_rogue_suspected is False


def test_ikki_xil_server_rogue_shubhasi():
    """Ikki DHCP server — klassik "internet uzilib-uzilib ketadi" sababi."""
    r = DhcpReport(offers=[
        DhcpOffer(server_ip="192.168.1.1", server_id="192.168.1.1"),
        DhcpOffer(server_ip="192.168.1.77", server_id="192.168.1.77"),
    ])
    assert len(r.servers) == 2
    assert r.is_rogue_suspected is True


def test_identity_server_id_ni_afzal_koradi():
    """Relay orqali kelgan paketda manba IP relay'niki bo'ladi, server ID esa asl.

    Manba IP bo'yicha ajratsak, bitta server relay ortidan ikki xil ko'rinib
    soxta "rogue DHCP" ogohlantirishini berardi.
    """
    o = DhcpOffer(server_ip="10.0.0.254", server_id="192.168.1.1")
    assert o.identity == "192.168.1.1"
    r = DhcpReport(offers=[
        DhcpOffer(server_ip="10.0.0.254", server_id="192.168.1.1"),
        DhcpOffer(server_ip="10.0.9.254", server_id="192.168.1.1"),
    ])
    assert r.is_rogue_suspected is False


def test_javob_kelmasligi_server_yoq_degani_emas():
    """`partial` — "tinglash tugadi, javob kelmadi". Bu "server yo'q" EMAS.

    DHCP javobi ko'p tarmoqda mijoz portiga (68) keladi va uni band qilib
    bo'lmaydi. Shuni "DHCP server topilmadi" deb ko'rsatish soxta signal.
    """
    r = DhcpReport(offers=[], partial=True)
    assert r.servers == []
    assert r.is_rogue_suspected is False
