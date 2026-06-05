"""oui testlari — OFFLINE.

``normalize_oui`` (turli MAC formatlari), ``is_locally_administered`` (U/L bit),
va ``lookup_vendor`` (o'rnatilgan jadval) sof mantiq sifatida sinaladi. Tarmoq
yo'q — faqat string/regex va kichik dict qidiruvi.
"""

from __future__ import annotations

import pytest

from systop.core.oui import (
    is_locally_administered,
    lookup_vendor,
    normalize_oui,
)

# --- normalize_oui: turli formatlar -----------------------------------------


@pytest.mark.parametrize(
    "mac, expected",
    [
        # colon (eng keng tarqalgan)
        ("a4:b1:c2:d3:e4:f5", "A4B1C2"),
        # tире (Windows uslubi)
        ("A4-B1-C2-D3-E4-F5", "A4B1C2"),
        # Cisco nuqta-formati (aabb.ccdd.eeff)
        ("a4b1.c2d3.e4f5", "A4B1C2"),
        # umuman separatorsiz
        ("a4b1c2d3e4f5", "A4B1C2"),
        # aralash separatorlar + bo'sh joy
        ("a4 b1-c2:d3.e4f5", "A4B1C2"),
        # allaqachon UPPER
        ("FF:EE:DD:CC:BB:AA", "FFEEDD"),
    ],
)
def test_normalize_oui_formats(mac, expected):
    assert normalize_oui(mac) == expected


def test_normalize_oui_only_needs_three_octets():
    # Faqat OUI qismi berilsa ham (6 hex) ishlaydi.
    assert normalize_oui("a4:b1:c2") == "A4B1C2"
    assert normalize_oui("a4b1c2") == "A4B1C2"


@pytest.mark.parametrize(
    "mac",
    [
        "",  # bo'sh
        "a4:b1",  # 4 hex < 6
        "zz:zz:zz",  # hex emas -> tozalangach 0 belgi
        "g4:h1:i2:j3",  # hex bo'lmagan belgilar
        ":::::",  # faqat separatorlar
    ],
)
def test_normalize_oui_insufficient_returns_none(mac):
    assert normalize_oui(mac) is None


def test_normalize_oui_none_input():
    assert normalize_oui(None) is None  # type: ignore[arg-type]


# --- is_locally_administered: U/L bit (0x02) --------------------------------


@pytest.mark.parametrize(
    "mac",
    [
        # ikkinchi nibble 2/6/A/E -> U/L bit yoqilgan
        "02:00:00:00:00:00",
        "06:11:22:33:44:55",
        "0a:bb:cc:dd:ee:ff",
        "0e:00:00:00:00:00",
        "aa:bb:cc:dd:ee:ff",  # AA -> 0xAA & 0x02 = 0x02
        "DA:A1:19:00:00:00",  # random privacy MAC
    ],
)
def test_is_locally_administered_true(mac):
    assert is_locally_administered(mac) is True


@pytest.mark.parametrize(
    "mac",
    [
        "a4:b1:c2:d3:e4:f5",  # A4 -> 0xA4 & 0x02 = 0
        "00:00:0c:00:00:00",  # Cisco global
        "b8:27:eb:00:00:00",  # Raspberry Pi global
        "f0:db:e2:00:00:00",  # Apple global
    ],
)
def test_is_locally_administered_false(mac):
    assert is_locally_administered(mac) is False


def test_is_locally_administered_invalid_mac_false():
    # OUI ajratib bo'lmasa -> False (xato emas, vendor noma'lum).
    assert is_locally_administered("zz") is False
    assert is_locally_administered("") is False


# --- lookup_vendor: o'rnatilgan jadval --------------------------------------


@pytest.mark.parametrize(
    "mac, vendor",
    [
        ("a4:b1:c2:d3:e4:f5", "Apple"),
        ("00:00:0c:11:22:33", "Cisco"),
        ("b8:27:eb:aa:bb:cc", "Raspberry Pi"),
        ("00:50:56:00:00:01", "VMware"),
        ("4c:5e:0c:00:00:00", "MikroTik"),
        # format farqi vendor topishga ta'sir qilmasligi kerak:
        ("A4-B1-C2-D3-E4-F5", "Apple"),
        ("a4b1.c2d3.e4f5", "Apple"),
    ],
)
def test_lookup_vendor_known(mac, vendor):
    assert lookup_vendor(mac) == vendor


def test_lookup_vendor_unknown_oui_returns_none():
    # Jadvalda yo'q OUI (ataylab mavjud bo'lmagan).
    assert lookup_vendor("12:34:56:78:9a:bc") is None


def test_lookup_vendor_none_and_empty():
    assert lookup_vendor(None) is None
    assert lookup_vendor("") is None


def test_lookup_vendor_short_mac_returns_none():
    # OUI ajratib bo'lmaydigan qisqa MAC.
    assert lookup_vendor("a4:b1") is None
