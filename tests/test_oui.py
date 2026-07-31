"""oui tests — OFFLINE.

``normalize_oui`` (the various MAC formats), ``is_locally_administered`` (the
U/L bit) and ``lookup_vendor`` (the built-in table) are exercised as pure logic.
No network — only strings/regexes and a small dict lookup.
"""

from __future__ import annotations

import pytest

from systop.core.oui import (
    is_locally_administered,
    lookup_vendor,
    normalize_oui,
)

# --- normalize_oui: the various formats -------------------------------------


@pytest.mark.parametrize(
    "mac, expected",
    [
        # colon (the most widespread)
        ("a4:b1:c2:d3:e4:f5", "A4B1C2"),
        # dash (the Windows style)
        ("A4-B1-C2-D3-E4-F5", "A4B1C2"),
        # the Cisco dot format (aabb.ccdd.eeff)
        ("a4b1.c2d3.e4f5", "A4B1C2"),
        # no separator at all
        ("a4b1c2d3e4f5", "A4B1C2"),
        # mixed separators + whitespace
        ("a4 b1-c2:d3.e4f5", "A4B1C2"),
        # already UPPER
        ("FF:EE:DD:CC:BB:AA", "FFEEDD"),
    ],
)
def test_normalize_oui_formats(mac, expected):
    assert normalize_oui(mac) == expected


def test_normalize_oui_only_needs_three_octets():
    # It works even when only the OUI part is given (6 hex characters).
    assert normalize_oui("a4:b1:c2") == "A4B1C2"
    assert normalize_oui("a4b1c2") == "A4B1C2"


@pytest.mark.parametrize(
    "mac",
    [
        "",  # empty
        "a4:b1",  # 4 hex < 6
        "zz:zz:zz",  # not hex -> 0 characters after stripping
        "g4:h1:i2:j3",  # non-hex characters
        ":::::",  # separators only
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
        # second nibble 2/6/A/E -> the U/L bit is set
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
    # If the OUI cannot be extracted -> False (not an error, the vendor is unknown).
    assert is_locally_administered("zz") is False
    assert is_locally_administered("") is False


# --- lookup_vendor: the built-in table --------------------------------------


@pytest.mark.parametrize(
    "mac, vendor",
    [
        ("a4:b1:c2:d3:e4:f5", "Apple"),
        ("00:00:0c:11:22:33", "Cisco"),
        ("b8:27:eb:aa:bb:cc", "Raspberry Pi"),
        ("00:50:56:00:00:01", "VMware"),
        ("4c:5e:0c:00:00:00", "MikroTik"),
        # a difference in format must not affect finding the vendor:
        ("A4-B1-C2-D3-E4-F5", "Apple"),
        ("a4b1.c2d3.e4f5", "Apple"),
    ],
)
def test_lookup_vendor_known(mac, vendor):
    assert lookup_vendor(mac) == vendor


def test_lookup_vendor_unknown_oui_returns_none():
    # An OUI that is not in the table (deliberately non-existent).
    assert lookup_vendor("12:34:56:78:9a:bc") is None


def test_lookup_vendor_none_and_empty():
    assert lookup_vendor(None) is None
    assert lookup_vendor("") is None


def test_lookup_vendor_short_mac_returns_none():
    # A MAC too short for the OUI to be extracted.
    assert lookup_vendor("a4:b1") is None
