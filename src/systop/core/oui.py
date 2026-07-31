"""MAC address -> vendor (manufacturer) name resolution — offline.

The first 3 octets of a MAC address (the OUI — Organizationally Unique
Identifier) identify the manufacturer. This module returns the vendor name from
a small built-in table (:mod:`systop.data.oui_min`) — without touching the
network and with no extra dependency.

Note: the table is small (the ~60 most common vendors), so for an unknown OUI
``None`` comes back. That is the expected situation, not an error.

Locally administered (random) MACs (second nibble 2/6/A/E) do not identify the
manufacturer through the OUI — in that case ``None`` comes back as well.
"""

from __future__ import annotations

import re

from systop.data.oui_min import OUI_VENDORS

# For stripping any separator/spacing inside a MAC (": - . whitespace").
_SEP_RE = re.compile(r"[^0-9A-Fa-f]")


def normalize_oui(mac: str) -> str | None:
    """Extracts the OUI from a MAC (the first 3 octets, UPPER hex, no separators).

    It accepts various formats: ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-DD-EE-FF``,
    ``aabb.ccdd.eeff`` (Cisco), ``aabbccddeeff``. If there is not enough hex,
    ``None``.
    """
    if not mac:
        return None
    hexed = _SEP_RE.sub("", mac).upper()
    if len(hexed) < 6:
        return None
    return hexed[:6]


def is_locally_administered(mac: str) -> bool:
    """Returns True if the MAC is locally administered (random/virtual).

    If one of the lowest bits of the first octet (the U/L bit, value 0x02) is
    set — the address is not global but locally assigned; the OUI says nothing
    about the vendor. Such MACs (the iOS/Android privacy randomisation, for
    instance) are normally not found in the table.
    """
    oui = normalize_oui(mac)
    if oui is None:
        return False
    first_octet = int(oui[:2], 16)
    return bool(first_octet & 0x02)


def lookup_vendor(mac: str | None) -> str | None:
    """Returns the vendor name for a MAC address (``None`` if it is not found).

    It looks the value up in the built-in
    :data:`systop.data.oui_min.OUI_VENDORS` table.
    """
    if not mac:
        return None
    oui = normalize_oui(mac)
    if oui is None:
        return None
    return OUI_VENDORS.get(oui)
