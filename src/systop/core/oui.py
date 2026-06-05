"""MAC manzil -> vendor (ishlab chiqaruvchi) nomini aniqlash — offline.

MAC manzilning birinchi 3 okteti (OUI — Organizationally Unique Identifier)
ishlab chiqaruvchini bildiradi. Bu modul o'rnatilgan kichik jadval
(:mod:`systop.data.oui_min`) bo'yicha vendor nomini qaytaradi — tarmoqqa
chiqmasdan, qo'shimcha bog'liqliksiz.

Eslatma: jadval kichik (eng ko'p tarqalgan ~60 vendor), shuning uchun noma'lum
OUI uchun ``None`` qaytadi. Bu kutilgan holat, xato emas.

Lokal-administered (random) MAC'lar (ikkinchi nibble 2/6/A/E) ishlab
chiqaruvchini OUI orqali bildirmaydi — bu holatda ham ``None`` qaytadi.
"""

from __future__ import annotations

import re

from systop.data.oui_min import OUI_VENDORS

# MAC ichidagi har qanday separator/oraliqdan tozalash uchun (": - . bo'sh joy").
_SEP_RE = re.compile(r"[^0-9A-Fa-f]")


def normalize_oui(mac: str) -> str | None:
    """MAC'dan OUI ni (birinchi 3 oktet, UPPER hex, separatorsiz) ajratadi.

    Turli formatlarni qabul qiladi: ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-DD-EE-FF``,
    ``aabb.ccdd.eeff`` (Cisco), ``aabbccddeeff``. Yetarli hex bo'lmasa ``None``.
    """
    if not mac:
        return None
    hexed = _SEP_RE.sub("", mac).upper()
    if len(hexed) < 6:
        return None
    return hexed[:6]


def is_locally_administered(mac: str) -> bool:
    """MAC lokal-administered (random/virtual) bo'lsa True qaytaradi.

    Birinchi oktetning eng past bitidan bittasi (U/L bit, qiymati 0x02) yoqilgan
    bo'lsa — manzil global emas, lokal tayinlangan; OUI vendorni bildirmaydi.
    Bunday MAC'lar (masalan iOS/Android maxfiylik randomizatsiyasi) odatda
    jadvalda topilmaydi.
    """
    oui = normalize_oui(mac)
    if oui is None:
        return False
    first_octet = int(oui[:2], 16)
    return bool(first_octet & 0x02)


def lookup_vendor(mac: str | None) -> str | None:
    """MAC manzil bo'yicha vendor nomini qaytaradi (topilmasa ``None``).

    O'rnatilgan :data:`systop.data.oui_min.OUI_VENDORS` jadvalidan qidiradi.
    """
    if not mac:
        return None
    oui = normalize_oui(mac)
    if oui is None:
        return None
    return OUI_VENDORS.get(oui)
