"""Markazlashgan glyph (belgi) helper — Unicode yoki ASCII fallback.

Legacy Windows konsoli (raster cmd.exe, codepage 65001 EMAS) Unicode blok/emoji
belgilarni (⬇ ⬆ ⊚ ◆ ⚡ ● 🌐 …) ko'rsata olmaydi — mojibake yoki bo'sh kvadrat
chiqaradi. `core._platform.unicode_ok()` shu holatni aniqlaydi: True bo'lsa
to'liq Unicode, False bo'lsa ASCII ekvivalent ishlatiladi.

Barcha widget'lar foydalanuvchiga ko'rinadigan maxsus belgini shu modul orqali
oladi (`glyph("download")` kabi) — shunda fallback bitta joyda boshqariladi va
macOS/Linux xulqi (har doim Unicode) o'zgarmaydi.

Eslatma: `unicode_ok()` har chaqiruvda baholanadi (Windows'da `GetConsoleOutputCP`
o'qiladi). Bu arzon va konsol holati ish davomida o'zgarishi mumkin (foydalanuvchi
`chcp` qilsa). Testlarda `unicode_ok` ni monkeypatch qilib har ikki shox sinaladi.
"""

from __future__ import annotations

from systop.core import _platform

# Har bir mantiqiy belgi uchun (Unicode, ASCII) juftligi.
# ASCII varianti SOF ASCII (codepage 437/866 da ham bir xil ko'rinadi).
_GLYPHS: dict[str, tuple[str, str]] = {
    # Tezlik paneli
    "download": ("⬇", "[v]"),  # download yo'nalishi
    "upload": ("⬆", "[^]"),  # upload yo'nalishi
    "latency": ("⊚", "[~]"),  # latency / ping vaqti
    # Holat belgilari
    "ok": ("●", "*"),  # tirik / faol nuqta
    "dead": ("●", "x"),  # o'lik nuqta (rang qizil bo'ladi)
    "gateway": ("◆", "=>"),  # gateway roli (LAN jadvali)
    "fast": ("⚡", "*"),  # eng tez resolver (DNS)
    "cross": ("✗", "X"),  # xato belgisi
    "sep": ("·", "-"),  # interfeys ajratuvchi (name · ip)
    "dash": ("—", "-"),  # bo'sh qiymat (em-dash -> tire)
    "ellipsis": ("…", "..."),  # tugallanmagan jarayon (… -> ...)
}


def unicode_ok() -> bool:
    """Terminal Unicode blok/emoji ko'rsata oladimi (core._platform orqali).

    Bitta o'rab beruvchi funksiya — testlar uni yoki `_platform.unicode_ok` ni
    monkeypatch qilishi mumkin. Atribut sifatida o'qiladi (`_platform.unicode_ok()`)
    shunda core'dagi monkeypatch ham ta'sir qiladi.
    """
    return _platform.unicode_ok()


def glyph(name: str) -> str:
    """Mantiqiy belgi nomini terminalga mos satrga aylantiradi.

    `unicode_ok()` True bo'lsa Unicode variant, aks holda ASCII fallback.
    Noma'lum nom kelsa — o'sha nomning o'zini qaytaradi (xato ko'tarmaydi),
    shunda noto'g'ri kalit ham UI'ni yiqitmaydi.
    """
    pair = _GLYPHS.get(name)
    if pair is None:
        return name
    return pair[0] if unicode_ok() else pair[1]


def ellipsis() -> str:
    """Jarayon tugallanmaganini bildiruvchi qo'shimcha (`…` yoki `...`)."""
    return glyph("ellipsis")


def dash() -> str:
    """Bo'sh / mavjud emas qiymat belgisi (`—` yoki `-`)."""
    return glyph("dash")
