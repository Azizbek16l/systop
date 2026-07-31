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

from rich.text import Text

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
    "empty": ("◌ ◌ ◌", "o o o"),  # bo'sh holat (hali ma'lumot yo'q) glyph qatori
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


def data_cell(value: object, empty: str | None = None) -> Text:
    """Ma'lumot qiymatini `Text` sifatida qaytaradi — markup/emoji parse QILINMAYDI.

    Nima uchun kerak: Rich `:ab:` kabi ketma-ketlikni **emoji shortcode** deb
    biladi va almashtiradi. MAC manzil `62:46:3c:ab:d1:1a` ekranda
    `62:46:3c🆎d1:1a` bo'lib chiqadi — ya'ni sysadmin ko'rgan MAC haqiqiy MAC
    emas. IPv6 yanada xavfli: 16-lik belgilardan iborat 10 ta shortcode bor
    (`:a:`->🅰, `:b:`->🅱, `:ab:`->🆎, `:cd:`->💿, `:abc:`->🔤, `:abcd:`->🔡,
    `:bed:`->🛏, `:bee:`->🐝, `:100:`->💯, `:1234:`->🔢).

    CLI'da `Console(emoji=False)` shu muammoni yopadi, ammo **Textual TUI**
    o'z render quvuridan o'tadi va u yerda almashtirish yoqilgan. `Text`
    obyekti esa parse qilinmaydi — shuning uchun har qanday MAC/IP/hostname
    katakchasi shu funksiyadan o'tishi kerak.

    `empty` — qiymat bo'sh bo'lganda ko'rsatiladigan belgi (xira uslubda).
    """
    if value is None or value == "":
        return Text(empty or "", style="dim")
    return Text(str(value))
