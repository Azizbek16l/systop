"""A centralised glyph (symbol) helper — Unicode, or an ASCII fallback.

The legacy Windows console (raster cmd.exe, codepage NOT 65001) cannot display
Unicode block/emoji characters (⬇ ⬆ ⊚ ◆ ⚡ ● 🌐 …) — it produces mojibake or an
empty square. `core._platform.unicode_ok()` detects that situation: on True the
full Unicode is used, on False the ASCII equivalent.

Every widget obtains its user-visible special characters through this module
(like `glyph("download")`) — that way the fallback is governed in one place and
the macOS/Linux behaviour (always Unicode) does not change.

Note: `unicode_ok()` is evaluated on every call (on Windows it reads
`GetConsoleOutputCP`). That is cheap, and the console state can change while the
program runs (if the user runs `chcp`). In the tests `unicode_ok` is
monkeypatched so that both branches are exercised.
"""

from __future__ import annotations

from rich.text import Text

from systop.core import _platform

# The (Unicode, ASCII) pair for every logical symbol.
# The ASCII variant is PURE ASCII (it looks the same in codepage 437/866 too).
_GLYPHS: dict[str, tuple[str, str]] = {
    # The speed panel
    "download": ("⬇", "[v]"),  # the download direction
    "upload": ("⬆", "[^]"),  # the upload direction
    "latency": ("⊚", "[~]"),  # latency / ping time
    # State marks
    "ok": ("●", "*"),  # an alive / active dot
    "dead": ("●", "x"),  # a dead dot (the colour will be red)
    "gateway": ("◆", "=>"),  # the gateway role (the LAN table)
    "fast": ("⚡", "*"),  # the fastest resolver (DNS)
    "cross": ("✗", "X"),  # the error mark
    "sep": ("·", "-"),  # the interface separator (name · ip)
    "dash": ("—", "-"),  # an empty value (em dash -> hyphen)
    "ellipsis": ("…", "..."),  # an unfinished process (… -> ...)
    "empty": ("◌ ◌ ◌", "o o o"),  # the glyph row for the empty state (no data yet)
}


def unicode_ok() -> bool:
    """Can the terminal display Unicode block/emoji characters (via core._platform)?

    A single wrapping function — the tests can monkeypatch either it or
    `_platform.unicode_ok`. It is read as an attribute
    (`_platform.unicode_ok()`), so that a monkeypatch in core takes effect too.
    """
    return _platform.unicode_ok()


def glyph(name: str) -> str:
    """Turns a logical symbol name into a string suited to the terminal.

    If `unicode_ok()` is True the Unicode variant, otherwise the ASCII fallback.
    If an unknown name arrives — that name itself is returned (no exception is
    raised), so that a wrong key does not bring the UI down either.
    """
    pair = _GLYPHS.get(name)
    if pair is None:
        return name
    return pair[0] if unicode_ok() else pair[1]


def ellipsis() -> str:
    """The suffix that marks a process as unfinished (`…` or `...`)."""
    return glyph("ellipsis")


def dash() -> str:
    """The mark for an empty / non-existent value (`—` or `-`)."""
    return glyph("dash")


def data_cell(value: object, empty: str | None = None) -> Text:
    """Returns a data value as a `Text` — markup/emoji are NOT parsed.

    Why this is needed: Rich treats a sequence like `:ab:` as an **emoji
    shortcode** and substitutes it. The MAC address `62:46:3c:ab:d1:1a` comes
    out on screen as `62:46:3c🆎d1:1a` — that is, the MAC the sysadmin sees is
    not the real MAC. IPv6 is even more dangerous: there are 10 shortcodes made
    up of hex characters (`:a:`->🅰, `:b:`->🅱, `:ab:`->🆎, `:cd:`->💿,
    `:abc:`->🔤, `:abcd:`->🔡, `:bed:`->🛏, `:bee:`->🐝, `:100:`->💯,
    `:1234:`->🔢).

    In the CLI `Console(emoji=False)` closes this hole, but the **Textual TUI**
    goes through its own render pipeline and the substitution is enabled there.
    A `Text` object, on the other hand, is not parsed — which is why every
    MAC/IP/hostname cell has to pass through this function.

    `empty` — the mark shown when the value is empty (in a dim style).
    """
    if value is None or value == "":
        return Text(empty or "", style="dim")
    return Text(str(value))
