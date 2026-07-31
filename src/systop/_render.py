"""Helpers that bring the CLI (Rich) output into the same design language as the TUI.

This module is ONLY for the human-readable "table" mode: light table chrome,
monochrome glyphs (through `_glyphs`) and the RTT/loss gradation. The JSON/CSV
mode has nothing to do with it (a separate path in cli.py).

Why a separate module: `styled_table` + the gradation are used dozens of times
in `cli.py`; this keeps the same thresholds (30/100 ms, 50% loss) as the
`ping_panel._rtt_cell`/`_loss_cell` logic in the TUI, all in one place.

IMPORTANT — colour: the TUI (Textual) understands the `[$success]` markup, but
the CLI (Rich) DOES NOT. That is why the theme colours are given here as EXACTLY
the same hex values as in `app.SYSTOP_THEME` (success=#34d399, warning=#fbbf24,
error=#f87171, ...). Rich accepts hex colours directly (`[#34d399]...[/]`), so
the CLI and the TUI appear in the same palette. The colour ALWAYS comes together
with the word/value — colour is never the only signal (the meaning is not lost
on a colourless terminal either).
"""

from __future__ import annotations

from rich import box
from rich.table import Table

from systop.widgets._glyphs import glyph

# --- Theme colours (EXACTLY the same hex values as in app.SYSTOP_THEME) -----
# Rich does not understand Textual's `$success`/`$warning`/... — hence the hex.
SUCCESS = "#34d399"  # alive / good (green)
WARNING = "#fbbf24"  # middling / warning (amber)
ERROR = "#f87171"  # dead / error (red)
PRIMARY = "#3b82f6"  # the main accent — blue (table titles)
SECONDARY = "#22d3ee"  # the secondary one — turquoise


def styled_table(title: str) -> Table:
    """Builds a Rich table with the same light chrome as the TUI.

    - `box.HORIZONTALS` — horizontal lines only (no heavy ┏━┳━┓ frame, no
      vertical separators) — it gives the feel of the DataTable in the TUI.
    - the title is left-aligned, `bold` + primary (blue) — like a panel title.
    - `pad_edge=False` — no extra whitespace at the left/right edge (compact).
    """
    return Table(
        title=title,
        box=box.HORIZONTALS,
        title_justify="left",
        title_style=f"bold {PRIMARY}",
        header_style=f"bold {SECONDARY}",
        pad_edge=False,
        expand=False,
    )


def rtt_cell(ms: float) -> str:
    """Colours an RTT (ms) value by its magnitude (the same as in ping_panel).

    <30 ms green, <100 ms amber, otherwise red. The colour always comes with the
    value — on a colourless terminal the number itself is still visible.
    """
    if ms < 30:
        return f"[{SUCCESS}]{ms:.1f}[/]"
    if ms < 100:
        return f"[{WARNING}]{ms:.1f}[/]"
    return f"[{ERROR}]{ms:.1f}[/]"


def loss_cell(pct: float) -> str:
    """Colours the loss percentage (same as ping_panel): 0 green, <50 amber, else red."""
    if pct <= 0:
        return f"[{SUCCESS}]0[/]"
    if pct < 50:
        return f"[{WARNING}]{pct:.0f}[/]"
    return f"[{ERROR}]{pct:.0f}[/]"


def alive_cell(alive: bool) -> str:
    """The state cell — the TUI's vocabulary: `alive` / `dead` (glyph + theme colour).

    glyph('ok')/('dead') gives a monochrome mark (Unicode `●`, ASCII `*`/`x`);
    the colour reinforces the meaning, and the word (`alive`/`dead`) remains the
    single signal.
    """
    if alive:
        return f"[{SUCCESS}]{glyph('ok')}[/] alive"
    return f"[{ERROR}]{glyph('dead')}[/] dead"
