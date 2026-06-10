"""CLI (Rich) chiqishini TUI bilan bitta dizayn tiliga keltiruvchi yordamchilar.

Bu modul FAQAT inson-o'qiydigan "table" rejimi uchun: yengil jadval chrome,
monoxrom glyphlar (`_glyphs` orqali) va RTT/loss gradatsiyasi. JSON/CSV rejimi
bunga umuman bog'liq emas (cli.py'da alohida yo'l).

Nega alohida modul: `styled_table` + gradatsiya `cli.py`'da o'nlab marta
ishlatiladi; TUI'dagi `ping_panel._rtt_cell`/`_loss_cell` mantig'i bilan bir xil
chegaralarni (30/100 ms, 50% loss) bitta joyda saqlash uchun.

MUHIM — rang: TUI (Textual) `[$success]` markup'ini biladi, ammo CLI (Rich)
BILMAYDI. Shu sababli bu yerda tema ranglari `app.SYSTOP_THEME` dagi AYNAN
o'sha hex qiymatlar bilan beriladi (success=#34d399, warning=#fbbf24,
error=#f87171, ...). Rich hex ranglarni to'g'ridan-to'g'ri qabul qiladi
(`[#34d399]...[/]`), shunda CLI va TUI bir xil palitrada ko'rinadi. Rang HAR
DOIM so'z/qiymat bilan birga — rang yagona signal emas (rangsiz terminalda ham
ma'no yo'qolmaydi).
"""

from __future__ import annotations

from rich import box
from rich.table import Table

from systop.widgets._glyphs import glyph

# --- Tema ranglari (app.SYSTOP_THEME hex qiymatlari bilan AYNAN bir xil) ----
# Textual `$success`/`$warning`/... ni Rich tushunmaydi — shu sababli hex.
SUCCESS = "#34d399"  # tirik / yaxshi (yashil)
WARNING = "#fbbf24"  # o'rtacha / ogohlantirish (amber)
ERROR = "#f87171"  # o'lik / xato (qizil)
PRIMARY = "#3b82f6"  # asosiy aksent — ko'k (jadval sarlavhalari)
SECONDARY = "#22d3ee"  # ikkilamchi — turkuaz


def styled_table(title: str) -> Table:
    """TUI bilan bir xil yengil chrome'li Rich jadval yasaydi.

    - `box.HORIZONTALS` — faqat gorizontal chiziqlar (og'ir ┏━┳━┓ ramka yo'q,
      vertikal ajratkichlar yo'q) — TUI'dagi DataTable hissini beradi.
    - title chapga tekislangan, `bold` + primary (ko'k) — panel sarlavhasi kabi.
    - `pad_edge=False` — chap/o'ng chetda ortiqcha bo'shliq yo'q (ixcham).
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
    """RTT (ms) qiymatini kattaligiga qarab ranglaydi (ping_panel bilan bir xil).

    <30 ms yashil, <100 ms amber, aks holda qizil. Rang doim qiymat bilan —
    rangsiz terminalda ham raqamning o'zi ko'rinadi.
    """
    if ms < 30:
        return f"[{SUCCESS}]{ms:.1f}[/]"
    if ms < 100:
        return f"[{WARNING}]{ms:.1f}[/]"
    return f"[{ERROR}]{ms:.1f}[/]"


def loss_cell(pct: float) -> str:
    """Loss foizini ranglaydi (ping_panel bilan bir xil): 0 yashil, <50 amber, aks qizil."""
    if pct <= 0:
        return f"[{SUCCESS}]0[/]"
    if pct < 50:
        return f"[{WARNING}]{pct:.0f}[/]"
    return f"[{ERROR}]{pct:.0f}[/]"


def alive_cell(alive: bool) -> str:
    """Holat katakchasi — TUI leksikoni: `tirik` / `o'lik` (glyph + tema rangi).

    glyph('ok')/('dead') monoxrom belgi beradi (Unicode `●`, ASCII `*`/`x`);
    rang ma'noni kuchaytiradi, so'z (`tirik`/`o'lik`) yagona signal sifatida qoladi.
    """
    if alive:
        return f"[{SUCCESS}]{glyph('ok')}[/] tirik"
    return f"[{ERROR}]{glyph('dead')}[/] o'lik"
