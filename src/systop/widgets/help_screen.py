"""Yordam ekrani — `?` tugmasi bilan ochiladigan modal oyna (o'zbekcha)."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Center, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from systop.widgets._glyphs import unicode_ok


def _help_text() -> str:
    """Yordam matnini quradi — strelka belgilari terminalga moslangan.

    Legacy konsol (Unicode'siz) ↑/↓ strelkalarini mojibake qilishi mumkin —
    bunday holatda so'z bilan ("Yuqori / Past") ko'rsatamiz. Matn import emas,
    chaqiruvda quriladi (konsol holati shu paytda aniq)."""
    arrows = "↑ / ↓" if unicode_ok() else "Yuqori / Past"
    return f"""\
[b]systop[/] — sysadminlar uchun terminal tarmoq tooli.

[b $accent]Panellar[/]
  [b]Internet tezligi[/]   download / upload / latency o'lchovi (Cloudflare)
  [b]Ping[/]               gateway + global DNS serverlarini davriy ping
  [b]Topologiya[/]         LAN hostlar (skan) va global yo'l (traceroute)

[b $accent]Tugmalar[/]
  [b $secondary]s[/]   Tezlik testini boshlash
  [b $secondary]r[/]   Ping jadvalini yangilash
  [b $secondary]l[/]   LAN ni skanerlash
  [b $secondary]t[/]   Traceroute maydoniga o'tish
  [b $secondary]d[/]   Temani almashtirish (qorong'i / yorug')
  [b $secondary]?[/]   Ushbu yordam oynasini ochish
  [b $secondary]q[/]   Chiqish

[b $accent]Navigatsiya[/]
  [b $secondary]Tab / Shift+Tab[/]   panellar va elementlar orasida
  [b $secondary]{arrows}[/]            jadval qatorlari bo'ylab
  [b $secondary]Ctrl+P[/]           buyruqlar palitrasi (command palette)
  [b $secondary]Esc[/]              ushbu oynani yopish

[dim]Yopish uchun Esc yoki ? bosing.[/]\
"""


class HelpScreen(ModalScreen):
    """Markazlashgan modal yordam oynasi."""

    BINDINGS = [
        ("escape", "dismiss", "Yopish"),
        ("question_mark", "dismiss", "Yopish"),
        ("q", "dismiss", "Yopish"),
    ]

    def compose(self) -> ComposeResult:
        with Center(id="help-wrap"):
            with VerticalScroll(id="help-box"):
                yield Static(" Yordam — systop ", id="help-title")
                yield Static(_help_text(), id="help-body")

    def action_dismiss(self) -> None:  # type: ignore[override]
        self.dismiss()
