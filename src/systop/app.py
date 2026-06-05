"""systop dashboard — panellarni birlashtiruvchi Textual ilovasi.

Tepada tarmoq holatini ko'rsatuvchi status-bar, ostida muvozanatli grid:
chap ustun — tezlik + ping, o'ng ustun — topologiya (LAN + traceroute).
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.theme import Theme
from textual.widgets import Footer, Header

from systop.widgets import HelpScreen, PingPanel, SpeedPanel, StatusBar, TopologyPanel

# systop uchun maxsus tema — sovuq "terminal" palitrasi (oklch'ga yaqin tonlar).
SYSTOP_THEME = Theme(
    name="systop",
    primary="#3b82f6",  # asosiy aksent — ko'k (ramkalar, sarlavhalar)
    secondary="#22d3ee",  # ikkilamchi — turkuaz
    accent="#a78bfa",  # fokus aksenti — siyohrang
    foreground="#e2e8f0",
    background="#0b1120",
    surface="#131c2e",
    panel="#1b2740",
    success="#34d399",  # tirik / yaxshi
    warning="#fbbf24",  # o'rtacha / ogohlantirish
    error="#f87171",  # o'lik / xato
    dark=True,
    variables={
        "block-cursor-text-style": "none",
        "footer-key-foreground": "#3b82f6",
        "input-selection-background": "#3b82f6 35%",
    },
)

SYSTOP_LIGHT = Theme(
    name="systop-light",
    primary="#2563eb",
    secondary="#0891b2",
    accent="#7c3aed",
    foreground="#0f172a",
    background="#f8fafc",
    surface="#ffffff",
    panel="#eef2f7",
    success="#059669",
    warning="#d97706",
    error="#dc2626",
    dark=False,
)


class SystopApp(App):
    """Tarmoq monitoringi dashboard'i: holat-paneli + tezlik + ping + topologiya."""

    CSS_PATH = Path(__file__).parent / "styles.tcss"
    TITLE = "systop"
    SUB_TITLE = "tarmoq monitoringi"

    BINDINGS = [
        ("s", "run_speed", "Tezlik"),
        ("r", "refresh_ping", "Ping yangilash"),
        ("l", "scan_lan", "LAN skan"),
        ("t", "focus_trace", "Traceroute"),
        ("d", "cycle_theme", "Tema"),
        ("question_mark", "help", "Yordam"),
        ("q", "quit", "Chiqish"),
    ]

    def on_mount(self) -> None:
        self.register_theme(SYSTOP_THEME)
        self.register_theme(SYSTOP_LIGHT)
        self.theme = "systop"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatusBar(id="status-bar")
        with Horizontal(id="main"):
            with Vertical(id="left-col"):
                yield SpeedPanel(id="speed")
                yield PingPanel(id="ping")
            yield TopologyPanel(id="topology")
        yield Footer()

    # --- Action'lar (widget worker metodlariga mos nomlanadi) ---

    def action_refresh_ping(self) -> None:
        self.query_one(PingPanel).update_pings()

    def action_run_speed(self) -> None:
        self.query_one(SpeedPanel).run_test()

    def action_scan_lan(self) -> None:
        self.query_one(TopologyPanel).scan_lan()

    def action_focus_trace(self) -> None:
        self.query_one(TopologyPanel).focus_trace()

    def action_cycle_theme(self) -> None:
        self.theme = "systop-light" if self.theme == "systop" else "systop"

    def action_help(self) -> None:
        self.push_screen(HelpScreen())


def run() -> None:
    """Dashboard'ni ishga tushiradi."""
    SystopApp().run()


if __name__ == "__main__":
    run()
