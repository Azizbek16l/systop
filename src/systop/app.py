"""The systop dashboard — the Textual application that ties the panels together.

At the top a status bar showing the network state, and below it a balanced grid:
the left column — speed + ping, the right column — topology (LAN + traceroute).
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.theme import Theme
from textual.widgets import Footer, Header

from systop.core import _platform
from systop.widgets import HelpScreen, PingPanel, SpeedPanel, StatusBar, TopologyPanel

# A theme made for systop — a cool "terminal" palette (tones close to oklch).
SYSTOP_THEME = Theme(
    name="systop",
    primary="#3b82f6",  # the main accent — blue (frames, titles)
    secondary="#22d3ee",  # the secondary one — turquoise
    accent="#a78bfa",  # the focus accent — violet
    foreground="#e2e8f0",
    background="#0b1120",
    surface="#131c2e",
    panel="#1b2740",
    success="#34d399",  # alive / good
    warning="#fbbf24",  # middling / warning
    error="#f87171",  # dead / error
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
    """The network monitoring dashboard: status bar + speed + ping + topology."""

    CSS_PATH = Path(__file__).parent / "styles.tcss"
    TITLE = "systop"
    SUB_TITLE = "network monitoring"

    BINDINGS = [
        ("s", "run_speed", "Speed"),
        ("r", "refresh_ping", "Refresh ping"),
        ("l", "scan_lan", "LAN scan"),
        ("t", "focus_trace", "Traceroute"),
        ("d", "cycle_theme", "Theme"),
        ("question_mark", "help", "Help"),
        ("q", "quit", "Quit"),
    ]

    def on_mount(self) -> None:
        self.register_theme(SYSTOP_THEME)
        self.register_theme(SYSTOP_LIGHT)
        self.theme = "systop"
        # A legacy console (no Unicode) — we add the `-ascii` class to the
        # screen; styles.tcss drops the frames down to ASCII and hides the
        # sparklines (so that the block characters do not turn into mojibake).
        # On macOS/Linux: nothing happens.
        if not _platform.unicode_ok():
            self.screen.add_class("-ascii")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield StatusBar(id="status-bar")
        with Horizontal(id="main"):
            with Vertical(id="left-col"):
                yield SpeedPanel(id="speed")
                yield PingPanel(id="ping")
            yield TopologyPanel(id="topology")
        yield Footer()

    # --- Actions (named to match the widgets' worker methods) ---

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
    """Starts the dashboard.

    First we prepare the console (`init_console`): on Windows, UTF-8 + VT mode —
    so that Textual's sparkline/braille/box characters render correctly even in
    the legacy cmd.exe. On other operating systems this is a no-op. Only then
    does the application start.
    """
    _platform.init_console()
    SystopApp().run()


if __name__ == "__main__":
    run()
