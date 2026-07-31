"""The help screen — a modal window opened with the `?` key."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Center, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from systop.widgets._glyphs import unicode_ok


def _help_text() -> str:
    """Builds the help text — the arrow symbols are adapted to the terminal.

    A legacy console (without Unicode) may turn the ↑/↓ arrows into mojibake —
    in that case we spell them out in words ("Up / Down"). The text is not built
    at import time but on the call (the console state is known by then)."""
    arrows = "↑ / ↓" if unicode_ok() else "Up / Down"
    return f"""\
[b]systop[/] — a terminal network tool for sysadmins.

[b $accent]Panels[/]
  [b]Internet speed[/]     download / upload / latency measurement (Cloudflare)
  [b]Ping[/]               periodic ping of the gateway + the global DNS servers
  [b]Topology[/]           LAN hosts (scan) and the global path (traceroute)

[b $accent]Keys[/]
  [b $secondary]s[/]   Start the speed test
  [b $secondary]r[/]   Refresh the ping table
  [b $secondary]l[/]   Scan the LAN
  [b $secondary]t[/]   Move to the traceroute field
  [b $secondary]d[/]   Switch the theme (dark / light)
  [b $secondary]?[/]   Open this help window
  [b $secondary]q[/]   Quit

[b $accent]Navigation[/]
  [b $secondary]Tab / Shift+Tab[/]   between panels and elements
  [b $secondary]{arrows}[/]            along the table rows
  [b $secondary]Ctrl+P[/]           the command palette
  [b $secondary]Esc[/]              close this window

[dim]Press Esc or ? to close.[/]\
"""


class HelpScreen(ModalScreen):
    """The centred modal help window."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("question_mark", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Center(id="help-wrap"):
            with VerticalScroll(id="help-box"):
                yield Static(" Help — systop ", id="help-title")
                yield Static(_help_text(), id="help-body")

    def action_dismiss(self) -> None:  # type: ignore[override]
        self.dismiss()
