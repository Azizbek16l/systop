"""The ping panel — periodically pings the local gateway and the global servers."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Sparkline, Static

from systop.core.netinfo import default_gateway
from systop.core.ping import build_targets, ping_many
from systop.widgets._glyphs import dash, glyph, unicode_ok

REFRESH_SECONDS = 3.0


class PingPanel(Vertical):
    """A table of targets + a live graph of the first target's RTT.

    Every row is coloured by its state (alive/dead), and yellow/red according to
    the loss percentage. Below the graph: the current/min/avg/max RTT (ms).
    """

    BORDER_TITLE = "Ping — local + global"
    BORDER_SUBTITLE = "r refresh"

    def compose(self) -> ComposeResult:
        yield DataTable(id="ping-table", zebra_stripes=True, cursor_type="row")
        yield Sparkline([0], id="ping-spark")
        yield Static(self._stats_caption(None), id="ping-stats", classes="spark-caption")

    def on_mount(self) -> None:
        table = self.query_one("#ping-table", DataTable)
        table.add_columns("State", "Target", "Address", "Avg ms", "Loss %")
        self._targets = build_targets(default_gateway())
        self._rtt_history: list[float] = []
        # The graph is hidden while there is no data — so that there is no empty
        # space/fake bar under the table until data arrives (the graph sits
        # directly against the table).
        self.query_one("#ping-spark", Sparkline).display = False
        self.update_pings()
        self.set_interval(REFRESH_SECONDS, self.update_pings)

    @work(exclusive=True)
    async def update_pings(self) -> None:
        if not self._targets:
            self._targets = build_targets(default_gateway())
        try:
            results = await ping_many(self._targets)
        except Exception:
            # No ICMP permission or a network error — the panel must not crash.
            return

        table = self.query_one("#ping-table", DataTable)
        table.clear()
        for r in results:
            # The state ALWAYS comes from the real parse result: even when the
            # target is dead, r.loss_pct is shown (never a hard-coded "100").
            # On partial loss (alive=True but loss>0) yellow, on a fully dead
            # target red.
            loss = self._loss_cell(r.loss_pct)
            if r.alive:
                dot = f"[green]{glyph('ok')}[/] [dim]alive[/]"
                avg = self._rtt_cell(r.avg_rtt)
            else:
                dot = f"[red]{glyph('dead')}[/] [dim]dead[/]"
                avg = f"[dim]{dash()}[/]"
            table.add_row(dot, r.label, r.address, avg, loss)

        # For the graph we track the first alive target.
        first_alive = next((r for r in results if r.alive), None)
        if first_alive:
            self._rtt_history.append(round(first_alive.avg_rtt, 1))
            self._rtt_history = self._rtt_history[-80:]
            spark = self.query_one("#ping-spark", Sparkline)
            spark.data = self._rtt_history
            spark.display = unicode_ok()  # there is data — show the graph
            self.query_one("#ping-stats", Static).update(
                self._stats_caption(self._rtt_history, label=first_alive.label)
            )

    @staticmethod
    def _rtt_cell(ms: float) -> str:
        """Colours the RTT value by its magnitude (DataTable Rich markup)."""
        if ms < 30:
            return f"[green]{ms:.1f}[/]"
        if ms < 100:
            return f"[yellow]{ms:.1f}[/]"
        return f"[red]{ms:.1f}[/]"

    @staticmethod
    def _loss_cell(pct: float) -> str:
        if pct <= 0:
            return "[green]0[/]"
        if pct < 50:
            return f"[yellow]{pct:.0f}[/]"
        return f"[red]{pct:.0f}[/]"

    @staticmethod
    def _stats_caption(history: list[float] | None, label: str = "") -> str:
        """The caption below the graph: current / min / avg / max RTT (ms)."""
        head = f"[dim]{label}[/]  " if label else ""
        if not history:
            d = dash()
            return f"{head}[dim]cur {d}   min {d}   avg {d}   max {d}   ms[/]"
        cur = history[-1]
        lo = min(history)
        avg = sum(history) / len(history)
        hi = max(history)
        return (
            f"{head}[dim]cur[/] [b]{cur:.1f}[/]   "
            f"[dim]min[/] [$success]{lo:.1f}[/]   "
            f"[dim]avg[/] {avg:.1f}   "
            f"[dim]max[/] {hi:.1f}   [dim]ms[/]"
        )
