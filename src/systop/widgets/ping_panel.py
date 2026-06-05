"""Ping paneli — lokal gateway va global serverlarni davriy ping qiladi."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Sparkline, Static

from systop.core.netinfo import default_gateway
from systop.core.ping import build_targets, ping_many

REFRESH_SECONDS = 3.0


class PingPanel(Vertical):
    """Nishonlar jadvali + birinchi nishon RTT'sining jonli grafigi.

    Har qator holatga qarab ranglanadi (tirik/o'lik), loss foiziga ko'ra
    sariq/qizil. Grafik ostida joriy/min/o'rt/maks RTT (ms).
    """

    BORDER_TITLE = "Ping — lokal + global"

    def compose(self) -> ComposeResult:
        yield DataTable(id="ping-table", zebra_stripes=True, cursor_type="row")
        yield Sparkline([0], id="ping-spark")
        yield Static(self._stats_caption(None), id="ping-stats", classes="spark-caption")

    def on_mount(self) -> None:
        table = self.query_one("#ping-table", DataTable)
        table.add_columns("Holat", "Nishon", "Manzil", "Avg ms", "Loss %")
        self._targets = build_targets(default_gateway())
        self._rtt_history: list[float] = []
        self.update_pings()
        self.set_interval(REFRESH_SECONDS, self.update_pings)

    @work(exclusive=True)
    async def update_pings(self) -> None:
        if not self._targets:
            self._targets = build_targets(default_gateway())
        try:
            results = await ping_many(self._targets)
        except Exception:
            # ICMP ruxsati yo'q yoki tarmoq xatosi — panel yiqilmasin.
            return

        table = self.query_one("#ping-table", DataTable)
        table.clear()
        for r in results:
            if r.alive:
                dot = "[green]●[/] [dim]tirik[/]"
                avg = self._rtt_cell(r.avg_rtt)
                loss = self._loss_cell(r.loss_pct)
            else:
                dot = "[red]●[/] [dim]o'lik[/]"
                avg = "[dim]—[/]"
                loss = "[red]100[/]"
            table.add_row(dot, r.label, r.address, avg, loss)

        # Grafik uchun birinchi tirik nishonni kuzatamiz.
        first_alive = next((r for r in results if r.alive), None)
        if first_alive:
            self._rtt_history.append(round(first_alive.avg_rtt, 1))
            self._rtt_history = self._rtt_history[-80:]
            self.query_one("#ping-spark", Sparkline).data = self._rtt_history
            self.query_one("#ping-stats", Static).update(
                self._stats_caption(self._rtt_history, label=first_alive.label)
            )

    @staticmethod
    def _rtt_cell(ms: float) -> str:
        """RTT qiymatini kattaligiga qarab ranglaydi (DataTable Rich markup)."""
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
        """Grafik ostidagi izoh: joriy / min / o'rt / maks RTT (ms)."""
        head = f"[dim]{label}[/]  " if label else ""
        if not history:
            return f"{head}[dim]joriy —   min —   o'rt —   maks —   ms[/]"
        cur = history[-1]
        lo = min(history)
        avg = sum(history) / len(history)
        hi = max(history)
        return (
            f"{head}[dim]joriy[/] [b]{cur:.1f}[/]   "
            f"[dim]min[/] [$success]{lo:.1f}[/]   "
            f"[dim]o'rt[/] {avg:.1f}   "
            f"[dim]maks[/] {hi:.1f}   [dim]ms[/]"
        )
