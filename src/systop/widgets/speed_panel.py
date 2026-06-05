"""Internet tezligi paneli — download/upload o'lchovi, jonli grafik va statistika."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, LoadingIndicator, Sparkline, Static

from systop.core.speed import SpeedResult, run_speedtest


class SpeedPanel(Vertical):
    """Tugma bosilganda tezlik testini ishga tushiradi, natijani ko'rsatadi.

    Holatlar: bo'sh (placeholder) → yuklanmoqda (LoadingIndicator + jonli
    qiymatlar) → natija yoki xato. Grafik ostida joriy/min/o'rt/maks Mbps.
    """

    BORDER_TITLE = "Internet tezligi"

    def compose(self) -> ComposeResult:
        yield Static(self._placeholder(), id="speed-readout")
        yield LoadingIndicator(id="speed-loading")
        yield Sparkline([0], summary_function=max, id="speed-spark")
        yield Static(self._stats_caption(None), id="speed-stats", classes="spark-caption")
        yield Button("Tezlikni o'lchash", id="run-speed", variant="primary")

    def on_mount(self) -> None:
        self._history: list[float] = []
        self.query_one("#speed-loading", LoadingIndicator).display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-speed":
            self.run_test()

    @work(exclusive=True)
    async def run_test(self) -> None:
        btn = self.query_one("#run-speed", Button)
        readout = self.query_one("#speed-readout", Static)
        spark = self.query_one("#speed-spark", Sparkline)
        stats = self.query_one("#speed-stats", Static)
        loading = self.query_one("#speed-loading", LoadingIndicator)

        btn.disabled = True
        btn.label = "O'lchanmoqda…"
        loading.display = True
        readout.update("[dim]Latency o'lchanmoqda…[/]")
        self._history = []

        def on_download(mbps: float) -> None:
            self._push(spark, stats, mbps)
            readout.update(
                f"⬇ Download   [b $success]{mbps:6.1f}[/] [dim]Mbps[/]   [dim]jarayonda…[/]"
            )

        def on_upload(mbps: float) -> None:
            self._push(spark, stats, mbps)
            readout.update(
                f"⬆ Upload     [b $secondary]{mbps:6.1f}[/] [dim]Mbps[/]   [dim]jarayonda…[/]"
            )

        try:
            result = await run_speedtest(on_download=on_download, on_upload=on_upload)
            readout.update(self._format(result))
            stats.update(self._stats_caption(self._history))
        except Exception as exc:  # tarmoq xatosi — UI yiqilmasin
            readout.update(f"[$error]✗ Xato:[/] {exc}")
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Qayta o'lchash"

    def _push(self, spark: Sparkline, stats: Static, mbps: float) -> None:
        self._history.append(round(mbps, 1))
        spark.data = self._history[-80:]
        stats.update(self._stats_caption(self._history))

    @staticmethod
    def _placeholder() -> str:
        return (
            "⬇ Download    [dim]—[/] [dim]Mbps[/]\n"
            "⬆ Upload      [dim]—[/] [dim]Mbps[/]\n"
            "⊚ Latency     [dim]—[/] [dim]ms[/]\n\n"
            "[dim]Boshlash uchun [b]s[/] yoki tugmani bosing.[/]"
        )

    @staticmethod
    def _stats_caption(history: list[float] | None) -> str:
        """Grafik ostidagi izoh: joriy / min / o'rt / maks (Mbps)."""
        if not history:
            return "[dim]joriy —   min —   o'rt —   maks —   Mbps[/]"
        cur = history[-1]
        lo = min(history)
        avg = sum(history) / len(history)
        hi = max(history)
        return (
            f"[dim]joriy[/] [b]{cur:.1f}[/]   "
            f"[dim]min[/] {lo:.1f}   "
            f"[dim]o'rt[/] {avg:.1f}   "
            f"[dim]maks[/] [b $success]{hi:.1f}[/]   [dim]Mbps[/]"
        )

    @staticmethod
    def _format(r: SpeedResult) -> str:
        return (
            f"⬇ Download   [b $success]{r.download_mbps:6.1f}[/] [dim]Mbps[/]\n"
            f"⬆ Upload     [b $secondary]{r.upload_mbps:6.1f}[/] [dim]Mbps[/]\n"
            f"⊚ Latency    [b]{r.latency_ms:5.1f}[/] [dim]ms[/]"
            f"   [dim]jitter[/] {r.jitter_ms:.1f} [dim]ms[/]"
        )
