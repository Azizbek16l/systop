"""The internet speed panel — download/upload measurement, a live graph and statistics."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, LoadingIndicator, Sparkline, Static

from systop.core.speed import SpeedResult, run_speedtest
from systop.widgets._glyphs import ellipsis, glyph, unicode_ok


class SpeedPanel(Vertical):
    """Runs the speed test when the button is pressed and shows the result.

    The states: empty (a placeholder) -> loading (a LoadingIndicator + live
    values) -> a result or an error. Below the graph: the current/min/avg/max
    Mbps.
    """

    BORDER_TITLE = "Internet speed"
    BORDER_SUBTITLE = "s start"

    def compose(self) -> ComposeResult:
        yield Static(self._placeholder(), id="speed-readout")
        yield LoadingIndicator(id="speed-loading")
        yield Sparkline([0], summary_function=max, id="speed-spark")
        yield Static(self._stats_caption(None), id="speed-stats", classes="spark-caption")
        yield Button("Measure the speed", id="run-speed", variant="primary")

    def on_mount(self) -> None:
        self._history: list[float] = []
        self.query_one("#speed-loading", LoadingIndicator).display = False
        # The graph is hidden while there is no data — so that no "fake" full
        # bar shows up in the idle state.
        self.query_one("#speed-spark", Sparkline).display = False

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

        ell = ellipsis()
        btn.disabled = True
        btn.label = f"Measuring{ell}"
        loading.display = True
        readout.update(f"[dim]Measuring the latency{ell}[/]")
        self._history = []
        spark.display = False  # a new test — the graph stays hidden until data arrives

        def on_download(mbps: float) -> None:
            self._progress(readout, spark, stats, glyph("download"), "Download", "$success", mbps)

        def on_upload(mbps: float) -> None:
            self._progress(readout, spark, stats, glyph("upload"), "Upload", "$secondary", mbps)

        try:
            result = await run_speedtest(on_download=on_download, on_upload=on_upload)
            readout.update(self._format(result))
            stats.update(self._stats_caption(self._history))
        except Exception as exc:  # a network error — the UI must not crash
            readout.update(f"[$error]{glyph('cross')} Error:[/] {exc}")
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Measure again"

    def _progress(
        self,
        readout: Static,
        spark: Sparkline,
        stats: Static,
        icon: str,
        label: str,
        color: str,
        mbps: float,
    ) -> None:
        """Shows the live state of a phase (download/upload).

        During the warmup the core sends `mbps=0.0` (the TCP slow-start bytes do
        not enter the measurement). At such a moment "0.0 in progress" looks
        stuck — instead of that we show "warming up…" and add no 0 to the graph
        (so that the statistics are not spoiled). Once the real measurement
        begins (mbps>0) it goes back to the usual display.
        """
        ell = ellipsis()
        if mbps <= 0.0:
            readout.update(
                f"{icon} {label:<10}[dim]warming up{ell}[/]   [dim]preparing the connection[/]"
            )
            return
        self._push(spark, stats, mbps)
        readout.update(
            f"{icon} {label:<10}[b {color}]{mbps:6.1f}[/] [dim]Mbps[/]   [dim]in progress{ell}[/]"
        )

    def _push(self, spark: Sparkline, stats: Static, mbps: float) -> None:
        self._history.append(round(mbps, 1))
        spark.data = self._history[-80:]
        # There is data — we show the graph (in ASCII mode the block characters
        # do not render, which is why it is conditioned on unicode_ok()).
        spark.display = unicode_ok()
        stats.update(self._stats_caption(self._history))

    @staticmethod
    def _placeholder() -> str:
        d = glyph("dash")
        return (
            f"{glyph('download')} Download    [dim]{d}[/] [dim]Mbps[/]\n"
            f"{glyph('upload')} Upload      [dim]{d}[/] [dim]Mbps[/]\n"
            f"{glyph('latency')} Latency     [dim]{d}[/] [dim]ms[/]\n\n"
            "[dim]Press [b]s[/] or the button to start.[/]"
        )

    @staticmethod
    def _stats_caption(history: list[float] | None) -> str:
        """The caption below the graph: current / min / avg / max (Mbps)."""
        if not history:
            d = glyph("dash")
            return f"[dim]cur {d}   min {d}   avg {d}   max {d}   Mbps   ·   test not started[/]"
        cur = history[-1]
        lo = min(history)
        avg = sum(history) / len(history)
        hi = max(history)
        return (
            f"[dim]cur[/] [b]{cur:.1f}[/]   "
            f"[dim]min[/] {lo:.1f}   "
            f"[dim]avg[/] {avg:.1f}   "
            f"[dim]max[/] [b $success]{hi:.1f}[/]   [dim]Mbps[/]"
        )

    @staticmethod
    def _format(r: SpeedResult) -> str:
        return (
            f"{glyph('download')} Download   [b $success]{r.download_mbps:6.1f}[/] [dim]Mbps[/]\n"
            f"{glyph('upload')} Upload     [b $secondary]{r.upload_mbps:6.1f}[/] [dim]Mbps[/]\n"
            f"{glyph('latency')} Latency    [b]{r.latency_ms:5.1f}[/] [dim]ms[/]"
            f"   [dim]jitter[/] {r.jitter_ms:.1f} [dim]ms[/]"
        )
