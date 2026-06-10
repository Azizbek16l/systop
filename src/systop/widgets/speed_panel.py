"""Internet tezligi paneli — download/upload o'lchovi, jonli grafik va statistika."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, LoadingIndicator, Sparkline, Static

from systop.core.speed import SpeedResult, run_speedtest
from systop.widgets._glyphs import ellipsis, glyph, unicode_ok


class SpeedPanel(Vertical):
    """Tugma bosilganda tezlik testini ishga tushiradi, natijani ko'rsatadi.

    Holatlar: bo'sh (placeholder) → yuklanmoqda (LoadingIndicator + jonli
    qiymatlar) → natija yoki xato. Grafik ostida joriy/min/o'rt/maks Mbps.
    """

    BORDER_TITLE = "Internet tezligi"
    BORDER_SUBTITLE = "s boshlash"

    def compose(self) -> ComposeResult:
        yield Static(self._placeholder(), id="speed-readout")
        yield LoadingIndicator(id="speed-loading")
        yield Sparkline([0], summary_function=max, id="speed-spark")
        yield Static(self._stats_caption(None), id="speed-stats", classes="spark-caption")
        yield Button("Tezlikni o'lchash", id="run-speed", variant="primary")

    def on_mount(self) -> None:
        self._history: list[float] = []
        self.query_one("#speed-loading", LoadingIndicator).display = False
        # Grafik ma'lumotsiz yashirin — idle holatda "soxta" to'liq bar ko'rinmasin.
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
        btn.label = f"O'lchanmoqda{ell}"
        loading.display = True
        readout.update(f"[dim]Latency o'lchanmoqda{ell}[/]")
        self._history = []
        spark.display = False  # yangi test — ma'lumot kelguncha grafik yashirin

        def on_download(mbps: float) -> None:
            self._progress(readout, spark, stats, glyph("download"), "Download", "$success", mbps)

        def on_upload(mbps: float) -> None:
            self._progress(readout, spark, stats, glyph("upload"), "Upload", "$secondary", mbps)

        try:
            result = await run_speedtest(on_download=on_download, on_upload=on_upload)
            readout.update(self._format(result))
            stats.update(self._stats_caption(self._history))
        except Exception as exc:  # tarmoq xatosi — UI yiqilmasin
            readout.update(f"[$error]{glyph('cross')} Xato:[/] {exc}")
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Qayta o'lchash"

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
        """Bosqich (download/upload) jonli holatini ko'rsatadi.

        Warmup paytida core `mbps=0.0` yuboradi (TCP slow-start baytlari o'lchovga
        kirmaydi). Bunday paytda "0.0 jarayonda" osilgandek ko'rinadi — shuning
        o'rniga "isinmoqda…" deb ko'rsatamiz va grafikka 0 qo'shmaymiz (statistika
        buzilmasin). Haqiqiy o'lchov boshlangach (mbps>0) odatdagi ko'rinish.
        """
        ell = ellipsis()
        if mbps <= 0.0:
            readout.update(
                f"{icon} {label:<10}[dim]isinmoqda{ell}[/]   [dim]ulanish tayyorlanmoqda[/]"
            )
            return
        self._push(spark, stats, mbps)
        readout.update(
            f"{icon} {label:<10}[b {color}]{mbps:6.1f}[/] [dim]Mbps[/]   [dim]jarayonda{ell}[/]"
        )

    def _push(self, spark: Sparkline, stats: Static, mbps: float) -> None:
        self._history.append(round(mbps, 1))
        spark.data = self._history[-80:]
        # Ma'lumot bor — grafikni ko'rsatamiz (ASCII rejimda block belgilar
        # ko'rinmaydi, shu sababli unicode_ok() bilan shartlaymiz).
        spark.display = unicode_ok()
        stats.update(self._stats_caption(self._history))

    @staticmethod
    def _placeholder() -> str:
        d = glyph("dash")
        return (
            f"{glyph('download')} Download    [dim]{d}[/] [dim]Mbps[/]\n"
            f"{glyph('upload')} Upload      [dim]{d}[/] [dim]Mbps[/]\n"
            f"{glyph('latency')} Latency     [dim]{d}[/] [dim]ms[/]\n\n"
            "[dim]Boshlash uchun [b]s[/] yoki tugmani bosing.[/]"
        )

    @staticmethod
    def _stats_caption(history: list[float] | None) -> str:
        """Grafik ostidagi izoh: joriy / min / o'rt / maks (Mbps)."""
        if not history:
            d = glyph("dash")
            return (
                f"[dim]joriy {d}   min {d}   o'rt {d}   maks {d}   Mbps   ·   test boshlanmagan[/]"
            )
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
            f"{glyph('download')} Download   [b $success]{r.download_mbps:6.1f}[/] [dim]Mbps[/]\n"
            f"{glyph('upload')} Upload     [b $secondary]{r.upload_mbps:6.1f}[/] [dim]Mbps[/]\n"
            f"{glyph('latency')} Latency    [b]{r.latency_ms:5.1f}[/] [dim]ms[/]"
            f"   [dim]jitter[/] {r.jitter_ms:.1f} [dim]ms[/]"
        )
