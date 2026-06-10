"""Topologiya/diagnostika paneli — LAN, traceroute, port skan, DNS, bandwidth,
ulanishlar (6 tab)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    LoadingIndicator,
    Static,
    TabbedContent,
    TabPane,
)

from systop.core.bandwidth import bandwidth_stream
from systop.core.connections import list_connections
from systop.core.dns import diagnose_dns
from systop.core.ports import parse_ports, scan_host
from systop.core.topology import discover_lan, trace_stream, traceroute
from systop.widgets._glyphs import dash, ellipsis, glyph


def _fmt_bps(bps: float) -> str:
    """bit/sekundni inson o'qiy oladigan birlikka aylantiradi (bps/Kbps/Mbps/Gbps)."""
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} Gbps"
    if bps >= 1e6:
        return f"{bps / 1e6:.1f} Mbps"
    if bps >= 1e3:
        return f"{bps / 1e3:.0f} Kbps"
    return f"{bps:.0f} bps"


class TopologyPanel(Vertical):
    """LAN hostlar, global yo'l (traceroute), port skan va DNS diagnostika.

    Har bir tab o'z LoadingIndicator'iga ega; ish davomida tugma disable
    bo'ladi. Bo'sh holatda o'zbekcha placeholder, xatoda qizil xabar.
    """

    BORDER_TITLE = "Tarmoq diagnostikasi"

    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("LAN hostlar", id="tab-lan"):
                with Horizontal(id="lan-controls"):
                    yield Button("LAN ni skanerlash", id="scan-lan", variant="primary")
                    yield LoadingIndicator(id="lan-loading")
                yield Static(
                    "[dim]LAN hostlarni ko'rish uchun [b]l[/] yoki tugmani bosing.[/]",
                    id="lan-empty",
                    classes="empty-state",
                )
                yield DataTable(id="lan-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Yo'l (traceroute)", id="tab-trace"):
                with Horizontal(id="trace-controls"):
                    yield Input(value="8.8.8.8", placeholder="manzil yoki domen", id="trace-target")
                    yield Checkbox("jonli (mtr)", id="trace-live")
                    yield Button("Traceroute", id="run-trace", variant="primary")
                    yield LoadingIndicator(id="trace-loading")
                yield Static(
                    "[dim]Manzil kiriting va [b]Enter[/] bosing — yo'l ko'rsatiladi.[/]",
                    id="trace-empty",
                    classes="empty-state",
                )
                yield DataTable(id="trace-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Port skan", id="tab-scan"):
                with Horizontal(id="scan-controls"):
                    yield Input(placeholder="host (IP yoki domen)", id="scan-host")
                    yield Input(placeholder="portlar: 22,80 (ixtiyoriy)", id="scan-ports")
                    yield Button("Skan", id="run-scan", variant="primary")
                    yield LoadingIndicator(id="scan-loading")
                yield Static(
                    "[dim]Host kiriting va [b]Enter[/] bosing — ochiq portlar topiladi.[/]",
                    id="scan-empty",
                    classes="empty-state",
                )
                yield DataTable(id="scan-table", zebra_stripes=True, cursor_type="row")
            with TabPane("DNS", id="tab-dns"):
                with Horizontal(id="dns-controls"):
                    yield Input(placeholder="domen (masalan google.com)", id="dns-name")
                    yield Button("DNS", id="run-dns", variant="primary")
                    yield LoadingIndicator(id="dns-loading")
                yield Static(
                    "[dim]Domen kiriting va [b]Enter[/] bosing — serverlar taqqoslanadi.[/]",
                    id="dns-empty",
                    classes="empty-state",
                )
                yield DataTable(id="dns-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Bandwidth", id="tab-bw"):
                with Horizontal(id="bw-controls"):
                    yield Button("Boshlash", id="run-bw", variant="primary")
                    yield LoadingIndicator(id="bw-loading")
                yield Static(
                    "[dim]Interfeyslar bo'yicha jonli RX/TX uchun "
                    "[b]Boshlash[/] tugmasini bosing.[/]",
                    id="bw-empty",
                    classes="empty-state",
                )
                yield DataTable(id="bw-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Ulanishlar", id="tab-conn"):
                with Horizontal(id="conn-controls"):
                    yield Button("Yangilash", id="run-conn", variant="primary")
                    yield LoadingIndicator(id="conn-loading")
                yield Static(
                    "[dim]Faol tarmoq ulanishlarini ko'rish uchun "
                    "[b]Yangilash[/] tugmasini bosing.[/]",
                    id="conn-empty",
                    classes="empty-state",
                )
                yield DataTable(id="conn-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#lan-table", DataTable).add_columns(
            "IP", "MAC", "Vendor", "Hostname", "RTT ms", "Rol"
        )
        self.query_one("#trace-table", DataTable).add_columns("#", "IP", "Hostname", "RTT ms")
        self.query_one("#scan-table", DataTable).add_columns("Port", "Xizmat", "Holat", "RTT ms")
        self.query_one("#dns-table", DataTable).add_columns(
            "Server", "Holat", "RTT ms", "Manzillar"
        )
        self.query_one("#bw-table", DataTable).add_columns(
            "Interfeys",
            f"{glyph('download')} RX",
            f"{glyph('upload')} TX",
            "Jami",
            "RX pps",
            "TX pps",
        )
        self.query_one("#conn-table", DataTable).add_columns(
            "Proto", "Lokal", "Masofaviy", "Holat", "PID", "Jarayon"
        )
        # Boshlang'ich holat: indikatorlar va jadvallar yashirin, placeholder ko'rinadi.
        for loader in (
            "#lan-loading",
            "#trace-loading",
            "#scan-loading",
            "#dns-loading",
            "#bw-loading",
            "#conn-loading",
        ):
            self.query_one(loader, LoadingIndicator).display = False
        for table in (
            "#lan-table",
            "#trace-table",
            "#scan-table",
            "#dns-table",
            "#bw-table",
            "#conn-table",
        ):
            self.query_one(table, DataTable).display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions: dict[str, Callable[[], object]] = {
            "scan-lan": self.scan_lan,
            "run-trace": self.run_trace,
            "run-scan": self.scan_ports,
            "run-dns": self.run_dns,
            "run-bw": self.toggle_bandwidth,
            "run-conn": self.load_connections,
        }
        action = actions.get(event.button.id or "")
        if action:
            action()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        dispatch = {
            "trace-target": self.run_trace,
            "scan-host": self.scan_ports,
            "scan-ports": self.scan_ports,
            "dns-name": self.run_dns,
        }
        action = dispatch.get(event.input.id or "")
        if action:
            action()

    def focus_trace(self) -> None:
        """Traceroute tab'iga o'tib, manzil maydoniga fokus beradi."""
        self.query_one(TabbedContent).active = "tab-trace"
        self.query_one("#trace-target", Input).focus()

    @work(exclusive=True, group="lan")
    async def scan_lan(self) -> None:
        btn = self.query_one("#scan-lan", Button)
        table = self.query_one("#lan-table", DataTable)
        loading = self.query_one("#lan-loading", LoadingIndicator)
        empty = self.query_one("#lan-empty", Static)

        btn.disabled = True
        btn.label = f"Skanerlanmoqda{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        d = dash()
        try:
            hosts = await discover_lan(resolve=True)
            if not hosts:
                empty.update("[dim]Tirik host topilmadi.[/]")
                empty.display = True
                btn.label = "Qayta skanerlash"
                return
            for h in hosts:
                role = f"[cyan]{glyph('gateway')} gateway[/]" if h.is_gateway else "[dim]host[/]"
                rtt = f"{h.rtt_ms:.1f}" if h.rtt_ms else f"[dim]{d}[/]"
                table.add_row(
                    h.ip,
                    h.mac or f"[dim]{d}[/]",
                    h.vendor or f"[dim]{d}[/]",
                    h.hostname or f"[dim]{d}[/]",
                    rtt,
                    role,
                )
            table.display = True
            btn.label = f"Qayta skanerlash ({len(hosts)} ta)"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
            btn.label = "LAN ni skanerlash"
        finally:
            loading.display = False
            btn.disabled = False

    @work(exclusive=True, group="trace")
    async def run_trace(self) -> None:
        target = self.query_one("#trace-target", Input).value.strip()
        if not target:
            return
        live = self.query_one("#trace-live", Checkbox).value
        # Jonli (mtr) rejimda ustunlar boshqacha — sarlavhalarni moslaymiz.
        self._set_trace_columns(live)
        if live:
            await self._run_trace_live(target)
        else:
            await self._run_trace_once(target)

    def _set_trace_columns(self, live: bool) -> None:
        """Traceroute jadval ustunlarini rejimga moslaydi (oddiy yoki mtr)."""
        table = self.query_one("#trace-table", DataTable)
        table.clear(columns=True)
        if live:
            table.add_columns("#", "IP", "Hostname", "Loss %", "Avg", "Best", "Worst")
        else:
            table.add_columns("#", "IP", "Hostname", "RTT ms")

    async def _run_trace_once(self, target: str) -> None:
        """Bir martalik traceroute — yo'lni bir marta o'lchaydi."""
        btn = self.query_one("#run-trace", Button)
        table = self.query_one("#trace-table", DataTable)
        loading = self.query_one("#trace-loading", LoadingIndicator)
        empty = self.query_one("#trace-empty", Static)

        btn.disabled = True
        btn.label = f"Kuzatilmoqda{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False

        d = dash()
        try:
            hops = await traceroute(target)
            if not hops:
                empty.update("[dim]Yo'l aniqlanmadi.[/]")
                empty.display = True
                return
            for hop in hops:
                if hop.alive:
                    rtt = self._rtt_cell(hop.rtt_ms)
                    addr = hop.address or "[dim]* * *[/]"
                else:
                    rtt = "[dim]*[/]"
                    addr = "[dim]* * *[/]"
                table.add_row(str(hop.index), addr, hop.hostname or f"[dim]{d}[/]", rtt)
            table.display = True
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Traceroute"

    async def _run_trace_live(self, target: str) -> None:
        """Jonli (mtr) traceroute — yo'lni qayta-qayta o'lchab jadvalni yangilaydi.

        Har siklda butun jadval qayta chiziladi (hop'lar to'planib boradi). Worker
        `exclusive=True` bo'lgani uchun yangi ishga tushirish yoki tab almashish
        oqimni xavfsiz to'xtatadi (CancelledError yutiladi).
        """
        btn = self.query_one("#run-trace", Button)
        table = self.query_one("#trace-table", DataTable)
        loading = self.query_one("#trace-loading", LoadingIndicator)
        empty = self.query_one("#trace-empty", Static)

        btn.disabled = True
        btn.label = f"Jonli kuzatilmoqda{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False

        d = dash()
        try:
            async for hops in trace_stream(target, interval=1.0):
                table.clear()
                for hop in hops:
                    addr = hop.address or "[dim]* * *[/]"
                    if hop.recv == 0:
                        avg = best = worst = "[dim]*[/]"
                    else:
                        avg = self._rtt_cell(hop.avg_rtt)
                        best = f"[dim]{hop.best_rtt:.1f}[/]"
                        worst = f"[dim]{hop.worst_rtt:.1f}[/]"
                    table.add_row(
                        str(hop.index),
                        addr,
                        hop.hostname or f"[dim]{d}[/]",
                        self._loss_cell(hop.loss_pct),
                        avg,
                        best,
                        worst,
                    )
                table.display = True
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Traceroute"

    @work(exclusive=True, group="scan")
    async def scan_ports(self) -> None:
        host = self.query_one("#scan-host", Input).value.strip()
        if not host:
            return
        ports_spec = self.query_one("#scan-ports", Input).value.strip()
        btn = self.query_one("#run-scan", Button)
        table = self.query_one("#scan-table", DataTable)
        loading = self.query_one("#scan-loading", LoadingIndicator)
        empty = self.query_one("#scan-empty", Static)

        ports = parse_ports(ports_spec) if ports_spec else None
        if ports_spec and not ports:
            empty.update(f"[red]{glyph('cross')} Portlar ro'yxati noto'g'ri.[/]")
            empty.display = True
            table.display = False
            return

        btn.disabled = True
        btn.label = f"Skanerlanmoqda{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        try:
            result = await scan_host(host, ports=ports)
            if result.error:
                empty.update(f"[red]{glyph('cross')} {result.error}[/]")
                empty.display = True
                btn.label = "Skan"
                return
            open_ports = result.open_ports
            if not open_ports:
                empty.update(
                    f"[dim]{result.resolved_ip}: ochiq port yo'q "
                    f"({len(result.ports)} ta tekshirildi).[/]"
                )
                empty.display = True
                btn.label = "Qayta skan"
                return
            for p in open_ports:
                table.add_row(
                    str(p.port),
                    p.service or f"[dim]{dash()}[/]",
                    "[green]ochiq[/]",
                    self._rtt_cell(p.rtt_ms),
                )
            table.display = True
            btn.label = f"Qayta skan ({len(open_ports)}/{len(result.ports)} ochiq)"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
            btn.label = "Skan"
        finally:
            loading.display = False
            btn.disabled = False

    @work(exclusive=True, group="dns")
    async def run_dns(self) -> None:
        name = self.query_one("#dns-name", Input).value.strip()
        if not name:
            return
        btn = self.query_one("#run-dns", Button)
        table = self.query_one("#dns-table", DataTable)
        loading = self.query_one("#dns-loading", LoadingIndicator)
        empty = self.query_one("#dns-empty", Static)

        btn.disabled = True
        btn.label = f"So'ralmoqda{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        d = dash()
        try:
            result = await diagnose_dns(name)
            # Tizim resolveri natijasi — birinchi qator.
            if result.system_error:
                table.add_row("Tizim", "[red]xato[/]", f"[dim]{d}[/]", result.system_error)
            else:
                addrs = ", ".join(result.system_addresses[:3]) or f"[dim]{d}[/]"
                table.add_row("Tizim resolver", "[green]ok[/]", f"[dim]{d}[/]", addrs)

            ok_resolvers = [r for r in result.resolvers if r.ok]
            fastest = min(ok_resolvers, key=lambda r: r.rtt_ms) if ok_resolvers else None
            for r in result.resolvers:
                if r.ok:
                    tag = f" [yellow]{glyph('fast')}[/]" if r is fastest else ""
                    addrs = ", ".join(r.addresses[:3])
                    table.add_row(f"{r.name}{tag}", "[green]ok[/]", self._rtt_cell(r.rtt_ms), addrs)
                else:
                    table.add_row(r.name, f"[red]{d}[/]", f"[dim]{d}[/]", r.error or "xato")

            if not result.tool:
                empty.update("[dim]Eslatma: dig/nslookup topilmadi — faqat tizim resolveri.[/]")
                empty.display = True
            table.display = True
            btn.label = "Qayta so'rash"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
            btn.label = "DNS"
        finally:
            loading.display = False
            btn.disabled = False

    def toggle_bandwidth(self) -> None:
        """Bandwidth oqimini boshlaydi yoki to'xtatadi (tugma — toggle)."""
        # Worker faolligini tugma yorlig'idan bilmaymiz — Textual worker holatini
        # tekshiramiz: agar "bw" guruhida ishlayotgan worker bo'lsa, to'xtatamiz.
        running = [w for w in self.workers if w.group == "bw" and w.is_running]
        if running:
            self.workers.cancel_group(self, "bw")
            btn = self.query_one("#run-bw", Button)
            btn.label = "Boshlash"
            btn.variant = "primary"
            self.query_one("#bw-loading", LoadingIndicator).display = False
            return
        self.stream_bandwidth()

    @work(exclusive=True, group="bw")
    async def stream_bandwidth(self) -> None:
        """Per-interfeys jonli RX/TX oqimi (bandwidth_stream)."""
        btn = self.query_one("#run-bw", Button)
        table = self.query_one("#bw-table", DataTable)
        loading = self.query_one("#bw-loading", LoadingIndicator)
        empty = self.query_one("#bw-empty", Static)

        btn.label = "To'xtatish"
        btn.variant = "warning"
        loading.display = True
        empty.display = False

        try:
            async for rates in bandwidth_stream(interval=1.0):
                # Faqat trafik bo'lgan yoki nomli interfeyslarni ko'rsatamiz;
                # tartib core'da nom bo'yicha barqaror.
                active = [r for r in rates if r.total_bps > 0] or rates
                table.clear()
                for r in active:
                    table.add_row(
                        r.name,
                        f"[green]{_fmt_bps(r.rx_bps)}[/]",
                        f"[cyan]{_fmt_bps(r.tx_bps)}[/]",
                        f"[b]{_fmt_bps(r.total_bps)}[/]",
                        f"[dim]{r.rx_pps:.0f}[/]",
                        f"[dim]{r.tx_pps:.0f}[/]",
                    )
                if table.row_count:
                    table.display = True
                    empty.display = False
                else:
                    empty.update("[dim]Faol interfeys topilmadi.[/]")
                    empty.display = True
                    table.display = False
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
            table.display = False
        finally:
            loading.display = False

    @work(exclusive=True, group="conn")
    async def load_connections(self) -> None:
        """Faol tarmoq ulanishlarini jadvalga yuklaydi (list_connections)."""
        btn = self.query_one("#run-conn", Button)
        table = self.query_one("#conn-table", DataTable)
        loading = self.query_one("#conn-loading", LoadingIndicator)
        empty = self.query_one("#conn-empty", Static)

        btn.disabled = True
        btn.label = f"Yuklanmoqda{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        d = dash()
        try:
            # list_connections sinxron va psutil'da sekin bo'lishi mumkin —
            # event loop bloklanmasligi uchun thread'da chaqiramiz.
            conns = await asyncio.to_thread(list_connections, "inet")
            if not conns:
                empty.update(
                    "[dim]Ulanishlar ko'rinmadi — macOS'da to'liq ro'yxat uchun "
                    "[b]sudo[/] kerak bo'lishi mumkin.[/]"
                )
                empty.display = True
                btn.label = "Yangilash"
                return
            for c in conns:
                table.add_row(
                    c.proto,
                    c.laddr or f"[dim]{d}[/]",
                    c.raddr or f"[dim]{d}[/]",
                    self._status_cell(c.status),
                    str(c.pid) if c.pid is not None else f"[dim]{d}[/]",
                    c.process or f"[dim]{d}[/]",
                )
            table.display = True
            btn.label = f"Yangilash ({len(conns)} ta)"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Xato:[/] {exc}")
            empty.display = True
            btn.label = "Yangilash"
        finally:
            loading.display = False
            btn.disabled = False

    @staticmethod
    def _status_cell(status: str) -> str:
        """Ulanish holatini ranglaydi (DataTable Rich markup)."""
        if not status:
            return f"[dim]{dash()}[/]"
        up = status.upper()
        if up == "ESTABLISHED":
            return f"[green]{status}[/]"
        if up == "LISTEN":
            return f"[cyan]{status}[/]"
        if up in ("CLOSE_WAIT", "TIME_WAIT", "CLOSING", "LAST_ACK", "FIN_WAIT1", "FIN_WAIT2"):
            return f"[yellow]{status}[/]"
        return f"[dim]{status}[/]"

    @staticmethod
    def _loss_cell(pct: float) -> str:
        """Paket yo'qotish foizini ranglaydi (DataTable Rich markup)."""
        if pct <= 0:
            return "[green]0[/]"
        if pct < 50:
            return f"[yellow]{pct:.0f}[/]"
        return f"[red]{pct:.0f}[/]"

    @staticmethod
    def _rtt_cell(ms: float) -> str:
        """RTT qiymatini ranglaydi (DataTable Rich markup)."""
        if ms < 30:
            return f"[green]{ms:.1f}[/]"
        if ms < 100:
            return f"[yellow]{ms:.1f}[/]"
        return f"[red]{ms:.1f}[/]"
