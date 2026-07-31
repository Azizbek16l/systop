"""The topology/diagnostics panel — LAN, traceroute, port scan, DNS, bandwidth,
connections (6 tabs)."""

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
from systop.core.ports import parse_ports, parse_targets, scan_host
from systop.core.topology import discover_lan, trace_stream, traceroute
from systop.widgets._glyphs import dash, data_cell, ellipsis, glyph


def _fmt_bps(bps: float) -> str:
    """Turns bits per second into a human-readable unit (bps/Kbps/Mbps/Gbps)."""
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} Gbps"
    if bps >= 1e6:
        return f"{bps / 1e6:.1f} Mbps"
    if bps >= 1e3:
        return f"{bps / 1e3:.0f} Kbps"
    return f"{bps:.0f} bps"


class TopologyPanel(Vertical):
    """LAN hosts, the global path (traceroute), a port scan and DNS diagnostics.

    Every tab has its own LoadingIndicator; while work is running the button is
    disabled. In the empty state there is a placeholder, on an error a red
    message.
    """

    BORDER_TITLE = "Network diagnostics"
    BORDER_SUBTITLE = "l LAN scan"

    def compose(self) -> ComposeResult:
        with TabbedContent():
            with TabPane("LAN hosts", id="tab-lan"):
                with Horizontal(id="lan-controls"):
                    yield Button("Scan the LAN", id="scan-lan", variant="primary")
                    yield LoadingIndicator(id="lan-loading")
                yield Static(
                    f"[dim]{glyph('empty')}[/]\n\n"
                    "[dim]The LAN has not been scanned yet[/]\n"
                    f"[$secondary]l[/][dim] — a /24 ping sweep + ARP {glyph('sep')} "
                    "IP, MAC, vendor, hostname[/]",
                    id="lan-empty",
                    classes="empty-state",
                )
                yield DataTable(id="lan-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Path (traceroute)", id="tab-trace"):
                with Horizontal(id="trace-controls"):
                    yield Input(value="8.8.8.8", placeholder="address or domain", id="trace-target")
                    yield Checkbox("live (mtr)", id="trace-live")
                    yield Button("Traceroute", id="run-trace", variant="primary")
                    yield LoadingIndicator(id="trace-loading")
                yield Static(
                    "[dim]Enter an address and press [b]Enter[/] — the path will be shown.[/]",
                    id="trace-empty",
                    classes="empty-state",
                )
                yield DataTable(id="trace-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Port scan", id="tab-scan"):
                with Horizontal(id="scan-controls"):
                    yield Input(placeholder="host / CIDR / range: 10.0.0.0/24", id="scan-host")
                    yield Input(placeholder="ports: 22,80 (optional)", id="scan-ports")
                    yield Button("Scan", id="run-scan", variant="primary")
                    yield LoadingIndicator(id="scan-loading")
                yield Static(
                    "[dim]Enter a host, a CIDR (10.0.0.0/24) or a range (10.0.0.1-50) — "
                    "then press [b]Enter[/].[/]",
                    id="scan-empty",
                    classes="empty-state",
                )
                yield DataTable(id="scan-table", zebra_stripes=True, cursor_type="row")
            with TabPane("DNS", id="tab-dns"):
                with Horizontal(id="dns-controls"):
                    yield Input(placeholder="domain (google.com, for example)", id="dns-name")
                    yield Button("DNS", id="run-dns", variant="primary")
                    yield LoadingIndicator(id="dns-loading")
                yield Static(
                    "[dim]Enter a domain and press [b]Enter[/] — the servers will be compared.[/]",
                    id="dns-empty",
                    classes="empty-state",
                )
                yield DataTable(id="dns-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Bandwidth", id="tab-bw"):
                with Horizontal(id="bw-controls"):
                    yield Button("Start", id="run-bw", variant="primary")
                    yield LoadingIndicator(id="bw-loading")
                yield Static(
                    "[dim]For live RX/TX per interface press the [b]Start[/] button.[/]",
                    id="bw-empty",
                    classes="empty-state",
                )
                yield DataTable(id="bw-table", zebra_stripes=True, cursor_type="row")
            with TabPane("Connections", id="tab-conn"):
                with Horizontal(id="conn-controls"):
                    yield Button("Refresh", id="run-conn", variant="primary")
                    yield LoadingIndicator(id="conn-loading")
                yield Static(
                    "[dim]To see the active network connections press the [b]Refresh[/] button.[/]",
                    id="conn-empty",
                    classes="empty-state",
                )
                yield DataTable(id="conn-table", zebra_stripes=True, cursor_type="row")

    def on_mount(self) -> None:
        self.query_one("#lan-table", DataTable).add_columns(
            "IP", "MAC", "Vendor", "Hostname", "RTT ms", "Role"
        )
        self.query_one("#trace-table", DataTable).add_columns("#", "IP", "Hostname", "RTT ms")
        self.query_one("#scan-table", DataTable).add_columns("Port", "Service", "State", "RTT ms")
        self.query_one("#dns-table", DataTable).add_columns(
            "Server", "State", "RTT ms", "Addresses"
        )
        self.query_one("#bw-table", DataTable).add_columns(
            "Interface",
            f"{glyph('download')} RX",
            f"{glyph('upload')} TX",
            "Total",
            "RX pps",
            "TX pps",
        )
        self.query_one("#conn-table", DataTable).add_columns(
            "Proto", "Local", "Remote", "State", "PID", "Process"
        )
        # The initial state: the indicators and the tables are hidden, the
        # placeholder is visible.
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
        """Switches to the traceroute tab and focuses the address field."""
        self.query_one(TabbedContent).active = "tab-trace"
        self.query_one("#trace-target", Input).focus()

    @work(exclusive=True, group="lan")
    async def scan_lan(self) -> None:
        btn = self.query_one("#scan-lan", Button)
        table = self.query_one("#lan-table", DataTable)
        loading = self.query_one("#lan-loading", LoadingIndicator)
        empty = self.query_one("#lan-empty", Static)

        btn.disabled = True
        btn.label = f"Scanning{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        d = dash()
        try:
            hosts = await discover_lan(resolve=True)
            if not hosts:
                empty.update("[dim]No alive host was found.[/]")
                empty.display = True
                btn.label = "Scan again"
                return
            for h in hosts:
                role = f"[cyan]{glyph('gateway')} gateway[/]" if h.is_gateway else "[dim]host[/]"
                rtt = f"{h.rtt_ms:.1f}" if h.rtt_ms else f"[dim]{d}[/]"
                table.add_row(
                    data_cell(h.ip),
                    data_cell(h.mac, d),
                    data_cell(h.vendor, d),
                    data_cell(h.hostname, d),
                    rtt,
                    role,
                )
            table.display = True
            btn.label = f"Scan again ({len(hosts)} found)"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
            btn.label = "Scan the LAN"
        finally:
            loading.display = False
            btn.disabled = False

    @work(exclusive=True, group="trace")
    async def run_trace(self) -> None:
        target = self.query_one("#trace-target", Input).value.strip()
        if not target:
            return
        live = self.query_one("#trace-live", Checkbox).value
        # In live (mtr) mode the columns are different — we adapt the headers.
        self._set_trace_columns(live)
        if live:
            await self._run_trace_live(target)
        else:
            await self._run_trace_once(target)

    def _set_trace_columns(self, live: bool) -> None:
        """Adapts the traceroute table columns to the mode (plain or mtr)."""
        table = self.query_one("#trace-table", DataTable)
        table.clear(columns=True)
        if live:
            table.add_columns("#", "IP", "Hostname", "Loss %", "Avg", "Best", "Worst")
        else:
            table.add_columns("#", "IP", "Hostname", "RTT ms")

    async def _run_trace_once(self, target: str) -> None:
        """A one-shot traceroute — it measures the path once."""
        btn = self.query_one("#run-trace", Button)
        table = self.query_one("#trace-table", DataTable)
        loading = self.query_one("#trace-loading", LoadingIndicator)
        empty = self.query_one("#trace-empty", Static)

        btn.disabled = True
        btn.label = f"Tracing{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False

        d = dash()
        try:
            hops = await traceroute(target)
            if not hops:
                empty.update("[dim]The path could not be determined.[/]")
                empty.display = True
                return
            for hop in hops:
                if hop.alive:
                    rtt = self._rtt_cell(hop.rtt_ms)
                    addr = hop.address or "[dim]* * *[/]"
                else:
                    rtt = "[dim]*[/]"
                    addr = "[dim]* * *[/]"
                table.add_row(
                    str(hop.index),
                    addr if addr.startswith("[") else data_cell(addr),
                    data_cell(hop.hostname, d),
                    rtt,
                )
            table.display = True
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Traceroute"

    async def _run_trace_live(self, target: str) -> None:
        """A live (mtr) traceroute — it measures the path repeatedly and refreshes the table.

        On every cycle the whole table is redrawn (the hops accumulate). Because
        the worker is `exclusive=True`, starting it again or switching tabs stops
        the stream safely (the CancelledError is swallowed).
        """
        btn = self.query_one("#run-trace", Button)
        table = self.query_one("#trace-table", DataTable)
        loading = self.query_one("#trace-loading", LoadingIndicator)
        empty = self.query_one("#trace-empty", Static)

        btn.disabled = True
        btn.label = f"Tracing live{ellipsis()}"
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
                        addr if addr.startswith("[") else data_cell(addr),
                        data_cell(hop.hostname, d),
                        self._loss_cell(hop.loss_pct),
                        avg,
                        best,
                        worst,
                    )
                table.display = True
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
        finally:
            loading.display = False
            btn.disabled = False
            btn.label = "Traceroute"

    def _set_scan_columns(self, table: DataTable, sweep: bool) -> None:
        """Rebuilds the port scan table columns according to the mode.

        A single host -> a per-port view; a subnet -> a per-host summary.
        Textual DataTable columns are static, so they are rebuilt with
        `clear(columns=True)`.
        """
        wanted = (
            ("Host", "Open ports", "Services") if sweep else ("Port", "Service", "State", "RTT ms")
        )
        current = tuple(str(c.label) for c in table.columns.values())
        if current == wanted:
            table.clear()
            return
        table.clear(columns=True)
        table.add_columns(*wanted)

    async def _scan_sweep_rows(
        self,
        targets: list[str],
        ports: list[int] | None,
        table: DataTable,
        empty: Static,
        btn: Button,
    ) -> None:
        """A subnet/range scan — one row per host (the same as the CLI `scan CIDR`)."""
        from systop.core.ports import scan_targets, top_ports

        port_list = ports or top_ports(20)
        self._set_scan_columns(table, sweep=True)
        btn.label = f"Scanning ({len(targets)} hosts){ellipsis()}"
        sweep = await scan_targets(targets, ports=port_list, timeout=1.5, concurrency=64)
        if not sweep.responsive:
            empty.update(
                f"[dim]{sweep.scanned_hosts} hosts x {sweep.scanned_ports} ports "
                "were checked — no open port was found.[/]"
            )
            empty.display = True
            btn.label = "Scan again"
            return
        for h in sweep.responsive:
            table.add_row(
                data_cell(h.resolved_ip or h.host),
                data_cell(" ".join(str(p.port) for p in h.open_ports)),
                data_cell(", ".join(p.service or "?" for p in h.open_ports), dash()),
            )
        table.display = True
        btn.label = (
            f"Scan again ({len(sweep.responsive)}/{sweep.scanned_hosts} hosts, "
            f"{sweep.total_open} ports)"
        )

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
            empty.update(f"[red]{glyph('cross')} The list of ports is invalid.[/]")
            empty.display = True
            table.display = False
            return

        btn.disabled = True
        btn.label = f"Scanning{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        try:
            # The target may be a CIDR/range ("10.0.0.0/24", "10.0.0.1-50").
            # If it expands to many hosts we switch to sweep mode — the table
            # columns change with it (the DataTable columns are rebuilt
            # dynamically).
            targets = parse_targets(host, max_hosts=512)
            if len(targets) > 1:
                await self._scan_sweep_rows(targets, ports, table, empty, btn)
                return

            self._set_scan_columns(table, sweep=False)
            result = await scan_host(targets[0] if targets else host, ports=ports)
            if result.error:
                empty.update(f"[red]{glyph('cross')} {result.error}[/]")
                empty.display = True
                btn.label = "Scan"
                return
            open_ports = result.open_ports
            if not open_ports:
                empty.update(
                    f"[dim]{result.resolved_ip}: no open port "
                    f"({len(result.ports)} were checked).[/]"
                )
                empty.display = True
                btn.label = "Scan again"
                return
            for p in open_ports:
                table.add_row(
                    str(p.port),
                    data_cell(p.service, dash()),
                    "[green]open[/]",
                    self._rtt_cell(p.rtt_ms),
                )
            table.display = True
            btn.label = f"Scan again ({len(open_ports)}/{len(result.ports)} open)"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
            btn.label = "Scan"
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
        btn.label = f"Querying{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        d = dash()
        try:
            result = await diagnose_dns(name)
            # The system resolver's result — the first row.
            if result.system_error:
                table.add_row("System", "[red]error[/]", f"[dim]{d}[/]", result.system_error)
            else:
                joined = ", ".join(result.system_addresses[:3])
                table.add_row(
                    "System resolver", "[green]ok[/]", f"[dim]{d}[/]", data_cell(joined, d)
                )

            ok_resolvers = [r for r in result.resolvers if r.ok]
            fastest = min(ok_resolvers, key=lambda r: r.rtt_ms) if ok_resolvers else None
            for r in result.resolvers:
                if r.ok:
                    tag = f" [yellow]{glyph('fast')}[/]" if r is fastest else ""
                    addrs = ", ".join(r.addresses[:3])
                    table.add_row(
                        f"{r.name}{tag}",
                        "[green]ok[/]",
                        self._rtt_cell(r.rtt_ms),
                        data_cell(addrs, d),
                    )
                else:
                    table.add_row(r.name, f"[red]{d}[/]", f"[dim]{d}[/]", r.error or "error")

            if not result.tool:
                empty.update("[dim]Note: dig/nslookup was not found — the system resolver only.[/]")
                empty.display = True
            table.display = True
            btn.label = "Query again"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
            btn.label = "DNS"
        finally:
            loading.display = False
            btn.disabled = False

    def toggle_bandwidth(self) -> None:
        """Starts or stops the bandwidth stream (the button is a toggle)."""
        # We do not learn whether the worker is active from the button label —
        # we check the Textual worker state: if a worker is running in the "bw"
        # group, we stop it.
        running = [w for w in self.workers if w.group == "bw" and w.is_running]
        if running:
            self.workers.cancel_group(self, "bw")
            btn = self.query_one("#run-bw", Button)
            btn.label = "Start"
            btn.variant = "primary"
            self.query_one("#bw-loading", LoadingIndicator).display = False
            return
        self.stream_bandwidth()

    @work(exclusive=True, group="bw")
    async def stream_bandwidth(self) -> None:
        """The live per-interface RX/TX stream (bandwidth_stream)."""
        btn = self.query_one("#run-bw", Button)
        table = self.query_one("#bw-table", DataTable)
        loading = self.query_one("#bw-loading", LoadingIndicator)
        empty = self.query_one("#bw-empty", Static)

        btn.label = "Stop"
        btn.variant = "warning"
        loading.display = True
        empty.display = False

        try:
            async for rates in bandwidth_stream(interval=1.0):
                # We only show the interfaces that carried traffic or have a
                # name; the order is stable by name in the core.
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
                    empty.update("[dim]No active interface was found.[/]")
                    empty.display = True
                    table.display = False
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
            table.display = False
        finally:
            loading.display = False

    @work(exclusive=True, group="conn")
    async def load_connections(self) -> None:
        """Loads the active network connections into the table (list_connections)."""
        btn = self.query_one("#run-conn", Button)
        table = self.query_one("#conn-table", DataTable)
        loading = self.query_one("#conn-loading", LoadingIndicator)
        empty = self.query_one("#conn-empty", Static)

        btn.disabled = True
        btn.label = f"Loading{ellipsis()}"
        loading.display = True
        empty.display = False
        table.display = False
        table.clear()

        d = dash()
        try:
            # list_connections is synchronous and can be slow in psutil — we call
            # it in a thread so that the event loop is not blocked.
            conns = await asyncio.to_thread(list_connections, "inet")
            if not conns:
                empty.update(
                    "[dim]No connection was visible — on macOS the full list may "
                    "require [b]sudo[/].[/]"
                )
                empty.display = True
                btn.label = "Refresh"
                return
            for c in conns:
                table.add_row(
                    data_cell(c.proto),
                    data_cell(c.laddr, d),
                    data_cell(c.raddr, d),
                    self._status_cell(c.status),
                    str(c.pid) if c.pid is not None else f"[dim]{d}[/]",
                    data_cell(c.process, d),
                )
            table.display = True
            btn.label = f"Refresh ({len(conns)} found)"
        except Exception as exc:
            empty.update(f"[red]{glyph('cross')} Error:[/] {exc}")
            empty.display = True
            btn.label = "Refresh"
        finally:
            loading.display = False
            btn.disabled = False

    @staticmethod
    def _status_cell(status: str) -> str:
        """Colours the connection state (DataTable Rich markup)."""
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
        """Colours the packet loss percentage (DataTable Rich markup)."""
        if pct <= 0:
            return "[green]0[/]"
        if pct < 50:
            return f"[yellow]{pct:.0f}[/]"
        return f"[red]{pct:.0f}[/]"

    @staticmethod
    def _rtt_cell(ms: float) -> str:
        """Colours the RTT value (DataTable Rich markup)."""
        if ms < 30:
            return f"[green]{ms:.1f}[/]"
        if ms < 100:
            return f"[yellow]{ms:.1f}[/]"
        return f"[red]{ms:.1f}[/]"
