"""The status bar — a thin row under the Header: gateway / public IP / interface.

It takes its data from `gather_summary()` (core.netinfo) and shows it as three
"chips". A network error does not bring the panel down — the values simply stay
at "—".
"""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from systop.core.netinfo import gather_summary, primary_interface
from systop.widgets._glyphs import dash, ellipsis, glyph


class StatusBar(Horizontal):
    """An aggregate view of the network state: gateway, public IP, primary interface."""

    def compose(self) -> ComposeResult:
        loading = ellipsis()
        yield Static(self._chip("Gateway", loading), id="chip-gateway")
        yield Static(self._chip("Public IP", loading), id="chip-public")
        yield Static(self._chip("Interface", loading), id="chip-iface")

    def on_mount(self) -> None:
        # We show the local data straight away and fill in the public IP later.
        self._show_iface(primary_interface())
        self.load_summary()

    @work(exclusive=True)
    async def load_summary(self) -> None:
        d = dash()
        try:
            summary = await gather_summary()
        except Exception:
            # There is no network — we leave the placeholders in place so that
            # the panel does not crash.
            self.query_one("#chip-gateway", Static).update(self._chip("Gateway", d))
            self.query_one("#chip-public", Static).update(self._chip("Public IP", d))
            return

        # We append the prefix next to the gateway (`10.0.0.1/24`) — so that the
        # size of the network is visible at a glance. The prefix is taken from
        # the primary interface's mask, because the gateway sits on that segment.
        iface = primary_interface()
        gw = summary.gateway or d
        if summary.gateway and iface is not None and iface.prefixlen is not None:
            gw = f"{summary.gateway}/{iface.prefixlen}"
        pub = summary.public_ip or d
        self.query_one("#chip-gateway", Static).update(self._chip("Gateway", gw))
        self.query_one("#chip-public", Static).update(self._chip("Public IP", pub))
        # The interface is determined by primary_interface() — the real primary
        # NIC, not an APIPA (169.254) or a vEthernet one. That is more reliable
        # than the first-ipv4 heuristic in the summary (it takes the gateway
        # relationship into account).
        self._show_iface(primary_interface())

    def _show_iface(self, iface: object) -> None:
        """Updates the interface chip (`name · ipv4`); skips it if there is no iface."""
        if iface is None:
            return
        name = getattr(iface, "name", None)
        if not name:
            return
        ipv4 = getattr(iface, "ipv4", None) or dash()
        label = f"{name} {glyph('sep')} {ipv4}"
        self.query_one("#chip-iface", Static).update(self._chip("Interface", label))

    @staticmethod
    def _chip(title: str, value: str) -> str:
        """A single "chip": [dim title] value."""
        return f"[dim]{title}[/]  [b]{value}[/]"
