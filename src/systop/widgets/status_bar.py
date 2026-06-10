"""Holat-paneli — Header ostidagi ingichka qator: gateway / public IP / interfeys.

`gather_summary()` (core.netinfo) dan ma'lumot oladi va uchta "chip" ko'rinishida
ko'rsatadi. Tarmoq xatosi panelni yiqitmaydi — qiymatlar "—" bo'lib qoladi.
"""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from systop.core.netinfo import gather_summary, primary_interface
from systop.widgets._glyphs import dash, ellipsis, glyph


class StatusBar(Horizontal):
    """Tarmoq holatining yig'ma ko'rinishi: gateway, public IP, asosiy interfeys."""

    def compose(self) -> ComposeResult:
        loading = ellipsis()
        yield Static(self._chip("Gateway", loading), id="chip-gateway")
        yield Static(self._chip("Public IP", loading), id="chip-public")
        yield Static(self._chip("Interfeys", loading), id="chip-iface")

    def on_mount(self) -> None:
        # Mahalliy ma'lumotni darhol ko'rsatamiz, public IP'ni keyin to'ldiramiz.
        self._show_iface(primary_interface())
        self.load_summary()

    @work(exclusive=True)
    async def load_summary(self) -> None:
        d = dash()
        try:
            summary = await gather_summary()
        except Exception:
            # Tarmoq mavjud emas — placeholder bilan qoldiramiz, panel yiqilmasin.
            self.query_one("#chip-gateway", Static).update(self._chip("Gateway", d))
            self.query_one("#chip-public", Static).update(self._chip("Public IP", d))
            return

        gw = summary.gateway or d
        pub = summary.public_ip or d
        self.query_one("#chip-gateway", Static).update(self._chip("Gateway", gw))
        self.query_one("#chip-public", Static).update(self._chip("Public IP", pub))
        # Interfeysni primary_interface() aniqlaydi — APIPA (169.254) yoki
        # vEthernet emas, haqiqiy asosiy NIC. summary'dagi birinchi-ipv4
        # heuristikasidan ko'ra ishonchli (gateway bog'liqligini hisobga oladi).
        self._show_iface(primary_interface())

    def _show_iface(self, iface: object) -> None:
        """Interfeys chipini yangilaydi (`name · ipv4`); iface yo'q bo'lsa o'tkazadi."""
        if iface is None:
            return
        name = getattr(iface, "name", None)
        if not name:
            return
        ipv4 = getattr(iface, "ipv4", None) or dash()
        label = f"{name} {glyph('sep')} {ipv4}"
        self.query_one("#chip-iface", Static).update(self._chip("Interfeys", label))

    @staticmethod
    def _chip(title: str, value: str) -> str:
        """Bitta "chip": [dim sarlavha] qiymat."""
        return f"[dim]{title}[/]  [b]{value}[/]"
