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


class StatusBar(Horizontal):
    """Tarmoq holatining yig'ma ko'rinishi: gateway, public IP, asosiy interfeys."""

    def compose(self) -> ComposeResult:
        yield Static(self._chip("Gateway", "…"), id="chip-gateway")
        yield Static(self._chip("Public IP", "…"), id="chip-public")
        yield Static(self._chip("Interfeys", "…"), id="chip-iface")

    def on_mount(self) -> None:
        # Mahalliy ma'lumotni darhol ko'rsatamiz, public IP'ni keyin to'ldiramiz.
        iface = primary_interface()
        if iface:
            label = f"{iface.name} · {iface.ipv4 or '—'}"
            self.query_one("#chip-iface", Static).update(self._chip("Interfeys", label))
        self.load_summary()

    @work(exclusive=True)
    async def load_summary(self) -> None:
        try:
            summary = await gather_summary()
        except Exception:
            # Tarmoq mavjud emas — "—" bilan qoldiramiz, panel yiqilmasin.
            self.query_one("#chip-gateway", Static).update(self._chip("Gateway", "—"))
            self.query_one("#chip-public", Static).update(self._chip("Public IP", "—"))
            return

        gw = summary.gateway or "—"
        pub = summary.public_ip or "—"
        self.query_one("#chip-gateway", Static).update(self._chip("Gateway", gw))
        self.query_one("#chip-public", Static).update(self._chip("Public IP", pub))

        iface = next((i for i in summary.interfaces if i.ipv4), None)
        if iface:
            label = f"{iface.name} · {iface.ipv4}"
            self.query_one("#chip-iface", Static).update(self._chip("Interfeys", label))

    @staticmethod
    def _chip(title: str, value: str) -> str:
        """Bitta "chip": [dim sarlavha] qiymat."""
        return f"[dim]{title}[/]  [b]{value}[/]"
