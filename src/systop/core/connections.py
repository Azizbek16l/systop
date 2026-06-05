"""Faol tarmoq ulanishlari ko'rinishi — `ss`/`bandwhich` connection-table o'rnida.

`psutil.net_connections(kind='inet')` socketlarni beradi; har bir ulanishning
PID'i bo'lsa, `psutil.Process(pid).name()` orqali jarayon nomi qo'shiladi.
Jarayon nomlari qisqa kesh'da saqlanadi (bir chaqiruvda bir PID ko'p marta
uchrashi mumkin). Ruxsat yetishmasa (AccessDenied) — toza yutiladi, bor
ma'lumot qaytariladi (ba'zi tizimlarda to'liq jadval uchun root kerak).

Faqat stdlib + psutil; boshqa core modullarni import qilmaydi.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

import psutil

# psutil socket statuslari Linux/macOS'da bir xil string'lar (CONN_*).
# None status — UDP yoki tinglovsiz socket (psutil ba'zan bo'sh qaytaradi).


@dataclass(slots=True)
class ConnInfo:
    """Bitta tarmoq ulanishi (socket) haqida ma'lumot."""

    proto: str  # "tcp" | "udp" | "tcp6" | "udp6"
    laddr: str  # "ip:port" (lokal)
    raddr: str  # "ip:port" (masofaviy) yoki "" agar yo'q bo'lsa
    status: str  # ESTABLISHED, LISTEN, ... yoki "" (UDP)
    pid: int | None = None
    process: str | None = None


def _proto_name(family: int, kind: int) -> str:
    """socket oilasi+turidan "tcp"/"udp"/"tcp6"/"udp6" nomini yasaydi."""
    base = "tcp" if kind == socket.SOCK_STREAM else "udp"
    return base + "6" if family == socket.AF_INET6 else base


def _fmt_addr(addr: object) -> str:
    """psutil addr (ip, port) named-tuple'ni "ip:port" satriga aylantiradi."""
    if not addr:
        return ""
    ip = getattr(addr, "ip", "") or ""
    port = getattr(addr, "port", "") or ""
    if ip and ":" in ip:
        # IPv6 — manzilni qavsga olib portdan ajratamiz.
        return f"[{ip}]:{port}" if port != "" else f"[{ip}]"
    return f"{ip}:{port}" if port != "" else ip


def list_connections(
    kind: str = "inet",
    states: list[str] | None = None,
) -> list[ConnInfo]:
    """Faol tarmoq ulanishlarini jarayon nomi bilan birga qaytaradi.

    kind — psutil `net_connections` turi ('inet', 'tcp', 'udp', 'inet4', ...).
    states — agar berilsa, faqat shu statuslar bilan ulanishlar qaytariladi
    (masalan ['ESTABLISHED', 'LISTEN']); katta-kichik harf farqi e'tiborsiz.

    Ruxsat yetishmasa yoki socketlarni o'qib bo'lmasa — bo'sh ro'yxat
    (xato ko'tarilmaydi). Ayrim socketlar uchun PID/jarayon noma'lum bo'lishi
    mumkin (ruxsat yoki socket egasi yo'qligi sababli).
    """
    wanted = {s.upper() for s in states} if states else None
    name_cache: dict[int, str | None] = {}
    result: list[ConnInfo] = []

    try:
        conns = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, psutil.Error, OSError, PermissionError):
        # Ba'zi tizimlarda to'liq jadval root talab qiladi — toza yutamiz.
        return result

    for c in conns:
        status = c.status if c.status and c.status != psutil.CONN_NONE else ""
        if wanted is not None and status.upper() not in wanted:
            continue

        pid = c.pid
        pname: str | None = None
        if pid is not None:
            if pid in name_cache:
                pname = name_cache[pid]
            else:
                try:
                    pname = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error, OSError):
                    pname = None
                name_cache[pid] = pname

        result.append(
            ConnInfo(
                proto=_proto_name(c.family, c.type),
                laddr=_fmt_addr(c.laddr),
                raddr=_fmt_addr(c.raddr),
                status=status,
                pid=pid,
                process=pname,
            )
        )

    # Barqaror tartib: proto, keyin lokal manzil bo'yicha.
    result.sort(key=lambda r: (r.proto, r.laddr))
    return result
