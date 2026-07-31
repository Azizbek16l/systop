"""Faol tarmoq ulanishlari ko'rinishi — `ss`/`bandwhich` connection-table o'rnida.

`psutil.net_connections(kind='inet')` socketlarni beradi; har bir ulanishning
PID'i bo'lsa, `psutil.Process(pid).name()` orqali jarayon nomi qo'shiladi.
Jarayon nomlari qisqa kesh'da saqlanadi (bir chaqiruvda bir PID ko'p marta
uchrashi mumkin). Ruxsat yetishmasa (AccessDenied) — toza yutiladi, bor
ma'lumot qaytariladi (ba'zi tizimlarda to'liq jadval uchun root kerak).

**macOS'da `psutil.net_connections()` root'siz HAR DOIM `AccessDenied`
ko'taradi** — bu psutil xatosi emas, `_psosx.py` barcha PID'lar bo'ylab
yuradi va begona jarayonga yetganda to'xtaydi. Natijada `list_connections()`
bo'sh ro'yxat qaytaradi va "ochiq xizmatlar" tekshiruvi **jimgina o'lik**
bo'lib qoladi: Docker API (2375), Redis, telnet ochiq turgan bo'lsa ham
"muammo topilmadi" deyiladi. Shuning uchun `scan_connections()` qo'shildi —
u `netstat -an -p tcp` ga tushadi va **ruxsat bor-yo'qligini ochiq
aytadi** (`ConnScan.permitted`), toki chaqiruvchi "tekshirildi" bilan
"tekshirib bo'lmadi" ni farqlay olsin.

Faqat stdlib + psutil; `_platform` faqat `scan_connections` ichida, kech
import qilinadi (buyruq ishga tushirish uchun — kod takrorlamaslik uchun).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

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


# --------------------------------------------------------------------------- #
# netstat zaxira yo'li (macOS/BSD — psutil root'siz ishlamaydi)
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ConnScan:
    """Ulanishlarni o'qishga urinish natijasi — MA'LUMOT + RUXSAT holati.

    `list_connections()` bo'sh ro'yxat qaytarganda ikki holat aralashib
    ketadi: "hech narsa tinglanmayapti" va "o'qishga ruxsat yo'q". Xavfsizlik
    tekshiruvida bu farq hal qiluvchi — birinchisi "toza", ikkinchisi
    "bilmayman". `permitted` aynan shuni ajratadi.
    """

    conns: list[ConnInfo] = field(default_factory=list)
    permitted: bool = True
    source: str = "psutil"  # psutil | netstat | none
    error: str | None = None


def _split_listen_addr(token: str) -> tuple[str, int] | None:
    """`netstat` manzil ustunini `(host, port)` ga ajratadi — SOF funksiya.

    Uchala OS uchta xil ajratgich ishlatadi va ularni bitta qoida bilan
    hal qilib bo'lmaydi:

    ===========  ==========================  ===========================
    OS           IPv4                        IPv6
    ===========  ==========================  ===========================
    macOS/BSD    ``127.0.0.1.7265``          ``::1.8443``  ``*.6379``
    Linux        ``127.0.0.1:7265``          ``:::8443``   ``0.0.0.0:6379``
    Windows      ``127.0.0.1:7265``          ``[::]:8443``
    ===========  ==========================  ===========================

    Shuning uchun avval **nuqta** bo'yicha sinaladi (BSD), o'tmasa **ikki
    nuqta** (Linux/Windows). Tartib muhim: `0.0.0.0:6379` da nuqta bo'yicha
    bo'lish `("0.0.0", "0:6379")` beradi — port raqam emas, demak keyingi
    usulga tushadi. Aksincha, BSD `::1.8443` ni ikki nuqta bilan bo'lsak
    `("::", "1.8443")` chiqadi va tinglovchi butunlay yo'qoladi.

    Port raqam bo'lmasa (`*.*`, `*:*` — masofaviy manzil ustuni) `None`.
    """
    for sep in (".", ":"):
        host, found, port_s = token.rpartition(sep)
        if found and port_s.isdigit():
            return host.strip("[]"), int(port_s)
    return None


# Windows "LISTENING", POSIX "LISTEN" — bitta nomga keltiriladi.
_STATE_ALIASES = {"LISTENING": "LISTEN"}


def parse_netstat_listeners(text: str, states: list[str] | None = None) -> list[ConnInfo]:
    """`netstat -an` chiqishini `ConnInfo` ro'yxatiga aylantiradi — SOF funksiya.

    **Uchala OS bir funksiyada.** Ustun soni ham, tartibi ham har xil:

    * macOS/BSD — ``Proto Recv-Q Send-Q Local Foreign [(state)]`` (5-6 ustun)
    * Linux — ``Proto Recv-Q Send-Q Local Foreign State`` (6 ustun)
    * Windows — ``Proto Local Foreign State`` (4 ustun; UDP'da 3 ta)

    Shuning uchun ustun **raqamiga** tayanilmaydi: qatordagi har bir bo'lak
    manzil-port sifatida o'qib ko'riladi, birinchi ikkitasi lokal va
    masofaviy manzil deb olinadi. `Recv-Q`/`Send-Q` (yalang'och `0`) tabiiy
    ravishda o'tmaydi, chunki ularda ajratgich yo'q. Bu `routes.parse_netstat`
    dagi bilan bir xil dars: qat'iy ustun/regex kutish qatorlarni JIMGINA
    yo'qotadi.

    Proto `tcp4`/`tcp6`/`tcp46`/`tcp`/`TCP` ko'rinishida keladi. `tcp46` —
    dual-stack socket: IPv4 va IPv6 dan bir vaqtda qabul qiladi, shuning uchun
    `tcp6` deb belgilanadi (ta'sir doirasi kengroq). Windows'da oila proto'da
    ko'rsatilmaydi — manzilning o'zidan aniqlanadi.

    Wildcard `*` oilaga qarab `0.0.0.0` yoki `::` ga aylantiriladi — shunda
    `evaluate_listeners` dagi "wildcard'ga bog'langanmi" mantiq'i psutil
    yo'lidagi bilan bir xil ishlaydi.

    PID/jarayon nomi **berilmaydi** (`netstat -an` da yo'q; `-v`/`-b` root
    yoki admin talab qiladi). Bu ataylab: port va manzil xavfni aniqlash
    uchun yetarli.
    """
    wanted = {s.upper() for s in states} if states else None
    out: list[ConnInfo] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        proto_raw = parts[0].lower()
        if not proto_raw.startswith(("tcp", "udp")):
            continue  # sarlavha va "Active Internet connections" qatorlari

        addrs: list[tuple[str, int]] = []
        state = ""
        for tok in parts[1:]:
            parsed = _split_listen_addr(tok)
            if parsed is not None:
                addrs.append(parsed)
            elif tok.isalpha():
                # Holat ustuni (LISTEN / ESTABLISHED / LISTENING / TIME_WAIT).
                # `isalpha()` pastki chiziqli statuslarni tashlaydi — ular
                # bizni qiziqtirmaydi (biz LISTEN izlayapmiz).
                state = _STATE_ALIASES.get(tok.upper(), tok.upper())
        if not addrs:
            continue
        if wanted is not None and state not in wanted:
            continue

        host, port = addrs[0]
        base = "tcp" if proto_raw.startswith("tcp") else "udp"
        # Oila: proto qo'shimchasidan (tcp6/tcp46) YOKI manzil shaklidan.
        is_v6 = "6" in proto_raw[3:] or ":" in host
        if host == "*":
            host = "::" if is_v6 else "0.0.0.0"

        laddr = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        raddr = ""
        if len(addrs) > 1:
            rh, rp = addrs[1]
            raddr = f"[{rh}]:{rp}" if ":" in rh else f"{rh}:{rp}"

        out.append(
            ConnInfo(
                proto=base + "6" if is_v6 else base,
                laddr=laddr,
                raddr=raddr,
                status=state,
            )
        )
    out.sort(key=lambda r: (r.proto, r.laddr))
    return out


async def scan_connections(states: list[str] | None = None) -> ConnScan:
    """Ulanishlarni o'qiydi va RUXSAT holatini ham qaytaradi.

    Tartib: avval `psutil` (jarayon nomlari bilan — foydaliroq), u
    `AccessDenied` bersa `netstat -an -p tcp` (jarayon nomisiz, lekin
    portlar to'liq).

    `lsof` ATAYLAB ishlatilmaydi: o'lchab ko'rildi — u root egaligidagi
    tinglovchilarni (8021, 43434) ko'rsatmaydi, ya'ni aynan `RISKY_LISTENERS`
    nishonga oladigan xizmatlarni o'tkazib yuboradi. Yarim javob bergan
    xavfsizlik tekshiruvi javob bermaganidan yomonroq.
    """
    from systop.core import _platform

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as exc:
        denied: str | None = type(exc).__name__
    except (psutil.Error, OSError) as exc:
        denied = type(exc).__name__
    else:
        # psutil ishladi — to'liq yo'ldan qaytamiz (jarayon nomlari bilan).
        del conns
        return ConnScan(conns=list_connections(states=states), permitted=True, source="psutil")

    # Windows `netstat` `-p` dan keyin protokolni KATTA harfda kutadi va
    # `-p tcp` ni "invalid argument" deb rad etadi; `-an` esa uchala OS'da
    # ham ishlaydi. POSIX'da `-p tcp` chiqishni ancha qisqartiradi.
    cmd = ["netstat", "-an"] if _platform.IS_WINDOWS else ["netstat", "-an", "-p", "tcp"]
    text = await _platform.run_command(cmd, timeout=8.0)
    if not text:
        return ConnScan(conns=[], permitted=False, source="none", error=denied)
    return ConnScan(
        conns=parse_netstat_listeners(text, states=states),
        permitted=True,
        source="netstat",
    )
