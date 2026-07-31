"""connections testlari — OFFLINE.

``psutil.net_connections`` va ``psutil.Process`` monkeypatch qilinib,
``list_connections`` ning format/filtr mantig'i, jarayon nomi keshlash va
``AccessDenied`` yutilishi sinaladi. Hech qanday haqiqiy socket o'qilmaydi.
"""

from __future__ import annotations

import socket

import psutil
import pytest
from conftest import FakeAddr, FakeConn, FakeProcess

from systop.core.connections import (
    ConnInfo,
    _fmt_addr,
    _proto_name,
    list_connections,
)

# --- _proto_name ------------------------------------------------------------


@pytest.mark.parametrize(
    "family, kind, expected",
    [
        (socket.AF_INET, socket.SOCK_STREAM, "tcp"),
        (socket.AF_INET, socket.SOCK_DGRAM, "udp"),
        (socket.AF_INET6, socket.SOCK_STREAM, "tcp6"),
        (socket.AF_INET6, socket.SOCK_DGRAM, "udp6"),
    ],
)
def test_proto_name(family, kind, expected):
    assert _proto_name(family, kind) == expected


# --- _fmt_addr --------------------------------------------------------------


def test_fmt_addr_ipv4():
    assert _fmt_addr(FakeAddr(ip="127.0.0.1", port=8080)) == "127.0.0.1:8080"


def test_fmt_addr_ipv6_bracketed():
    assert _fmt_addr(FakeAddr(ip="::1", port=443)) == "[::1]:443"


def test_fmt_addr_empty():
    assert _fmt_addr(None) == ""
    assert _fmt_addr(()) == ""


def test_fmt_addr_ip_without_port():
    # port=0 (psutil ba'zan UDP'da 0 qaytaradi) -> `0 or "" == ""` => faqat ip.
    assert _fmt_addr(FakeAddr(ip="10.0.0.1", port=0)) == "10.0.0.1"


# --- ConnInfo dataclass -----------------------------------------------------


def test_conninfo_defaults():
    c = ConnInfo(proto="tcp", laddr="127.0.0.1:80", raddr="", status="LISTEN")
    assert c.pid is None
    assert c.process is None


# --- list_connections: happy path -------------------------------------------


def test_list_connections_maps_and_sorts(monkeypatch):
    conns = [
        FakeConn(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=FakeAddr("127.0.0.1", 8000),
            raddr=FakeAddr("1.2.3.4", 443),
            status="ESTABLISHED",
            pid=42,
        ),
        FakeConn(
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            laddr=FakeAddr("::1", 22),
            raddr=None,
            status="LISTEN",
            pid=7,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProcess(pid, name=f"proc{pid}"))

    result = list_connections()
    assert len(result) == 2
    # tartib: proto, keyin laddr -> tcp avval, tcp6 keyin.
    assert result[0].proto == "tcp"
    assert result[0].laddr == "127.0.0.1:8000"
    assert result[0].raddr == "1.2.3.4:443"
    assert result[0].status == "ESTABLISHED"
    assert result[0].process == "proc42"
    assert result[1].proto == "tcp6"
    assert result[1].laddr == "[::1]:22"
    assert result[1].process == "proc7"


def test_list_connections_state_filter(monkeypatch):
    conns = [
        FakeConn(socket.AF_INET, socket.SOCK_STREAM, FakeAddr("0.0.0.0", 80), None, "LISTEN", 1),
        FakeConn(
            socket.AF_INET,
            socket.SOCK_STREAM,
            FakeAddr("10.0.0.1", 5000),
            FakeAddr("9.9.9.9", 443),
            "ESTABLISHED",
            2,
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
    monkeypatch.setattr(psutil, "Process", lambda pid: FakeProcess(pid))

    # katta-kichik harf farqsiz: 'listen' -> faqat LISTEN qatori.
    result = list_connections(states=["listen"])
    assert len(result) == 1
    assert result[0].status == "LISTEN"
    assert result[0].laddr == "0.0.0.0:80"


def test_list_connections_none_status_normalized(monkeypatch):
    """CONN_NONE / bo'sh status -> "" (UDP socketlar)."""
    conns = [
        FakeConn(
            socket.AF_INET, socket.SOCK_DGRAM, FakeAddr("0.0.0.0", 68), None, psutil.CONN_NONE, None
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
    result = list_connections()
    assert len(result) == 1
    assert result[0].proto == "udp"
    assert result[0].status == ""
    assert result[0].pid is None
    assert result[0].process is None


def test_list_connections_process_name_cached(monkeypatch):
    """Bir xil PID bir necha bor uchrasa, Process faqat bir marta qurilishi kerak."""
    conns = [
        FakeConn(
            socket.AF_INET, socket.SOCK_STREAM, FakeAddr("127.0.0.1", 1000 + i), None, "LISTEN", 99
        )
        for i in range(3)
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)

    build_count = {"n": 0}

    def fake_process(pid):
        build_count["n"] += 1
        return FakeProcess(pid, name="cached")

    monkeypatch.setattr(psutil, "Process", fake_process)
    result = list_connections()
    assert len(result) == 3
    assert all(r.process == "cached" for r in result)
    assert build_count["n"] == 1  # kesh: PID 99 uchun bir marta


# --- AccessDenied / xato yutilishi ------------------------------------------


def test_list_connections_access_denied_returns_empty(monkeypatch):
    def boom(kind="inet"):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", boom)
    # macOS'da root'siz odatdagi holat — bo'sh ro'yxat, xato YO'Q.
    assert list_connections() == []


def test_list_connections_oserror_returns_empty(monkeypatch):
    def boom(kind="inet"):
        raise OSError("nope")

    monkeypatch.setattr(psutil, "net_connections", boom)
    assert list_connections() == []


def test_list_connections_process_access_denied_keeps_conn(monkeypatch):
    """Bitta socket egasini o'qib bo'lmasa ham, ulanishning o'zi qaytariladi."""
    conns = [
        FakeConn(
            socket.AF_INET, socket.SOCK_STREAM, FakeAddr("127.0.0.1", 80), None, "LISTEN", 500
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)

    def denied(pid):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "Process", denied)
    result = list_connections()
    assert len(result) == 1
    assert result[0].pid == 500
    assert result[0].process is None  # nom noma'lum, lekin yiqilmaydi


def test_list_connections_process_no_such_process(monkeypatch):
    """PID o'lib qolgan bo'lsa (NoSuchProcess) -> process None, xato yo'q."""
    conns = [
        FakeConn(
            socket.AF_INET, socket.SOCK_STREAM, FakeAddr("127.0.0.1", 80), None, "LISTEN", 12345
        ),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)

    def gone(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", gone)
    result = list_connections()
    assert result[0].process is None


def test_list_connections_empty_table(monkeypatch):
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
    assert list_connections() == []


# --------------------------------------------------------------------------- #
# netstat zaxira yo'li (macOS/BSD — psutil root'siz AccessDenied beradi)
# --------------------------------------------------------------------------- #

from systop.core.connections import (  # noqa: E402
    ConnScan,
    _split_listen_addr,
    parse_netstat_listeners,
)

# Haqiqiy macOS chiqishi — oxirgi ustun (state) bor va yo'q qatorlar aralash.
NETSTAT_BSD = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.11.43.49207    160.79.104.10.443      ESTABLISHED
tcp46      0      0  *.56577                *.*                    LISTEN
tcp4       0      0  127.0.0.1.7265         *.*                    LISTEN
tcp6       0      0  *.49152                *.*                    LISTEN
tcp4       0      0  *.6379                 *.*                    LISTEN
tcp6       0      0  ::1.8443               *.*                    LISTEN
udp4       0      0  *.5353                 *.*
"""


def test_netstat_port_ajratgichi_nuqta_ikki_nuqta_emas():
    """`::1.8443` — BSD portni NUQTA bilan ajratadi.

    `rpartition(":")` bu yerda `("::", "1.8443")` beradi va IPv6 tinglovchini
    butunlay yo'q qiladi. Aynan shuning uchun alohida `_split_bsd_addr` bor.
    """
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    v6 = [r for r in rows if r.laddr == "[::1]:8443"]
    assert len(v6) == 1
    assert v6[0].proto == "tcp6"


def test_netstat_wildcard_oilaga_qarab_kengaytiriladi():
    """`*` IPv4'da 0.0.0.0, IPv6'da :: bo'lishi kerak.

    `evaluate_listeners` "wildcard'ga bog'langanmi" ni shu manzil bo'yicha
    hal qiladi — `*` holicha qolsa hech bir xavfli xizmat aniqlanmaydi.
    """
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    assert "0.0.0.0:6379" in [r.laddr for r in rows]
    assert "[::]:49152" in [r.laddr for r in rows]


def test_netstat_tcp46_ikki_stekli_deb_belgilanadi():
    """`tcp46` — dual-stack socket, ta'sir doirasi kengroq: tcp6 deb olinadi."""
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    dual = [r for r in rows if r.laddr == "[::]:56577"]
    assert len(dual) == 1
    assert dual[0].proto == "tcp6"


def test_netstat_state_filtri_ishlaydi():
    """ESTABLISHED qatori LISTEN so'ralganda kelmasligi kerak."""
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    assert all(r.status == "LISTEN" for r in rows)
    assert not any("49207" in r.laddr for r in rows)


def test_netstat_state_ustuni_yoq_qator_tashlanmaydi():
    """UDP qatorida (state) ustuni umuman yo'q — filtrsiz u ham kelishi kerak.

    Qat'iy regex aynan shunday qatorlarni jimgina yo'qotadi (routes.py da
    93 qatordan 75 tasi shu sababdan yo'qolgandi).
    """
    rows = parse_netstat_listeners(NETSTAT_BSD)
    assert "0.0.0.0:5353" in [r.laddr for r in rows]


def test_netstat_sarlavha_qatorlari_otkazib_yuboriladi():
    rows = parse_netstat_listeners(NETSTAT_BSD)
    assert all(r.proto.startswith(("tcp", "udp")) for r in rows)


def test_netstat_yulduzcha_port_tashlanadi():
    """Masofaviy manzil `*.*` — port raqam emas, qator buzilmasligi kerak."""
    rows = parse_netstat_listeners("tcp4 0 0 *.* *.* LISTEN")
    assert rows == []


def test_connscan_default_ruxsat_berilgan():
    """Bo'sh ro'yxat != ruxsat yo'q. Ikkisi ATAYLAB ajratilgan."""
    assert ConnScan().permitted is True
    assert ConnScan(permitted=False).conns == []


# --------------------------------------------------------------------------- #
# Uchala OS formati — bir parser
# --------------------------------------------------------------------------- #

# Linux `netstat -an`: port IKKI NUQTA bilan, IPv6 wildcard `:::8443`.
NETSTAT_LINUX = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:7265          0.0.0.0:*               LISTEN
tcp6       0      0 :::8443                 :::*                    LISTEN
tcp        0      0 10.0.0.5:22             10.0.0.9:51234          ESTABLISHED
udp        0      0 0.0.0.0:5353            0.0.0.0:*
"""

# Windows `netstat -an`: 4 ustun, holat `LISTENING`, IPv6 kvadrat qavsda.
NETSTAT_WINDOWS = """
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:6379           0.0.0.0:0              LISTENING
  TCP    127.0.0.1:7265         0.0.0.0:0              LISTENING
  TCP    [::]:8443              [::]:0                 LISTENING
  TCP    10.0.0.5:22            10.0.0.9:51234         ESTABLISHED
  UDP    0.0.0.0:5353           *:*
"""


def test_manzil_ajratgich_uchala_shaklni_tushunadi():
    """BSD nuqta, Linux/Windows ikki nuqta, Windows kvadrat qavs."""
    assert _split_listen_addr("127.0.0.1.7265") == ("127.0.0.1", 7265)   # BSD
    assert _split_listen_addr("::1.8443") == ("::1", 8443)               # BSD IPv6
    assert _split_listen_addr("0.0.0.0:6379") == ("0.0.0.0", 6379)       # Linux
    assert _split_listen_addr(":::8443") == ("::", 8443)                 # Linux IPv6
    assert _split_listen_addr("[::]:8443") == ("::", 8443)               # Windows IPv6
    assert _split_listen_addr("*.6379") == ("*", 6379)                   # BSD wildcard


def test_manzil_ajratgich_portsizni_rad_etadi():
    for tok in ("*.*", "*:*", "0", "LISTEN", ""):
        assert _split_listen_addr(tok) is None


def test_linux_formati_parse_qilinadi():
    rows = parse_netstat_listeners(NETSTAT_LINUX, states=["LISTEN"])
    laddrs = [r.laddr for r in rows]
    assert "0.0.0.0:6379" in laddrs
    assert "127.0.0.1:7265" in laddrs
    assert "[::]:8443" in laddrs
    assert not any("10.0.0.9" in r.raddr for r in rows)  # ESTABLISHED tashlandi


def test_windows_formati_parse_qilinadi():
    """Windows'da 4 ustun va holat `LISTENING` — ikkalasi ham normallashtiriladi."""
    rows = parse_netstat_listeners(NETSTAT_WINDOWS, states=["LISTEN"])
    laddrs = [r.laddr for r in rows]
    assert "0.0.0.0:6379" in laddrs
    assert "[::]:8443" in laddrs
    assert all(r.status == "LISTEN" for r in rows)


def test_windows_oila_manzildan_aniqlanadi():
    """Windows proto'da 4/6 ko'rsatilmaydi — `[::]` dan tcp6 chiqishi kerak."""
    rows = parse_netstat_listeners(NETSTAT_WINDOWS, states=["LISTEN"])
    v6 = [r for r in rows if r.laddr == "[::]:8443"]
    assert v6 and v6[0].proto == "tcp6"


def test_uchala_os_bir_xil_natija_beradi():
    """Bir xil tinglovchilar — uchala OS chiqishidan bir xil to'plam.

    Bu toolning asosiy va'dasi: `doctor` xulosasi OS'ga qarab o'zgarmasligi
    kerak. Parser farqi shu yerda ushlanadi.
    """
    def listen_set(text):
        return {(r.laddr, r.proto) for r in parse_netstat_listeners(text, states=["LISTEN"])}

    bsd = listen_set(NETSTAT_BSD)
    linux = listen_set(NETSTAT_LINUX)
    windows = listen_set(NETSTAT_WINDOWS)
    umumiy = {("0.0.0.0:6379", "tcp"), ("127.0.0.1:7265", "tcp")}
    assert umumiy <= bsd
    assert umumiy <= linux
    assert umumiy <= windows
    assert ("[::]:8443", "tcp6") in linux
    assert ("[::]:8443", "tcp6") in windows
