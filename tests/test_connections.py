"""connections tests — OFFLINE.

``psutil.net_connections`` and ``psutil.Process`` are monkeypatched, and the
formatting/filtering logic of ``list_connections``, the process-name caching
and the swallowing of ``AccessDenied`` are exercised. No real socket is read.
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
    # port=0 (psutil sometimes returns 0 for UDP) -> `0 or "" == ""` => ip only.
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
    # order: proto, then laddr -> tcp first, tcp6 after.
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

    # case-insensitive: 'listen' -> only the LISTEN row.
    result = list_connections(states=["listen"])
    assert len(result) == 1
    assert result[0].status == "LISTEN"
    assert result[0].laddr == "0.0.0.0:80"


def test_list_connections_none_status_normalized(monkeypatch):
    """CONN_NONE / empty status -> "" (UDP sockets)."""
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
    """If the same PID appears several times, Process must be built only once."""
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
    assert build_count["n"] == 1  # cache: only once for PID 99


# --- AccessDenied / error swallowing ----------------------------------------


def test_list_connections_access_denied_returns_empty(monkeypatch):
    def boom(kind="inet"):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", boom)
    # The normal situation on macOS without root — empty list, NO exception.
    assert list_connections() == []


def test_list_connections_oserror_returns_empty(monkeypatch):
    def boom(kind="inet"):
        raise OSError("nope")

    monkeypatch.setattr(psutil, "net_connections", boom)
    assert list_connections() == []


def test_list_connections_process_access_denied_keeps_conn(monkeypatch):
    """Even if a socket's owner cannot be read, the connection itself is returned."""
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
    assert result[0].process is None  # name unknown, but it does not crash


def test_list_connections_process_no_such_process(monkeypatch):
    """If the PID has died (NoSuchProcess) -> process None, no exception."""
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
# netstat fallback path (macOS/BSD — psutil raises AccessDenied without root)
# --------------------------------------------------------------------------- #

from systop.core.connections import (  # noqa: E402
    ConnScan,
    _split_listen_addr,
    parse_netstat_listeners,
)

# Real macOS output — a mix of lines with and without the last (state) column.
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


def test_netstat_port_separator_is_dot_not_colon():
    """`::1.8443` — BSD separates the port with a DOT.

    Here `rpartition(":")` yields `("::", "1.8443")` and wipes out the IPv6
    listener entirely. That is exactly why a separate `_split_bsd_addr` exists.
    """
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    v6 = [r for r in rows if r.laddr == "[::1]:8443"]
    assert len(v6) == 1
    assert v6[0].proto == "tcp6"


def test_netstat_wildcard_expanded_by_family():
    """`*` must become 0.0.0.0 for IPv4 and :: for IPv6.

    `evaluate_listeners` decides "is it bound to a wildcard" from that address —
    if `*` is left as it is, no risky service is ever detected.
    """
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    assert "0.0.0.0:6379" in [r.laddr for r in rows]
    assert "[::]:49152" in [r.laddr for r in rows]


def test_netstat_tcp46_marked_as_dual_stack():
    """`tcp46` — a dual-stack socket with a wider blast radius: taken as tcp6."""
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    dual = [r for r in rows if r.laddr == "[::]:56577"]
    assert len(dual) == 1
    assert dual[0].proto == "tcp6"


def test_netstat_state_filter_works():
    """The ESTABLISHED row must not come back when LISTEN is requested."""
    rows = parse_netstat_listeners(NETSTAT_BSD, states=["LISTEN"])
    assert all(r.status == "LISTEN" for r in rows)
    assert not any("49207" in r.laddr for r in rows)


def test_netstat_line_without_state_column_is_not_dropped():
    """The UDP line has no (state) column at all — without a filter it must come too.

    A strict regex silently loses exactly these lines (in routes.py 75 out of
    93 lines were lost for that very reason).
    """
    rows = parse_netstat_listeners(NETSTAT_BSD)
    assert "0.0.0.0:5353" in [r.laddr for r in rows]


def test_netstat_header_lines_are_skipped():
    rows = parse_netstat_listeners(NETSTAT_BSD)
    assert all(r.proto.startswith(("tcp", "udp")) for r in rows)


def test_netstat_asterisk_port_is_dropped():
    """The remote address `*.*` — the port is not a number, the line must not break."""
    rows = parse_netstat_listeners("tcp4 0 0 *.* *.* LISTEN")
    assert rows == []


def test_connscan_defaults_to_permitted():
    """An empty list != no permission. The two are DELIBERATELY kept apart."""
    assert ConnScan().permitted is True
    assert ConnScan(permitted=False).conns == []


# --------------------------------------------------------------------------- #
# All three OS formats — a single parser
# --------------------------------------------------------------------------- #

# Linux `netstat -an`: port after a COLON, IPv6 wildcard `:::8443`.
NETSTAT_LINUX = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:7265          0.0.0.0:*               LISTEN
tcp6       0      0 :::8443                 :::*                    LISTEN
tcp        0      0 10.0.0.5:22             10.0.0.9:51234          ESTABLISHED
udp        0      0 0.0.0.0:5353            0.0.0.0:*
"""

# Windows `netstat -an`: 4 columns, state `LISTENING`, IPv6 in square brackets.
NETSTAT_WINDOWS = """
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:6379           0.0.0.0:0              LISTENING
  TCP    127.0.0.1:7265         0.0.0.0:0              LISTENING
  TCP    [::]:8443              [::]:0                 LISTENING
  TCP    10.0.0.5:22            10.0.0.9:51234         ESTABLISHED
  UDP    0.0.0.0:5353           *:*
"""


def test_address_splitter_understands_all_three_shapes():
    """BSD dot, Linux/Windows colon, Windows square brackets."""
    assert _split_listen_addr("127.0.0.1.7265") == ("127.0.0.1", 7265)  # BSD
    assert _split_listen_addr("::1.8443") == ("::1", 8443)  # BSD IPv6
    assert _split_listen_addr("0.0.0.0:6379") == ("0.0.0.0", 6379)  # Linux
    assert _split_listen_addr(":::8443") == ("::", 8443)  # Linux IPv6
    assert _split_listen_addr("[::]:8443") == ("::", 8443)  # Windows IPv6
    assert _split_listen_addr("*.6379") == ("*", 6379)  # BSD wildcard


def test_address_splitter_rejects_tokens_without_a_port():
    for tok in ("*.*", "*:*", "0", "LISTEN", ""):
        assert _split_listen_addr(tok) is None


def test_linux_format_is_parsed():
    rows = parse_netstat_listeners(NETSTAT_LINUX, states=["LISTEN"])
    laddrs = [r.laddr for r in rows]
    assert "0.0.0.0:6379" in laddrs
    assert "127.0.0.1:7265" in laddrs
    assert "[::]:8443" in laddrs
    assert not any("10.0.0.9" in r.raddr for r in rows)  # ESTABLISHED was dropped


def test_windows_format_is_parsed():
    """On Windows there are 4 columns and the state is `LISTENING` — both are normalised."""
    rows = parse_netstat_listeners(NETSTAT_WINDOWS, states=["LISTEN"])
    laddrs = [r.laddr for r in rows]
    assert "0.0.0.0:6379" in laddrs
    assert "[::]:8443" in laddrs
    assert all(r.status == "LISTEN" for r in rows)


def test_windows_family_is_derived_from_the_address():
    """Windows does not show 4/6 in the proto — `[::]` must produce tcp6."""
    rows = parse_netstat_listeners(NETSTAT_WINDOWS, states=["LISTEN"])
    v6 = [r for r in rows if r.laddr == "[::]:8443"]
    assert v6 and v6[0].proto == "tcp6"


def test_all_three_os_give_the_same_result():
    """The same listeners — an identical set from all three OS outputs.

    This is the core promise of the tool: the `doctor` verdict must not change
    depending on the OS. Parser differences get caught right here.
    """

    def listen_set(text):
        return {(r.laddr, r.proto) for r in parse_netstat_listeners(text, states=["LISTEN"])}

    bsd = listen_set(NETSTAT_BSD)
    linux = listen_set(NETSTAT_LINUX)
    windows = listen_set(NETSTAT_WINDOWS)
    common = {("0.0.0.0:6379", "tcp"), ("127.0.0.1:7265", "tcp")}
    assert common <= bsd
    assert common <= linux
    assert common <= windows
    assert ("[::]:8443", "tcp6") in linux
    assert ("[::]:8443", "tcp6") in windows
