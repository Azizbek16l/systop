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
