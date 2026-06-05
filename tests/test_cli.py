"""CLI testlari — OFFLINE.

``systop --version`` va ``--help`` ni subprocess orqali (tarmoqqa chiqmaydi,
tez), hamda argparse dispatch mantig'ini ``main()`` ni in-process chaqirib
(tarmoq funksiyalari mock qilinib) sinaydi.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from systop import __version__


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """systop CLI'ni alohida jarayonda ishga tushiradi (tarmoqsiz buyruqlar)."""
    return subprocess.run(
        [sys.executable, "-m", "systop", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_version():
    proc = _run_cli("--version")
    assert proc.returncode == 0
    assert __version__ in proc.stdout
    assert "systop" in proc.stdout


def test_cli_help_lists_subcommands():
    proc = _run_cli("--help")
    assert proc.returncode == 0
    out = proc.stdout
    for cmd in ("speed", "ping", "trace", "lan", "info", "dashboard"):
        assert cmd in out


def test_cli_trace_help_has_host_arg():
    proc = _run_cli("trace", "--help")
    assert proc.returncode == 0
    assert "host" in proc.stdout.lower()


def test_cli_unknown_command_errors():
    proc = _run_cli("nonsense-command")
    assert proc.returncode != 0
    # argparse xatoni stderr'ga yozadi.
    assert "nonsense-command" in proc.stderr or "invalid choice" in proc.stderr


# --- main() dispatch (in-process, tarmoq mock) ------------------------------


def test_main_default_runs_dashboard(monkeypatch):
    """Argument berilmasa -> dashboard ishga tushadi."""
    import systop.cli as cli

    called = {"dashboard": False}

    # `from systop.app import run as run_dashboard` ni ushlash uchun app modulini mock.
    import systop.app as app

    def fake_run():
        called["dashboard"] = True

    monkeypatch.setattr(app, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["systop"])
    cli.main()
    assert called["dashboard"] is True


def _main_expect_exit(cli, code: int = 0) -> None:
    """`main()` endi mazmunli exit kod bilan `sys.exit` chaqiradi (skriptlar uchun).

    Default handler'lar muvaffaqiyatda 0 qaytaradi; test fake'lari ham shunday.
    """
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == code


def test_main_dispatches_trace_with_host(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_trace(host):
        captured["host"] = host
        return 0

    monkeypatch.setattr(cli, "_cmd_trace", fake_cmd_trace)
    monkeypatch.setattr(sys, "argv", ["systop", "trace", "1.2.3.4"])
    _main_expect_exit(cli)
    assert captured["host"] == "1.2.3.4"


def test_main_trace_default_host(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_trace(host):
        captured["host"] = host
        return 0

    monkeypatch.setattr(cli, "_cmd_trace", fake_cmd_trace)
    monkeypatch.setattr(sys, "argv", ["systop", "trace"])
    _main_expect_exit(cli)
    assert captured["host"] == "8.8.8.8"


@pytest.mark.parametrize(
    "command, handler_name",
    [
        ("speed", "_cmd_speed"),
        ("lan", "_cmd_lan"),
        ("info", "_cmd_info"),
    ],
)
def test_main_dispatches_noarg_commands(monkeypatch, command, handler_name):
    """Argumentsiz buyruqlar (speed/lan/info) to'g'ri handler'ga yo'naltirilsin."""
    import systop.cli as cli

    called = {"name": None}

    async def fake_handler():
        called["name"] = command
        return 0

    monkeypatch.setattr(cli, handler_name, fake_handler)
    monkeypatch.setattr(sys, "argv", ["systop", command])
    _main_expect_exit(cli)
    assert called["name"] == command


def test_main_dispatches_ping_with_flags(monkeypatch):
    """`ping --ipv6 --watch` bayroqlari _cmd_ping'ga to'g'ri uzatilsin."""
    import systop.cli as cli

    captured = {}

    async def fake_cmd_ping(*, ipv6=False, watch=False, targets_arg=None):
        captured["ipv6"] = ipv6
        captured["watch"] = watch
        captured["targets_arg"] = targets_arg
        return 0

    monkeypatch.setattr(cli, "_cmd_ping", fake_cmd_ping)
    monkeypatch.setattr(sys, "argv", ["systop", "ping", "--ipv6", "--watch"])
    _main_expect_exit(cli)
    assert captured == {"ipv6": True, "watch": True, "targets_arg": None}


def test_main_dispatches_ping_defaults(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_ping(*, ipv6=False, watch=False, targets_arg=None):
        captured["ipv6"] = ipv6
        captured["watch"] = watch
        captured["targets_arg"] = targets_arg
        return 0

    monkeypatch.setattr(cli, "_cmd_ping", fake_cmd_ping)
    monkeypatch.setattr(sys, "argv", ["systop", "ping"])
    _main_expect_exit(cli)
    assert captured == {"ipv6": False, "watch": False, "targets_arg": None}
