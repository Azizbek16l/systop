"""CLI tests — OFFLINE.

``systop --version`` and ``--help`` are exercised through a subprocess (no
network, fast), and the argparse dispatch logic by calling ``main()`` in-process
with the network functions mocked out.

The cross-platform (Windows/POSIX C-locale) console guard is tested here too:
the CLI must not fall over on an ASCII-encoded stream (no UnicodeEncodeError) —
the same problem on Windows cp1252/cp866 and under POSIX `LANG=C`.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from systop import __version__


def _run_cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """Runs the systop CLI in a separate process (network-free commands).

    The child writes stdout as UTF-8 (the systop console guard). The parent
    decodes as UTF-8 too (`errors="replace"`) — otherwise a parent in an ASCII
    locale (`LANG=C`) could not DECODE the child's UTF-8 bytes and crashed (a
    test-harness artefact, not a systop bug).
    """
    return subprocess.run(
        [sys.executable, "-m", "systop", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=env,
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
    # argparse writes the error to stderr.
    assert "nonsense-command" in proc.stderr or "invalid choice" in proc.stderr


# --- main() dispatch (in-process, network mocked) ---------------------------


def test_main_default_runs_dashboard(monkeypatch):
    """With no arguments -> the dashboard starts."""
    import systop.cli as cli

    called = {"dashboard": False}

    # Mock the app module to intercept `from systop.app import run as run_dashboard`.
    import systop.app as app

    def fake_run():
        called["dashboard"] = True

    monkeypatch.setattr(app, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["systop"])
    cli.main()
    assert called["dashboard"] is True


def _main_expect_exit(cli, code: int = 0) -> None:
    """`main()` now calls `sys.exit` with a meaningful exit code (for scripts).

    The real handlers return 0 on success; so do the fakes in these tests.
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
        ("info", "_cmd_info"),
    ],
)
def test_main_dispatches_noarg_commands(monkeypatch, command, handler_name):
    """Argument-free commands (info) must reach the right handler.

    `lan` (0.4.0) and `speed` (0.9.0) take flags, so they were dropped from this
    list and moved to tests of their own.
    """
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
    """The `ping --ipv6 --watch` flags must reach _cmd_ping correctly."""
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


# --- main() passes the handler's exit code through (script-friendly) --------


@pytest.mark.parametrize("rc", [0, 1, 2])
def test_main_propagates_handler_exit_code(monkeypatch, rc):
    """The exit code a handler returns must pass through `sys.exit` unchanged.

    This matters on Windows: if ping is wrongly read as "dead" on a localised
    console, EXIT_UNREACHABLE (2) comes back — a script has to tell that from 0.
    """
    import systop.cli as cli

    async def fake_cmd_info():
        return rc

    monkeypatch.setattr(cli, "_cmd_info", fake_cmd_info)
    monkeypatch.setattr(sys, "argv", ["systop", "info"])
    _main_expect_exit(cli, code=rc)


def test_main_calls_init_console(monkeypatch):
    """`_platform.init_console` must be called when main() runs.

    It switches the Windows console to UTF-8/VT (for TUI/Rich Unicode). On POSIX
    it is a no-op, but the call must happen anyway (regression guard).
    """
    import systop.cli as cli

    called = {"init": 0}

    def fake_init():
        called["init"] += 1

    monkeypatch.setattr(cli._platform, "init_console", fake_init)

    async def fake_cmd_info():
        return 0

    monkeypatch.setattr(cli, "_cmd_info", fake_cmd_info)
    monkeypatch.setattr(sys, "argv", ["systop", "info"])
    _main_expect_exit(cli, code=0)
    assert called["init"] >= 1


# --- Console encoding guard (Windows cp866 / POSIX LANG=C) ------------------


@pytest.mark.parametrize(
    "encoding, expected",
    [
        ("utf-8", True),
        ("UTF-8", True),
        ("utf8", True),
        ("ascii", False),
        ("ANSI_X3.4-1968", False),  # the POSIX C locale's name for it
        ("cp1252", False),  # Windows Western
        ("cp866", False),  # a Windows Cyrillic console
        (None, False),  # encoding unknown -> play it safe
        ("", False),
    ],
)
def test_stream_encoding_is_safe(encoding, expected):
    """ASCII/OEM encodings must be detected as NOT safe (reconfigure needed)."""
    import systop.cli as cli

    class _FakeStream:
        pass

    stream = _FakeStream()
    stream.encoding = encoding  # type: ignore[attr-defined]
    assert cli._stream_encoding_is_safe(stream) is expected


def test_safe_write_survives_non_ascii_on_ascii_stream():
    """Writing non-ASCII to an ASCII stream must not crash (LANG=C).

    A plain `print` would have raised UnicodeEncodeError; `_safe_write` writes to
    the buffer with `errors="replace"` instead.
    """
    import systop.cli as cli

    raw = io.BytesIO()

    class _AsciiStream:
        encoding = "ascii"

        def __init__(self) -> None:
            self.buffer = raw

        def write(self, text: str) -> int:
            # Fails on non-ASCII, exactly like a real ASCII stream.
            text.encode("ascii")
            raw.write(text.encode("ascii"))
            return len(text)

    stream = _AsciiStream()
    # Accented Latin + Cyrillic + emoji — all of it non-ASCII.
    cli._safe_write(stream, "Speed measured — Ответ 🟢\n")
    out = raw.getvalue()
    assert out  # something was written
    # Characters that do not fit ASCII became '?', but there is NO exception.
    assert b"?" in out


def test_safe_write_plain_ascii_passthrough():
    """Pure ASCII text is written unchanged (the plain `write` succeeds)."""
    import systop.cli as cli

    buf = io.StringIO()  # StringIO accepts non-ASCII too and never errors
    cli._safe_write(buf, "hello\n")
    assert buf.getvalue() == "hello\n"


def test_harden_console_streams_idempotent(monkeypatch):
    """`_harden_console_streams` leaves a UTF stream alone and reconfigures ASCII."""
    import systop.cli as cli

    calls: list[tuple[str, str]] = []

    class _Stream:
        def __init__(self, encoding: str) -> None:
            self.encoding = encoding

        def reconfigure(self, *, encoding: str, errors: str) -> None:
            calls.append((encoding, errors))
            self.encoding = encoding

    utf_stream = _Stream("utf-8")
    ascii_stream = _Stream("ascii")
    monkeypatch.setattr(sys, "stdout", utf_stream)
    monkeypatch.setattr(sys, "stderr", ascii_stream)

    cli._harden_console_streams()

    # The UTF stream was NOT reconfigured; the ASCII one moved to UTF-8 + replace.
    assert ("utf-8", "replace") in calls
    assert len(calls) == 1  # ascii_stream only


# --- emit_json / emit_csv survive an ASCII locale too -----------------------


def test_emit_json_writes_valid_json_via_safe_path(monkeypatch, capsys):
    """emit_json produces clean, readable JSON (non-ASCII is preserved)."""
    import systop.cli as cli

    monkeypatch.setattr(cli, "_FORMAT", "json")
    cli.emit_json({"label": "Gateway (local)", "answer": "Ответ"})
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["label"] == "Gateway (local)"
    assert parsed["answer"] == "Ответ"


def test_error_machine_mode_goes_to_stderr(monkeypatch, capsys):
    """In machine (json) mode errors go to STDERR (stdout stays clean)."""
    import systop.cli as cli

    monkeypatch.setattr(cli, "_FORMAT", "json")
    cli.error("host is dead — Узел недоступен")
    captured = capsys.readouterr()
    assert captured.out == ""  # stdout is clean (machine parsing is not broken)
    assert "Узел недоступен" in captured.err


# --- Integration: the CLI survives a C/ASCII locale (LANG=C), offline command
#
# `config --show` does NOT touch the network, yet it prints non-ASCII text.
# `PYTHONUTF8=0`+`PYTHONCOERCECLOCALE=0`+`LC_ALL=C` forces stdout onto the
# `ascii` codec (the POSIX equivalent of the Windows cp866/cp1252 problem).
# Unguarded that gave `UnicodeEncodeError` + exit 1; thanks to
# `_harden_console_streams` it now runs cleanly.


def _ascii_locale_env() -> dict:
    import os

    env = dict(os.environ)
    env.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONIOENCODING": "",
        }
    )
    # NO_COLOR — no Rich markup, plain text (so the assertions stay stable).
    env["NO_COLOR"] = "1"
    return env


def _python_uses_ascii_stdout(env: dict) -> bool:
    """Does Python open stdout on the ascii codec in this environment?

    macOS/Linux: the forced env yields ascii. Windows: the codec may differ — this
    test only means anything when the ascii locale is genuinely reproduced.
    """
    probe = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.stdout.encoding)"],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    return probe.stdout.strip().lower().replace("-", "").startswith("ascii")


def test_cli_json_survives_ascii_locale(tmp_path):
    """`config --show --json` must give clean JSON + exit 0 in an ASCII locale too."""
    env = _ascii_locale_env()
    if not _python_uses_ascii_stdout(env):
        pytest.skip("the ascii locale could not be reproduced here (PEP 540 UTF-8 mode)")
    proc = _run_cli("config", "--show", "--json", env=env)
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == ""  # clean stderr (no UnicodeEncodeError)
    data = json.loads(proc.stdout)  # complete, valid JSON
    assert "ping_targets" in data


def test_cli_table_survives_ascii_locale():
    """`config --show` (non-ASCII glyphs) must not crash in an ASCII locale."""
    env = _ascii_locale_env()
    if not _python_uses_ascii_stdout(env):
        pytest.skip("the ascii locale could not be reproduced here (PEP 540 UTF-8 mode)")
    proc = _run_cli("config", "--show", env=env)
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    # There is some output (the table) and NO traceback.
    assert "Traceback" not in proc.stderr
    assert "UnicodeEncodeError" not in proc.stderr


# --------------------------------------------------------------------------- #
# 0.4.0: lan flags + the web/doctor commands
# --------------------------------------------------------------------------- #


def test_main_dispatches_lan_with_flags(monkeypatch):
    """The `lan -6 --global-only` flags must reach _cmd_lan correctly."""
    import systop.cli as cli

    captured = {}

    async def fake_cmd_lan(*, ipv6=False, only_ipv6=False, global_only=False):
        captured.update(ipv6=ipv6, only_ipv6=only_ipv6, global_only=global_only)
        return 0

    monkeypatch.setattr(cli, "_cmd_lan", fake_cmd_lan)
    monkeypatch.setattr(sys, "argv", ["systop", "lan", "-6", "--global-only"])
    _main_expect_exit(cli)
    assert captured == {"ipv6": True, "only_ipv6": False, "global_only": True}


def test_main_dispatches_lan_defaults(monkeypatch):
    """`lan` with no flags — everything False (the old behaviour is preserved)."""
    import systop.cli as cli

    captured = {}

    async def fake_cmd_lan(*, ipv6=False, only_ipv6=False, global_only=False):
        captured.update(ipv6=ipv6, only_ipv6=only_ipv6, global_only=global_only)
        return 0

    monkeypatch.setattr(cli, "_cmd_lan", fake_cmd_lan)
    monkeypatch.setattr(sys, "argv", ["systop", "lan"])
    _main_expect_exit(cli)
    assert captured == {"ipv6": False, "only_ipv6": False, "global_only": False}


def test_main_dispatches_web_with_hosts(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_web(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_cmd_web", fake_cmd_web)
    monkeypatch.setattr(
        sys, "argv", ["systop", "web", "10.0.0.1", "10.0.0.2", "--admin-only", "--polite"]
    )
    _main_expect_exit(cli)
    assert captured["hosts"] == ["10.0.0.1", "10.0.0.2"]
    assert captured["admin_only"] is True
    assert captured["polite"] is True


def test_web_http80_shortcut_sets_port_80(monkeypatch):
    """`--http80` — the shortcut for finding port 80."""
    import systop.cli as cli

    captured = {}

    async def fake_cmd_web(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_cmd_web", fake_cmd_web)
    monkeypatch.setattr(sys, "argv", ["systop", "web", "--http80"])
    _main_expect_exit(cli)
    assert captured["ports_spec"] == "80"


def test_main_dispatches_doctor(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_doctor(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_cmd_doctor", fake_cmd_doctor)
    monkeypatch.setattr(sys, "argv", ["systop", "doctor", "--quick", "--no-web"])
    _main_expect_exit(cli)
    assert captured["quick"] is True
    assert captured["no_web"] is True


def test_scan_family_flags_are_mutually_exclusive():
    """`-4` and `-6` must not be given together (argparse should error)."""
    import systop.cli as cli

    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "host", "-4", "-6"])


def test_scan_family_from_args():
    import systop.cli as cli
    from systop.core.ports import FAMILY_AUTO, FAMILY_V4, FAMILY_V6

    parser = cli._build_parser()
    assert cli._family_from_args(parser.parse_args(["scan", "h"])) == FAMILY_AUTO
    assert cli._family_from_args(parser.parse_args(["scan", "h", "-4"])) == FAMILY_V4
    assert cli._family_from_args(parser.parse_args(["scan", "h", "-6"])) == FAMILY_V6


def test_to_dict_includes_webservice_properties():
    """The `url`/`risk` properties MUST land in the JSON (no silent loss)."""
    import systop.cli as cli
    from systop.core.webscan import WebService

    d = cli._to_dict(WebService(ip="2001:db8::1", port=443, scheme="https", is_admin=True))
    assert d["url"] == "https://[2001:db8::1]:443/"
    assert "risk" in d


def test_to_dict_includes_lanhost_is_link_local():
    import systop.cli as cli
    from systop.core.topology import LanHost

    d = cli._to_dict(LanHost(ip="fe80::1%en0", family="ipv6"))
    assert d["is_link_local"] is True
    assert d["family"] == "ipv6"


# --------------------------------------------------------------------------- #
# 0.5.0: scan sweep (nmap style) + the nc command
# --------------------------------------------------------------------------- #


def test_main_dispatches_scan_with_multiple_targets(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_scan(*args, **kwargs):
        captured["targets"] = args[0] if args else kwargs.get("targets_spec")
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_cmd_scan", fake_cmd_scan)
    monkeypatch.setattr(
        sys,
        "argv",
        ["systop", "scan", "10.0.0.1", "10.0.0.0/24", "--top", "10", "--banner", "--polite"],
    )
    _main_expect_exit(cli)
    assert captured["targets"] == ["10.0.0.1", "10.0.0.0/24"]
    assert captured["top"] == 10
    assert captured["banner"] is True
    assert captured["polite"] is True


def test_scan_single_target_still_works(monkeypatch):
    """The old invocation form (`scan HOST`) must keep working."""
    import systop.cli as cli

    captured = {}

    async def fake_cmd_scan(*args, **kwargs):
        captured["targets"] = args[0]
        return 0

    monkeypatch.setattr(cli, "_cmd_scan", fake_cmd_scan)
    monkeypatch.setattr(sys, "argv", ["systop", "scan", "example.com"])
    _main_expect_exit(cli)
    assert captured["targets"] == ["example.com"]


def test_main_dispatches_nc(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_nc(host, port, **kwargs):
        captured["host"] = host
        captured["port"] = port
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_cmd_nc", fake_cmd_nc)
    monkeypatch.setattr(
        sys,
        "argv",
        ["systop", "nc", "10.0.0.1", "443", "--tls", "--hex", "--send", r"PING\r\n"],
    )
    _main_expect_exit(cli)
    assert captured["host"] == "10.0.0.1"
    assert captured["port"] == 443
    assert captured["tls"] is True
    assert captured["as_hex"] is True
    assert captured["send"] == r"PING\r\n"


def test_nc_family_flag(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_nc(host, port, **kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_cmd_nc", fake_cmd_nc)
    monkeypatch.setattr(sys, "argv", ["systop", "nc", "localhost", "22", "-6"])
    _main_expect_exit(cli)
    assert captured["family"] == "ipv6"


def test_to_dict_includes_ncresult_properties():
    """`received` bytes must survive JSON encoding, and the properties must be included."""
    import systop.cli as cli
    from systop.core.netcat import NcResult

    d = cli._to_dict(NcResult(host="h", port=22, received=b"SSH-2.0\r\n", connected=True))
    assert d["received_text"].startswith("SSH-2.0")
    assert d["received_bytes_count"] == 9
    assert d["is_binary"] is False


def test_main_dispatches_speed_with_local_flags(monkeypatch):
    """The `speed --local-url URL` flags must reach _cmd_speed."""
    import systop.cli as cli

    captured = {}

    async def fake_cmd_speed(*, local=False, local_urls=None):
        captured.update(local=local, local_urls=local_urls)
        return 0

    monkeypatch.setattr(cli, "_cmd_speed", fake_cmd_speed)
    monkeypatch.setattr(
        sys, "argv", ["systop", "speed", "--local-url", "https://a.uz/f", "--local"]
    )
    _main_expect_exit(cli)
    assert captured["local"] is True
    assert captured["local_urls"] == ["https://a.uz/f"]


def test_main_dispatches_speed_defaults(monkeypatch):
    import systop.cli as cli

    captured = {}

    async def fake_cmd_speed(*, local=False, local_urls=None):
        captured.update(local=local, local_urls=local_urls)
        return 0

    monkeypatch.setattr(cli, "_cmd_speed", fake_cmd_speed)
    monkeypatch.setattr(sys, "argv", ["systop", "speed"])
    _main_expect_exit(cli)
    assert captured == {"local": False, "local_urls": None}
