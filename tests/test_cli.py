"""CLI testlari — OFFLINE.

``systop --version`` va ``--help`` ni subprocess orqali (tarmoqqa chiqmaydi,
tez), hamda argparse dispatch mantig'ini ``main()`` ni in-process chaqirib
(tarmoq funksiyalari mock qilinib) sinaydi.

Cross-platform (Windows/POSIX C-lokal) konsol himoyasi ham shu yerda sinaladi:
ASCII kodlashli oqimda ham CLI yiqilmasligi (UnicodeEncodeError bermasligi)
kerak — bu Windows cp1252/cp866 va `LANG=C` POSIX uchun bir xil muammo.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from systop import __version__


def _run_cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """systop CLI'ni alohida jarayonda ishga tushiradi (tarmoqsiz buyruqlar).

    Bola jarayon stdout'ni UTF-8 yozadi (systop konsol himoyasi). Ota jarayon
    ham UTF-8 (`errors="replace"`) bilan dekodlaydi — aks holda ota jarayon
    ASCII lokalda (`LANG=C`) bola UTF-8 baytlarini DEKODLAY olmay yiqilardi
    (bu test harness artefakti, systop xatosi emas).
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


# --- main() exit kodlarini handler'dan o'tkazadi (skript-do'st) --------------


@pytest.mark.parametrize("rc", [0, 1, 2])
def test_main_propagates_handler_exit_code(monkeypatch, rc):
    """Handler qaytargan exit kod `sys.exit` orqali aynan o'tishi kerak.

    Windows uchun muhim: ruscha konsolda ping noto'g'ri "o'lik" deb topilsa
    EXIT_UNREACHABLE (2) qaytadi — skript buni 0 dan farqlay olishi shart.
    """
    import systop.cli as cli

    async def fake_cmd_info():
        return rc

    monkeypatch.setattr(cli, "_cmd_info", fake_cmd_info)
    monkeypatch.setattr(sys, "argv", ["systop", "info"])
    _main_expect_exit(cli, code=rc)


def test_main_calls_init_console(monkeypatch):
    """main() ishga tushganda `_platform.init_console` chaqirilishi shart.

    Windows konsolini UTF-8/VT ga o'tkazadi (TUI/Rich Unicode uchun). POSIX'da
    no-op, ammo chaqiruv baribir bo'lishi kerak (regressiya himoyasi).
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


# --- Konsol kodlash himoyasi (Windows cp866 / POSIX LANG=C) -----------------


@pytest.mark.parametrize(
    "encoding, expected",
    [
        ("utf-8", True),
        ("UTF-8", True),
        ("utf8", True),
        ("ascii", False),
        ("ANSI_X3.4-1968", False),  # POSIX C lokal nomi
        ("cp1252", False),  # Windows G'arbiy
        ("cp866", False),  # Windows RUS konsoli
        (None, False),  # kodlash noma'lum -> himoyalaymiz
        ("", False),
    ],
)
def test_stream_encoding_is_safe(encoding, expected):
    """ASCII/OEM kodlash xavfsiz EMAS deb aniqlansin (reconfigure kerak)."""
    import systop.cli as cli

    class _FakeStream:
        pass

    stream = _FakeStream()
    stream.encoding = encoding  # type: ignore[attr-defined]
    assert cli._stream_encoding_is_safe(stream) is expected


def test_safe_write_survives_non_ascii_on_ascii_stream():
    """ASCII kodlashli oqimga non-ASCII yozish yiqitmasligi kerak (LANG=C).

    `print` to'g'ridan-to'g'ri UnicodeEncodeError bergan bo'lardi; `_safe_write`
    esa `errors="replace"` bilan buffer'ga yozadi.
    """
    import systop.cli as cli

    raw = io.BytesIO()

    class _AsciiStream:
        encoding = "ascii"

        def __init__(self) -> None:
            self.buffer = raw

        def write(self, text: str) -> int:
            # Haqiqiy ASCII oqim kabi non-ASCII'da yiqiladi.
            text.encode("ascii")
            raw.write(text.encode("ascii"))
            return len(text)

    stream = _AsciiStream()
    # O'zbekcha + kirill + emoji — hammasi non-ASCII.
    cli._safe_write(stream, "Tezlik o'lchandi — Ответ 🟢\n")
    out = raw.getvalue()
    assert out  # nimadir yozildi
    # ASCII'ga sig'maydigan belgilar '?' ga aylangan, ammo istisno YO'Q.
    assert b"?" in out


def test_safe_write_plain_ascii_passthrough():
    """Sof ASCII matn o'zgarmasdan yoziladi (oddiy `write` muvaffaqiyatli)."""
    import systop.cli as cli

    buf = io.StringIO()  # StringIO non-ASCII'ni ham qabul qiladi, xato bermaydi
    cli._safe_write(buf, "hello\n")
    assert buf.getvalue() == "hello\n"


def test_harden_console_streams_idempotent(monkeypatch):
    """`_harden_console_streams` UTF oqimga tegmaydi, ASCII'ni reconfigure qiladi."""
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

    # UTF oqim reconfigure QILINMADI; ASCII oqim UTF-8 + replace'ga o'tkazildi.
    assert ("utf-8", "replace") in calls
    assert len(calls) == 1  # faqat ascii_stream


# --- emit_json / emit_csv ASCII lokalda ham yiqilmaydi ----------------------


def test_emit_json_writes_valid_json_via_safe_path(monkeypatch, capsys):
    """emit_json sof, o'qish mumkin JSON beradi (non-ASCII saqlanadi)."""
    import systop.cli as cli

    monkeypatch.setattr(cli, "_FORMAT", "json")
    cli.emit_json({"label": "Gateway (lokal)", "javob": "Ответ"})
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["label"] == "Gateway (lokal)"
    assert parsed["javob"] == "Ответ"


def test_error_machine_mode_goes_to_stderr(monkeypatch, capsys):
    """Machine (json) rejimida xato STDERR'ga (stdout toza qoladi)."""
    import systop.cli as cli

    monkeypatch.setattr(cli, "_FORMAT", "json")
    cli.error("host o'lik — Узел недоступен")
    captured = capsys.readouterr()
    assert captured.out == ""  # stdout toza (mashina o'qishi buzilmaydi)
    assert "Узел недоступен" in captured.err


# --- Integratsiya: C/ASCII lokalda (LANG=C) CLI yiqilmaydi (offline buyruq) --
#
# `config --show` tarmoqqa CHIQMAYDI, ammo o'zbekcha + kirill + emoji chiqaradi.
# `PYTHONUTF8=0`+`PYTHONCOERCECLOCALE=0`+`LC_ALL=C` stdout'ni `ascii` codec'ga
# majburlaydi (Windows cp866/cp1252 muammosining POSIX ekvivalenti). Himoyasiz
# bu `UnicodeEncodeError` + exit 1 berardi; `_harden_console_streams` tufayli
# endi toza ishlaydi.


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
    # NO_COLOR — Rich markup'siz, sof matn (tekshirish barqaror bo'lsin).
    env["NO_COLOR"] = "1"
    return env


def _python_uses_ascii_stdout(env: dict) -> bool:
    """Berilgan muhitda Python stdout'ni ascii codec bilan ochadimi (tekshiramiz).

    macOS/Linux: forced env ascii beradi. Windows: codec boshqacha bo'lishi
    mumkin — bu test faqat ascii lokal haqiqatan reproduksiya bo'lsa ma'noli.
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
    """`config --show --json` ASCII lokalda ham toza JSON + exit 0 berishi shart."""
    env = _ascii_locale_env()
    if not _python_uses_ascii_stdout(env):
        pytest.skip("bu platformada ascii lokal reproduksiya bo'lmadi (PEP 540 UTF-8 rejimi)")
    proc = _run_cli("config", "--show", "--json", env=env)
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == ""  # toza stderr (UnicodeEncodeError yo'q)
    data = json.loads(proc.stdout)  # to'liq, yaroqli JSON
    assert "ping_targets" in data


def test_cli_table_survives_ascii_locale():
    """`config --show` (o'zbekcha matn) ASCII lokalda yiqilmasligi kerak."""
    env = _ascii_locale_env()
    if not _python_uses_ascii_stdout(env):
        pytest.skip("bu platformada ascii lokal reproduksiya bo'lmadi (PEP 540 UTF-8 rejimi)")
    proc = _run_cli("config", "--show", env=env)
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    # Chiqishda nimadir bor (jadval), traceback YO'Q.
    assert "Traceback" not in proc.stderr
    assert "UnicodeEncodeError" not in proc.stderr
