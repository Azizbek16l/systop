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
        ("info", "_cmd_info"),
    ],
)
def test_main_dispatches_noarg_commands(monkeypatch, command, handler_name):
    """Argumentsiz buyruqlar (info) to'g'ri handler'ga yo'naltirilsin.

    `lan` (0.4.0) va `speed` (0.9.0) bayroq oladi, shuning uchun ular bu
    ro'yxatdan chiqarilib, o'z testlariga ko'chirildi.
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


# --------------------------------------------------------------------------- #
# 0.4.0: lan bayroqlari + web/doctor buyruqlari
# --------------------------------------------------------------------------- #


def test_main_dispatches_lan_with_flags(monkeypatch):
    """`lan -6 --global-only` bayroqlari _cmd_lan'ga to'g'ri uzatilsin."""
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
    """Bayroqsiz `lan` — hammasi False (eski xulq saqlanadi)."""
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
    """`--http80` — 80-portni topishning qisqa yo'li."""
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
    """`-4` va `-6` birga berilmasligi kerak (argparse xato bersin)."""
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
    """`url`/`risk` property'lari JSON'ga tushishi SHART (jim yo'qolmasin)."""
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
# 0.5.0: scan sweep (nmap uslubi) + nc buyrug'i
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
    """Eski chaqiruv shakli (`scan HOST`) buzilmasligi kerak."""
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
    """`received` bytes JSON'da muammo qilmasligi va xossalar kirishi kerak."""
    import systop.cli as cli
    from systop.core.netcat import NcResult

    d = cli._to_dict(NcResult(host="h", port=22, received=b"SSH-2.0\r\n", connected=True))
    assert d["received_text"].startswith("SSH-2.0")
    assert d["received_bytes_count"] == 9
    assert d["is_binary"] is False


def test_main_dispatches_speed_with_local_flags(monkeypatch):
    """`speed --local-url URL` bayroqlari _cmd_speed'ga uzatilsin."""
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
