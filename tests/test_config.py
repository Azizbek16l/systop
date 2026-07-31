"""config tests — OFFLINE.

We exercise ``load_config`` with TOML files created under ``tmp_path``: valid
values, a missing file -> defaults, corrupt TOML -> defaults, a wrong type
silently ignored, the ``SYSTOP_CONFIG`` env override. There is no I/O other than
the filesystem.
"""

from __future__ import annotations

from pathlib import Path

from systop.core.config import (
    DEFAULT_DNS_RESOLVERS,
    DEFAULT_PING_TARGETS,
    DEFAULT_SPEED_DURATION,
    DEFAULT_SPEED_PARALLEL,
    DEFAULT_THEME,
    ENV_VAR,
    SystopConfig,
    config_fields,
    load_config,
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(body, encoding="utf-8")
    return p


# --- valid TOML -------------------------------------------------------------


def test_load_config_valid_full(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            """
            ping_targets = ["1.1.1.1", "8.8.4.4"]
            dns_resolvers = ["9.9.9.9"]
            speed_duration = 5.5
            speed_parallel = 8
            theme = "light"
            scan_ports = "1-1024"
            """,
        )
    )
    assert cfg.ping_targets == ["1.1.1.1", "8.8.4.4"]
    assert cfg.dns_resolvers == ["9.9.9.9"]
    assert cfg.speed_duration == 5.5
    assert cfg.speed_parallel == 8
    assert cfg.theme == "light"
    assert cfg.scan_ports == "1-1024"


def test_load_config_partial_keeps_defaults_for_missing(tmp_path):
    cfg = load_config(_write(tmp_path, 'theme = "solarized"\n'))
    assert cfg.theme == "solarized"
    # The keys that were not given stay at their defaults.
    assert cfg.ping_targets == DEFAULT_PING_TARGETS
    assert cfg.dns_resolvers == DEFAULT_DNS_RESOLVERS
    assert cfg.speed_duration == DEFAULT_SPEED_DURATION
    assert cfg.speed_parallel == DEFAULT_SPEED_PARALLEL


def test_load_config_integer_speed_duration_coerced_to_float(tmp_path):
    cfg = load_config(_write(tmp_path, "speed_duration = 7\n"))
    assert cfg.speed_duration == 7.0
    assert isinstance(cfg.speed_duration, float)


# --- a missing file / corrupt TOML -> defaults ------------------------------


def test_load_config_missing_file_returns_default(tmp_path):
    cfg = load_config(tmp_path / "absent.toml")
    assert cfg == SystopConfig()
    assert cfg.theme == DEFAULT_THEME


def test_load_config_directory_path_returns_default(tmp_path):
    # If the path points at a directory (IsADirectoryError) -> defaults.
    cfg = load_config(tmp_path)
    assert cfg == SystopConfig()


def test_load_config_broken_toml_returns_default(tmp_path):
    cfg = load_config(_write(tmp_path, "this is = = not valid toml ]["))
    assert cfg == SystopConfig()


def test_load_config_invalid_utf8_returns_default(tmp_path):
    p = tmp_path / "config.toml"
    p.write_bytes(b"\xff\xfe\x00bad")
    assert load_config(p) == SystopConfig()


# --- values of the wrong type are silently ignored --------------------------


def test_load_config_wrong_types_ignored(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            """
            ping_targets = "not-a-list"
            dns_resolvers = [1, 2, 3]
            speed_duration = -5
            speed_parallel = 0
            theme = ""
            """,
        )
    )
    # Everything is wrong/negative/empty -> it falls back to the defaults.
    assert cfg.ping_targets == DEFAULT_PING_TARGETS
    assert cfg.dns_resolvers == DEFAULT_DNS_RESOLVERS
    assert cfg.speed_duration == DEFAULT_SPEED_DURATION
    assert cfg.speed_parallel == DEFAULT_SPEED_PARALLEL
    assert cfg.theme == DEFAULT_THEME


def test_load_config_boolean_not_accepted_as_number(tmp_path):
    """In TOML ``true`` is a bool — it must not be accepted as a number."""
    cfg = load_config(_write(tmp_path, "speed_parallel = true\nspeed_duration = true\n"))
    assert cfg.speed_parallel == DEFAULT_SPEED_PARALLEL
    assert cfg.speed_duration == DEFAULT_SPEED_DURATION


def test_load_config_empty_scan_ports_allowed(tmp_path):
    # scan_ports = "" -> a genuine string, it is accepted (the default is "" too).
    cfg = load_config(_write(tmp_path, 'scan_ports = ""\n'))
    assert cfg.scan_ports == ""


def test_load_config_mixed_list_rejected(tmp_path):
    # If the list holds a non-string element -> the whole list is rejected.
    cfg = load_config(_write(tmp_path, 'ping_targets = ["1.1.1.1", 42]\n'))
    assert cfg.ping_targets == DEFAULT_PING_TARGETS


# --- SYSTOP_CONFIG env override ---------------------------------------------


def test_load_config_env_override(tmp_path, monkeypatch):
    p = _write(tmp_path, 'theme = "from-env"\n')
    monkeypatch.setenv(ENV_VAR, str(p))
    # No path argument is given -> it is read from the env.
    cfg = load_config()
    assert cfg.theme == "from-env"


def test_load_config_explicit_path_beats_env(tmp_path, monkeypatch):
    env_file = _write(tmp_path, 'theme = "env-theme"\n')
    arg_file = tmp_path / "arg.toml"
    arg_file.write_text('theme = "arg-theme"\n', encoding="utf-8")
    monkeypatch.setenv(ENV_VAR, str(env_file))
    cfg = load_config(arg_file)
    assert cfg.theme == "arg-theme"


def test_load_config_env_missing_file_returns_default(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_VAR, str(tmp_path / "does-not-exist.toml"))
    assert load_config() == SystopConfig()


# --- config_fields / dataclass ----------------------------------------------


def test_config_fields_names():
    fields = config_fields()
    assert "ping_targets" in fields
    assert "dns_resolvers" in fields
    assert "speed_duration" in fields
    assert "speed_parallel" in fields
    assert "theme" in fields
    assert "scan_ports" in fields


def test_systop_config_defaults_independent_lists():
    a = SystopConfig()
    b = SystopConfig()
    a.ping_targets.append("9.9.9.9")
    # default_factory -> every instance has its own list (they are not shared).
    assert "9.9.9.9" not in b.ping_targets
