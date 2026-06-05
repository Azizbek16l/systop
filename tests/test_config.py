"""config testlari — OFFLINE.

``load_config`` ni ``tmp_path`` da yaratilgan TOML fayllar bilan sinaymiz: to'g'ri
qiymatlar, yo'q fayl -> default, buzuq TOML -> default, noto'g'ri tur jim
e'tiborsiz, ``SYSTOP_CONFIG`` env override. Fayl tizimidan boshqa I/O yo'q.
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
    # Berilmagan kalitlar default qoladi.
    assert cfg.ping_targets == DEFAULT_PING_TARGETS
    assert cfg.dns_resolvers == DEFAULT_DNS_RESOLVERS
    assert cfg.speed_duration == DEFAULT_SPEED_DURATION
    assert cfg.speed_parallel == DEFAULT_SPEED_PARALLEL


def test_load_config_integer_speed_duration_coerced_to_float(tmp_path):
    cfg = load_config(_write(tmp_path, "speed_duration = 7\n"))
    assert cfg.speed_duration == 7.0
    assert isinstance(cfg.speed_duration, float)


# --- yo'q fayl / buzuq TOML -> default --------------------------------------


def test_load_config_missing_file_returns_default(tmp_path):
    cfg = load_config(tmp_path / "yoq.toml")
    assert cfg == SystopConfig()
    assert cfg.theme == DEFAULT_THEME


def test_load_config_directory_path_returns_default(tmp_path):
    # Yo'l katalogga ishora qilsa (IsADirectoryError) -> default.
    cfg = load_config(tmp_path)
    assert cfg == SystopConfig()


def test_load_config_broken_toml_returns_default(tmp_path):
    cfg = load_config(_write(tmp_path, "this is = = not valid toml ]["))
    assert cfg == SystopConfig()


def test_load_config_invalid_utf8_returns_default(tmp_path):
    p = tmp_path / "config.toml"
    p.write_bytes(b"\xff\xfe\x00bad")
    assert load_config(p) == SystopConfig()


# --- noto'g'ri turdagi qiymatlar jim e'tiborsiz -----------------------------


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
    # Hammasi noto'g'ri/manfiy/bo'sh -> default'ga qaytadi.
    assert cfg.ping_targets == DEFAULT_PING_TARGETS
    assert cfg.dns_resolvers == DEFAULT_DNS_RESOLVERS
    assert cfg.speed_duration == DEFAULT_SPEED_DURATION
    assert cfg.speed_parallel == DEFAULT_SPEED_PARALLEL
    assert cfg.theme == DEFAULT_THEME


def test_load_config_boolean_not_accepted_as_number(tmp_path):
    """TOML'da ``true`` bool — son sifatida qabul qilinmasligi kerak."""
    cfg = load_config(_write(tmp_path, "speed_parallel = true\nspeed_duration = true\n"))
    assert cfg.speed_parallel == DEFAULT_SPEED_PARALLEL
    assert cfg.speed_duration == DEFAULT_SPEED_DURATION


def test_load_config_empty_scan_ports_allowed(tmp_path):
    # scan_ports = "" -> haqiqiy string, qabul qilinadi (default ham "").
    cfg = load_config(_write(tmp_path, 'scan_ports = ""\n'))
    assert cfg.scan_ports == ""


def test_load_config_mixed_list_rejected(tmp_path):
    # Ro'yxatda string bo'lmagan element bo'lsa -> butun ro'yxat rad etiladi.
    cfg = load_config(_write(tmp_path, 'ping_targets = ["1.1.1.1", 42]\n'))
    assert cfg.ping_targets == DEFAULT_PING_TARGETS


# --- SYSTOP_CONFIG env override ---------------------------------------------


def test_load_config_env_override(tmp_path, monkeypatch):
    p = _write(tmp_path, 'theme = "from-env"\n')
    monkeypatch.setenv(ENV_VAR, str(p))
    # path argumenti berilmaydi -> env'dan o'qiladi.
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
    # default_factory -> har instansiya o'z ro'yxatiga ega (umumiy emas).
    assert "9.9.9.9" not in b.ping_targets
