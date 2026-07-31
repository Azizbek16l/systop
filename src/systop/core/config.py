"""User configuration — `~/.config/systop/config.toml` (stdlib tomllib).

The configuration is optional: if the file is missing or corrupt, a
`SystopConfig` with sensible default values is returned (silently, with no
exception raised). A different path can be pointed at through the
`SYSTOP_CONFIG` environment variable.

An example config.toml:

    ping_targets = ["1.1.1.1", "8.8.8.8"]
    dns_resolvers = ["1.1.1.1", "9.9.9.9"]
    speed_duration = 10.0
    speed_parallel = 4
    theme = "dark"
    scan_ports = "1-1024"

Only stdlib (tomllib, os, pathlib); it imports no other core module.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

# The default values — consistent with the choices made in the other core modules.
DEFAULT_PING_TARGETS: list[str] = ["1.1.1.1", "8.8.8.8"]
DEFAULT_DNS_RESOLVERS: list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DEFAULT_SPEED_DURATION: float = 10.0
DEFAULT_SPEED_PARALLEL: int = 4
DEFAULT_THEME: str = "dark"
# The local (IX) speed endpoints — DELIBERATELY EMPTY.
# Every country has to supply its own in the config (TAS-IX mirrors in
# Uzbekistan, that country's own IX elsewhere). Hard-coding them would tie the
# tool to a single country and make it give wrong answers anywhere else.
DEFAULT_SPEED_LOCAL_URLS: list[str] = []

DEFAULT_SCAN_PORTS: str = ""  # empty => the common ports (ports.default_ports)

# The environment override and the standard location.
ENV_VAR: str = "SYSTOP_CONFIG"
DEFAULT_CONFIG_PATH: Path = Path.home() / ".config" / "systop" / "config.toml"


@dataclass(slots=True)
class SystopConfig:
    """The user settings (all of them have defaults — the file is optional)."""

    ping_targets: list[str] = field(default_factory=lambda: list(DEFAULT_PING_TARGETS))
    dns_resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_DNS_RESOLVERS))
    speed_duration: float = DEFAULT_SPEED_DURATION
    speed_parallel: int = DEFAULT_SPEED_PARALLEL
    theme: str = DEFAULT_THEME
    scan_ports: str = DEFAULT_SCAN_PORTS
    speed_local_urls: list[str] = field(default_factory=lambda: list(DEFAULT_SPEED_LOCAL_URLS))


def _resolve_path(path: str | Path | None) -> Path:
    """Determines the config path: the argument > SYSTOP_CONFIG > the standard location."""
    if path is not None:
        return Path(path).expanduser()
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env).expanduser()
    return DEFAULT_CONFIG_PATH


def _as_str_list(value: object) -> list[str] | None:
    """Turns a TOML value into a list of strings (a wrong type => None)."""
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return list(value)
    return None


def _coerce(cfg: SystopConfig, data: dict[str, object]) -> None:
    """Applies the matching keys of the TOML dict onto `cfg` (a bad value is ignored)."""
    if (v := _as_str_list(data.get("ping_targets"))) is not None:
        cfg.ping_targets = v
    if (v := _as_str_list(data.get("dns_resolvers"))) is not None:
        cfg.dns_resolvers = v

    dur = data.get("speed_duration")
    if isinstance(dur, (int, float)) and not isinstance(dur, bool) and dur > 0:
        cfg.speed_duration = float(dur)

    par = data.get("speed_parallel")
    if isinstance(par, int) and not isinstance(par, bool) and par > 0:
        cfg.speed_parallel = par

    theme = data.get("theme")
    if isinstance(theme, str) and theme:
        cfg.theme = theme

    ports = data.get("scan_ports")
    if isinstance(ports, str):
        cfg.scan_ports = ports

    # The local (IX) speed endpoints — only http(s) URLs are accepted.
    if (v := _as_str_list(data.get("speed_local_urls"))) is not None:
        cfg.speed_local_urls = [u for u in v if u.startswith(("http://", "https://"))]


def load_config(path: str | Path | None = None) -> SystopConfig:
    """Reads the configuration; returns the defaults if the file is missing or corrupt.

    The path resolution order: the `path` argument > the `SYSTOP_CONFIG` env >
    the standard `~/.config/systop/config.toml`. No error is ever raised (a
    missing file, corrupt TOML, a lack of permission) — in such a case a full
    default `SystopConfig` comes back. Only known keys are accepted; values of
    the wrong type are silently ignored.
    """
    cfg = SystopConfig()
    target = _resolve_path(path)

    try:
        raw = target.read_bytes()
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
        return cfg

    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, ValueError):
        return cfg

    _coerce(cfg, data)
    return cfg


def config_fields() -> tuple[str, ...]:
    """Returns the names of the setting fields (for CLI help / introspection)."""
    return tuple(f.name for f in fields(SystopConfig))
