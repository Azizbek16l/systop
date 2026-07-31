"""Foydalanuvchi konfiguratsiyasi — `~/.config/systop/config.toml` (stdlib tomllib).

Konfiguratsiya ixtiyoriy: fayl bo'lmasa yoki buzuq bo'lsa, oqilona default
qiymatlar bilan `SystopConfig` qaytariladi (istisno ko'tarilmaydi, jim).
`SYSTOP_CONFIG` atrof-muhit o'zgaruvchisi orqali boshqa yo'l ko'rsatish mumkin.

config.toml namunasi:

    ping_targets = ["1.1.1.1", "8.8.8.8"]
    dns_resolvers = ["1.1.1.1", "9.9.9.9"]
    speed_duration = 10.0
    speed_parallel = 4
    theme = "dark"
    scan_ports = "1-1024"

Faqat stdlib (tomllib, os, pathlib); boshqa core modullarni import qilmaydi.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

# Default qiymatlar — boshqa core modullaridagi tanlovlar bilan mos.
DEFAULT_PING_TARGETS: list[str] = ["1.1.1.1", "8.8.8.8"]
DEFAULT_DNS_RESOLVERS: list[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DEFAULT_SPEED_DURATION: float = 10.0
DEFAULT_SPEED_PARALLEL: int = 4
DEFAULT_THEME: str = "dark"
# Lokal (IX) tezlik endpointlari — ATAYLAB BO'SH.
# Har mamlakatda o'zinikini config'da berish kerak (O'zbekistonda TAS-IX
# mirrorlari, boshqa yurtda o'sha yurt IX'i). Kodga yozib qo'yish tool'ni
# bitta mamlakatga bog'lab qo'yardi va boshqa joyda noto'g'ri ishlardi.
DEFAULT_SPEED_LOCAL_URLS: list[str] = []

DEFAULT_SCAN_PORTS: str = ""  # bo'sh => keng tarqalgan portlar (ports.default_ports)

# Atrof-muhit override va standart joylashuv.
ENV_VAR: str = "SYSTOP_CONFIG"
DEFAULT_CONFIG_PATH: Path = Path.home() / ".config" / "systop" / "config.toml"


@dataclass(slots=True)
class SystopConfig:
    """Foydalanuvchi sozlamalari (barchasi default qiymatli — fayl ixtiyoriy)."""

    ping_targets: list[str] = field(default_factory=lambda: list(DEFAULT_PING_TARGETS))
    dns_resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_DNS_RESOLVERS))
    speed_duration: float = DEFAULT_SPEED_DURATION
    speed_parallel: int = DEFAULT_SPEED_PARALLEL
    theme: str = DEFAULT_THEME
    scan_ports: str = DEFAULT_SCAN_PORTS
    speed_local_urls: list[str] = field(
        default_factory=lambda: list(DEFAULT_SPEED_LOCAL_URLS)
    )


def _resolve_path(path: str | Path | None) -> Path:
    """Konfiguratsiya yo'lini aniqlaydi: argument > SYSTOP_CONFIG > standart joy."""
    if path is not None:
        return Path(path).expanduser()
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env).expanduser()
    return DEFAULT_CONFIG_PATH


def _as_str_list(value: object) -> list[str] | None:
    """TOML qiymatini string ro'yxatiga aylantiradi (noto'g'ri tur => None)."""
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return list(value)
    return None


def _coerce(cfg: SystopConfig, data: dict[str, object]) -> None:
    """TOML lug'atidagi mos kalitlarni `cfg` ustiga qo'yadi (xato qiymat e'tiborsiz)."""
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

    # Lokal (IX) tezlik endpointlari — faqat http(s) URL qabul qilinadi.
    if (v := _as_str_list(data.get("speed_local_urls"))) is not None:
        cfg.speed_local_urls = [u for u in v if u.startswith(("http://", "https://"))]


def load_config(path: str | Path | None = None) -> SystopConfig:
    """Konfiguratsiyani o'qiydi; fayl yo'q yoki buzuq bo'lsa default qaytaradi.

    Yo'l aniqlash tartibi: `path` argumenti > `SYSTOP_CONFIG` env > standart
    `~/.config/systop/config.toml`. Hech qanday xato (yo'q fayl, buzuq TOML,
    ruxsat yo'qligi) ko'tarilmaydi — bunday holda to'liq default `SystopConfig`
    qaytadi. Faqat tanilgan kalitlar qabul qilinadi; noto'g'ri turdagi
    qiymatlar jim e'tiborsiz qoldiriladi.
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
    """Sozlama maydonlari nomlarini qaytaradi (CLI yordami / introspeksiya uchun)."""
    return tuple(f.name for f in fields(SystopConfig))
