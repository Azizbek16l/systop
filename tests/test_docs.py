"""Hujjat–kod pariteti testlari — OFFLINE.

Hujjatlar koddan orqada qolib ketishining oldini oladi. Yagona haqiqat manbai
— `cli.py`dagi `_build_parser()`. Bu yerda uch narsa tekshiriladi:

1. Har bir subbuyruq `README.md` da `systop <cmd>`
   ko'rinishida uchraydi;
2. `cli.py` modul docstring'idagi buyruqlar to'plami parser bilan AYNAN teng
   (kam ham emas, ortiq ham emas — o'chirilgan buyruq ham ushlanadi);
3. README'lar mavjud bo'lmagan lokal rasmga havola qilmaydi (`assets/demo.gif`
   bir marta shunday sinib qolgan edi).

Tarmoqqa chiqmaydi, subprocess ochmaydi — faqat fayl o'qish va regex.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

import systop.cli as cli

_REPO_ROOT = Path(__file__).resolve().parent.parent
_README_EN = _REPO_ROOT / "README.md"
_READMES = (_README_EN,)


def _subcommands() -> set[str]:
    """`_build_parser()` dagi haqiqiy subbuyruq nomlari — yagona manba."""
    parser = cli._build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("cli._build_parser() da subparser topilmadi")


# `systop <cmd>` — chegaralar ataylab qattiq:
#   * `[^\S\n]+` (gorizontal bo'shliq) — `cd systop\nuv sync` dagi keyingi
#     QATOR so'zini buyruq deb o'qimasligi uchun;
#   * `(?<![\w./-])` — `./systop-linux-x86_64` va `systop.app:SystopApp` chetda
#     qolsin;
#   * `[a-z]` bilan boshlanishi — `systop CLI — ...` kabi nasr mos kelmasin.
_CMD_RE = re.compile(r"(?<![\w./-])systop[^\S\n]+([a-z][a-z0-9_-]*)(?![\w-])")
_FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)


def _documented_in(text: str) -> set[str]:
    """Matndagi `systop <cmd>` ko'rinishlaridan buyruq nomlarini yig'adi."""
    return set(_CMD_RE.findall(text))


def _documented_in_code_blocks(text: str) -> set[str]:
    """Faqat ``` bilan o'ralgan kod bloklaridan yig'adi.

    Nasrda "systop runs on Linux" kabi jumlalar bor — ular buyruq emas.
    Hujjatda buyruq **ishlatilishi bilan** (nusxa-ko'chirsa bo'ladigan qator)
    ko'rsatilgan bo'lishi kerak, shuning uchun faqat kod bloklari sanaladi.
    """
    return _documented_in("\n".join(_FENCE_RE.findall(text)))


@pytest.fixture(scope="module")
def subcommands() -> set[str]:
    return _subcommands()


def test_subcommand_map_is_not_empty(subcommands: set[str]) -> None:
    """Sanity: parser haqiqatan subbuyruqlar beradi (regex bo'sh to'plamga mos kelmasin)."""
    assert len(subcommands) > 10
    # Bir nechta kotva — parser tuzilishi butunlay o'zgarsa darhol ko'rinadi.
    assert {"ping", "speed", "doctor", "wifi"} <= subcommands


@pytest.mark.parametrize("readme", _READMES, ids=lambda p: p.name)
def test_every_subcommand_appears_in_readme(readme: Path, subcommands: set[str]) -> None:
    """Har bir subbuyruq IKKALA README'da ham hujjatlashtirilgan bo'lishi kerak."""
    documented = _documented_in_code_blocks(readme.read_text(encoding="utf-8"))
    missing = sorted(subcommands - documented)
    assert not missing, (
        f"{readme.name} da hujjatlashtirilmagan subbuyruq(lar): {missing}. "
        f"`systop <buyruq>` qatorini qo'shing."
    )


@pytest.mark.parametrize("readme", _READMES, ids=lambda p: p.name)
def test_readme_does_not_document_unknown_subcommand(readme: Path, subcommands: set[str]) -> None:
    """README'da parser bilmaydigan buyruq ko'rsatilmasin (o'chirilgan/nomi o'zgargan)."""
    documented = _documented_in_code_blocks(readme.read_text(encoding="utf-8"))
    unknown = sorted(documented - subcommands)
    assert not unknown, f"{readme.name} mavjud bo'lmagan subbuyruq(lar)ni ko'rsatmoqda: {unknown}."


def test_cli_docstring_matches_subparsers(subcommands: set[str]) -> None:
    """`cli.py` modul docstring'i AYNAN parser'dagi buyruqlarni sanashi kerak."""
    doc = cli.__doc__
    assert doc, "cli.py modul docstring'i yo'q"
    listed = _documented_in(doc)

    missing = sorted(subcommands - listed)
    extra = sorted(listed - subcommands)
    assert not missing, f"cli.py docstring'ida yo'q: {missing}"
    assert not extra, f"cli.py docstring'ida ortiqcha (parser bilmaydi): {extra}"


@pytest.mark.parametrize("readme", _READMES, ids=lambda p: p.name)
def test_readme_local_images_exist(readme: Path) -> None:
    """README'dagi lokal rasm havolalari haqiqatan mavjud bo'lsin (sinuvchi embed yo'q)."""
    text = readme.read_text(encoding="utf-8")
    broken = [
        target
        for target in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)
        if not target.startswith(("http://", "https://", "data:"))
        and not (_REPO_ROOT / target).exists()
    ]
    assert not broken, f"{readme.name} da mavjud bo'lmagan rasm(lar): {broken}"
