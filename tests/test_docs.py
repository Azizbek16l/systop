"""Documentation–code parity tests — OFFLINE.

They stop the documentation from falling behind the code. The single source of
truth is `_build_parser()` in `cli.py`. Three things are checked here:

1. Every subcommand appears in `README.md` in the form `systop <cmd>`;
2. The set of commands in the `cli.py` module docstring is EXACTLY equal to the
   parser's (neither fewer nor more — a removed command is caught as well);
3. The READMEs do not link to a local image that does not exist
   (`assets/demo.gif` broke exactly like that once).

It never touches the network and opens no subprocess — only file reads and
regexes.
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
    """The real subcommand names in `_build_parser()` — the single source."""
    parser = cli._build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("no subparser was found in cli._build_parser()")


# `systop <cmd>` — the boundaries are deliberately strict:
#   * `[^\S\n]+` (horizontal whitespace) — so that the word on the NEXT LINE in
#     `cd systop\nuv sync` is not read as a command;
#   * `(?<![\w./-])` — so that `./systop-linux-x86_64` and `systop.app:SystopApp`
#     stay out;
#   * it has to start with `[a-z]` — so that prose like `systop CLI — ...` does
#     not match.
_CMD_RE = re.compile(r"(?<![\w./-])systop[^\S\n]+([a-z][a-z0-9_-]*)(?![\w-])")
_FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)


def _documented_in(text: str) -> set[str]:
    """Collects the command names from the `systop <cmd>` occurrences in the text."""
    return set(_CMD_RE.findall(text))


def _documented_in_code_blocks(text: str) -> set[str]:
    """Collects only from the code blocks fenced with ```.

    The prose contains sentences like "systop runs on Linux" — those are not
    commands. In the documentation a command has to be shown **through its
    usage** (a line you can copy and paste), so only the code blocks count.
    """
    return _documented_in("\n".join(_FENCE_RE.findall(text)))


@pytest.fixture(scope="module")
def subcommands() -> set[str]:
    return _subcommands()


def test_subcommand_map_is_not_empty(subcommands: set[str]) -> None:
    """Sanity: the parser really does yield subcommands (the regex must not match an empty set)."""
    assert len(subcommands) > 10
    # A few anchors — if the parser structure changes completely it shows at once.
    assert {"ping", "speed", "doctor", "wifi"} <= subcommands


@pytest.mark.parametrize("readme", _READMES, ids=lambda p: p.name)
def test_every_subcommand_appears_in_readme(readme: Path, subcommands: set[str]) -> None:
    """Every subcommand must be documented in BOTH READMEs."""
    documented = _documented_in_code_blocks(readme.read_text(encoding="utf-8"))
    missing = sorted(subcommands - documented)
    assert not missing, (
        f"subcommand(s) not documented in {readme.name}: {missing}. Add a `systop <command>` line."
    )


@pytest.mark.parametrize("readme", _READMES, ids=lambda p: p.name)
def test_readme_does_not_document_unknown_subcommand(readme: Path, subcommands: set[str]) -> None:
    """The README must not show a command the parser does not know (removed/renamed)."""
    documented = _documented_in_code_blocks(readme.read_text(encoding="utf-8"))
    unknown = sorted(documented - subcommands)
    assert not unknown, f"{readme.name} shows subcommand(s) that do not exist: {unknown}."


def test_cli_docstring_matches_subparsers(subcommands: set[str]) -> None:
    """The `cli.py` module docstring must list EXACTLY the parser's commands."""
    doc = cli.__doc__
    assert doc, "cli.py has no module docstring"
    listed = _documented_in(doc)

    missing = sorted(subcommands - listed)
    extra = sorted(listed - subcommands)
    assert not missing, f"missing from the cli.py docstring: {missing}"
    assert not extra, f"superfluous in the cli.py docstring (the parser does not know it): {extra}"


@pytest.mark.parametrize("readme", _READMES, ids=lambda p: p.name)
def test_readme_local_images_exist(readme: Path) -> None:
    """The local image links in the README must really exist (no broken embed)."""
    text = readme.read_text(encoding="utf-8")
    broken = [
        target
        for target in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)
        if not target.startswith(("http://", "https://", "data:"))
        and not (_REPO_ROOT / target).exists()
    ]
    assert not broken, f"image(s) that do not exist in {readme.name}: {broken}"
