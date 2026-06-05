# Contributing to systop

Thanks for your interest in improving systop. This guide covers the dev setup,
the tooling, and the two conventions that keep the codebase coherent.

## Dev setup

systop uses [uv](https://docs.astral.sh/uv/) and targets **Python 3.11+**.

```bash
git clone https://github.com/azizbek/systop
cd systop
uv sync --extra dev      # create the venv and install dev dependencies
```

## Tooling

```bash
uv run pytest            # run the full offline test suite
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy src          # type-check (if mypy is configured locally)
```

Run the TUI in dev/debug mode while iterating:

```bash
uv run textual run --dev systop.app:SystopApp
# In another terminal, see live logs:
uv run textual console
```

Please run `ruff check`, `ruff format`, and `pytest` before opening a pull
request. Keep changes focused and describe the user-visible effect.

## Architecture: keep core and UI separate

The codebase is split into two layers, and the separation is strict:

```
src/systop/
  core/        async network logic — NO Textual/UI imports; usable standalone
  cli.py       one-shot CLI commands (argparse + Rich tables / JSON / CSV)
  widgets/     Textual panels (the TUI)
  app.py       the dashboard that wires the widgets together
```

`cli.py` and `widgets/*` are the **only two callers** of `core/`. Both call the
same async functions. When you add a measurement:

1. Write a pure async function in `core/` first. It must take no UI objects and
   **return a dataclass or a plain value** — so the CLI, the TUI, and the tests
   can all use it identically.
2. Wire it into `cli.py` (a Rich table for `table` mode; make sure `--json` /
   `--format csv` work — the serializer in `cli.py` handles dataclasses).
3. Wire it into a `widgets/` panel for the dashboard.

In the TUI, network work runs in `@work(exclusive=True)` methods. Each
independent operation in a multi-action panel must use its own `group=`, or one
will cancel another (e.g. LAN scan vs DNS running at the same time).

## Offline-test rule

**Tests must not touch the network.** CI and contributors run them offline, so:

- Test pure logic: regex parsing, dataclasses, target building, port spec
  parsing, OUI lookup, config loading, etc.
- Genuinely network-bound functions (ping / traceroute / scan / dns / live
  bandwidth) cannot be unit-tested directly and are left untested.
- The speed test is the exception: it is tested with `httpx.MockTransport`
  (`tests/test_speed.py`) — no real network. Note that because the mock
  responds instantly, the `await asyncio.sleep(0)` in the speed streamers is
  load-bearing; without it the test hangs.

If you add core logic, add an offline test for the deterministic parts.

## Uzbek user-facing-text rule

This project's user-facing strings are written in **Uzbek**: panel titles,
table column headers, error messages, CLI help text, and docstrings. **Code
identifiers (names, functions, variables) stay in English.**

Keep this consistent — new commands, panels, and messages should follow the same
split (Uzbek for what the user reads, English for the code).

## Reporting bugs and proposing features

Open an issue with:

- What you ran (the exact command), your OS, and Python version.
- What you expected vs what happened (include `--json` output or a screenshot
  for the TUI where helpful).

For security issues, see [SECURITY.md](SECURITY.md) — please do not file them as
public issues.
