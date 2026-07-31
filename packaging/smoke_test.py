#!/usr/bin/env python3
"""Actually tests the built systop binary (not just `--help`).

Usage:
    python3 packaging/smoke_test.py dist/systop
    python3 packaging/smoke_test.py dist/systop.exe

Why this file exists:
  `--help` never gets past argparse — it touches neither textual nor
  styles.tcss. With styles.tcss missing from the bundle `--help` still comes
  back GREEN while the TUI dies in the user's hands. Hence:
    1) --help / --version         -> argparse and binary integrity
    2) doctor --quick --json      -> a real code path + JSON parse
    3) opening the TUI in a PTY   -> textual + styles.tcss (POSIX)
    4) archive TOC check          -> styles.tcss inside the bundle (all three OSes)

Exit: 0 = everything passed, 1 = at least one test failed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

FAILURES: list[str] = []
PASSES: list[str] = []


def ok(name: str, detail: str = "") -> None:
    PASSES.append(name)
    print(f"  PASS  {name}" + (f"  ({detail})" if detail else ""))


def fail(name: str, detail: str) -> None:
    FAILURES.append(f"{name}: {detail}")
    print(f"  FAIL  {name}  -> {detail}")


def skip(name: str, why: str) -> None:
    print(f"  SKIP  {name}  ({why})")


def run(binary: Path, args: list[str], timeout: int = 90) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # A onefile binary unpacks itself to tmp on first launch — no color, fixed width,
    # so the result is identical in any terminal.
    env["NO_COLOR"] = "1"
    env["COLUMNS"] = "120"
    return subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def test_help(binary: Path) -> None:
    name = "--help exit 0"
    try:
        p = run(binary, ["--help"], timeout=120)
    except subprocess.TimeoutExpired:
        fail(name, "timeout")
        return
    if p.returncode != 0:
        fail(name, f"exit={p.returncode} stderr={p.stderr[:400]!r}")
        return
    if "usage" not in p.stdout.lower():
        fail(name, f"no 'usage': {p.stdout[:200]!r}")
        return
    ok(name, f"{len(p.stdout)} bytes of help text")


def test_version(binary: Path) -> None:
    name = "--version"
    try:
        p = run(binary, ["--version"], timeout=60)
    except subprocess.TimeoutExpired:
        fail(name, "timeout")
        return
    out = (p.stdout + p.stderr).strip()
    if p.returncode != 0:
        fail(name, f"exit={p.returncode} out={out[:200]!r}")
        return
    ok(name, out.splitlines()[0] if out else "(empty)")


def test_doctor_json(binary: Path) -> None:
    name = "doctor --quick --json"
    try:
        p = run(binary, ["doctor", "--quick", "--json"], timeout=180)
    except subprocess.TimeoutExpired:
        fail(name, "timeout (>180s)")
        return
    # doctor returns 0 or 2 depending on finding severity — both are normal.
    if p.returncode not in (0, 2):
        fail(name, f"unexpected exit={p.returncode} stderr={p.stderr[:400]!r}")
        return
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        fail(name, f"JSON parse failed: {exc}; stdout[:300]={p.stdout[:300]!r}")
        return
    ok(name, f"exit={p.returncode}, JSON type={type(data).__name__}")


def test_bundle_contains_assets(binary: Path) -> None:
    """Whether systop/styles.tcss is in the onefile archive TOC — works on all three OSes."""
    name = "bundle contains systop/styles.tcss"
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except Exception as exc:  # pragma: no cover
        skip(name, f"PyInstaller import failed ({exc})")
        return
    try:
        reader = CArchiveReader(str(binary))
        names = list(reader.toc)
    except Exception as exc:
        skip(name, f"could not read the archive ({exc})")
        return
    if any(n.replace("\\", "/").endswith("systop/styles.tcss") for n in names):
        ok(name, f"{len(names)} entries in TOC")
    else:
        fail(name, "styles.tcss is MISSING from TOC — the TUI will not start")
    tcss = [n for n in names if n.endswith(".tcss")]
    if len(tcss) > 1:
        ok("textual .tcss assets in bundle", f"{len(tcss)} .tcss files")


def test_tui_starts(binary: Path) -> None:
    """Opens the TUI in a real PTY and closes it with 'q' (POSIX)."""
    name = "TUI starts in a PTY"
    if os.name != "posix":
        skip(name, "PTY is POSIX-only; the TOC check still covers Windows")
        return
    import pty
    import select
    import signal

    pid, fd = pty.fork()
    if pid == 0:  # child process
        os.environ["TERM"] = "xterm-256color"
        os.environ["LINES"] = "40"
        os.environ["COLUMNS"] = "120"
        os.environ.pop("NO_COLOR", None)
        try:
            os.execv(str(binary), [str(binary)])
        except Exception:
            os._exit(127)

    buf = b""
    deadline = time.time() + 45  # a onefile binary's first launch can be slow
    sent_quit = False
    status = None
    try:
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            # Send 'q' once we're confident the TUI has drawn.
            if not sent_quit and (len(buf) > 2000 or time.time() > deadline - 33):
                time.sleep(2.0)
                try:
                    os.write(fd, b"q")
                except OSError:
                    pass
                sent_quit = True
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = st
                break
        if status is None:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1.0)
            try:
                _, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                status = 0
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass

    text = buf.decode("utf-8", "replace")
    bad = [
        "Traceback (most recent call last)",
        "ModuleNotFoundError",
        "FileNotFoundError",
        "StylesheetError",
        "No such file or directory",
        "Failed to execute script",
    ]
    hit = [b for b in bad if b in text]
    if hit:
        tail = text[-1500:]
        fail(name, f"error markers in output {hit}; tail={tail!r}")
        return
    if len(buf) < 200:
        fail(name, f"the TUI drew almost nothing ({len(buf)} bytes) — it didn't start")
        return
    # ANSI screen control = textual actually drew something.
    drew = "\x1b[" in text
    if not drew:
        fail(name, f"no ANSI escapes — the TUI never drew; head={text[:300]!r}")
        return
    ok(name, f"{len(buf)} bytes of ANSI drawn, exited cleanly")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        print(f"ERROR: binary not found: {binary}")
        return 1
    if os.name == "posix" and not os.access(binary, os.X_OK):
        print(f"ERROR: binary is not executable: {binary}")
        return 1

    size = binary.stat().st_size
    print(f"\nsystop smoke test: {binary}")
    print(f"size: {size:,} bytes ({size / 1024 / 1024:.1f} MiB)")
    print(f"platform: {sys.platform} / {os.uname().machine if hasattr(os, 'uname') else 'win'}")
    print(f"`file`: {_file_type(binary)}\n")

    test_help(binary)
    test_version(binary)
    test_bundle_contains_assets(binary)
    test_doctor_json(binary)
    test_tui_starts(binary)

    print(f"\nresult: {len(PASSES)} passed, {len(FAILURES)} failed")
    for f in FAILURES:
        print(f"  - {f}")
    return 1 if FAILURES else 0


def _file_type(binary: Path) -> str:
    if not shutil.which("file"):
        return "(no file)"
    try:
        return subprocess.run(
            ["file", "-b", str(binary)], capture_output=True, text=True, timeout=20
        ).stdout.strip()
    except Exception:
        return "(undetermined)"


if __name__ == "__main__":
    sys.exit(main())
