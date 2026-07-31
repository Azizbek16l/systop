#!/usr/bin/env bash
# Shared build logic — sourced by build-linux.sh and build-macos.sh.
# Not meant to run standalone.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="$REPO_ROOT/packaging/systop.spec"
DIST="$REPO_ROOT/dist"
WORK="$REPO_ROOT/build/pyinstaller"

# Configurable:
#   SYSTOP_SKIP_SMOKE=1   skip the smoke test
#   SYSTOP_PY=python3.12  interpreter for the venv fallback
: "${SYSTOP_SKIP_SMOKE:=0}"
: "${SYSTOP_PY:=python3}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# Prepares the environment and sets the global PYRUN array.
#
# If uv is present — a throwaway overlay environment (leaves the project's
# `.venv` and `pyproject.toml` untouched). If uv is absent — a plain venv
# under build/.buildenv. Either way the build never touches the project's
# own `.venv`, which is also why `pyinstaller` was not added to
# `pyproject.toml` as a dev dependency — it is unnecessary.
prepare_env() {
  if command -v uv >/dev/null 2>&1; then
    log "uv found — using a throwaway build environment (leaves the project .venv untouched)"
    PYRUN=(uv run --with pyinstaller)
    "${PYRUN[@]}" python -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
  else
    local venv="$REPO_ROOT/build/.buildenv"
    log "uv not found — venv fallback: $venv"
    command -v "$SYSTOP_PY" >/dev/null 2>&1 || die "$SYSTOP_PY not found (point to it with SYSTOP_PY)"
    [ -x "$venv/bin/python" ] || "$SYSTOP_PY" -m venv "$venv"
    "$venv/bin/python" -m pip install --upgrade --quiet pip wheel
    # The project itself + the build-only dependency. `.` not `-e .` — a
    # frozen binary must not end up bound to the editable path.
    "$venv/bin/python" -m pip install --quiet "$REPO_ROOT" pyinstaller
    PYRUN=("$venv/bin/python" -m)
    "$venv/bin/python" -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
  fi
}

# Runs PyInstaller with the spec file.
build() {
  log "PyInstaller (onefile, console) — $SPEC"
  rm -rf "$WORK"
  if [ "${PYRUN[0]}" = "uv" ]; then
    (cd "$REPO_ROOT" && "${PYRUN[@]}" pyinstaller --noconfirm --clean \
        --distpath "$DIST" --workpath "$WORK" "$SPEC")
  else
    (cd "$REPO_ROOT" && "${PYRUN[@]}" PyInstaller --noconfirm --clean \
        --distpath "$DIST" --workpath "$WORK" "$SPEC")
  fi
  [ -f "$DIST/systop" ] || die "binary was not created: $DIST/systop"
}

# Creates the labeled copy: systop-<os>-<arch>
label() {
  local osname="$1"
  local arch
  arch="$(uname -m)"
  ARTIFACT="$DIST/systop-${osname}-${arch}"
  cp -f "$DIST/systop" "$ARTIFACT"
  chmod +x "$ARTIFACT" "$DIST/systop"
  log "Artifact: $ARTIFACT"
  ls -lh "$ARTIFACT" | awk '{print "    size:", $5}'
  # The hash file must contain ONLY the base name — otherwise `shasum -c`
  # on another machine looks for the absolute path (the build machine's path)
  # and fails.
  local base
  base="$(basename "$ARTIFACT")"
  if command -v shasum >/dev/null 2>&1; then
    (cd "$DIST" && shasum -a 256 "$base" | tee "$base.sha256")
  else
    (cd "$DIST" && sha256sum "$base" | tee "$base.sha256")
  fi
}

smoke() {
  if [ "$SYSTOP_SKIP_SMOKE" = "1" ]; then
    log "smoke test skipped (SYSTOP_SKIP_SMOKE=1)"
    return 0
  fi
  log "Smoke test (--help, --version, doctor --json, TUI in a PTY)"
  if [ "${PYRUN[0]}" = "uv" ]; then
    (cd "$REPO_ROOT" && "${PYRUN[@]}" python packaging/smoke_test.py "$DIST/systop")
  else
    (cd "$REPO_ROOT" && "$REPO_ROOT/build/.buildenv/bin/python" packaging/smoke_test.py "$DIST/systop")
  fi
}
