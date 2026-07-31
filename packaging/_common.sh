#!/usr/bin/env bash
# Umumiy build mantiqi — build-linux.sh va build-macos.sh shuni source qiladi.
# O'zi mustaqil ishga tushirilmaydi.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="$REPO_ROOT/packaging/systop.spec"
DIST="$REPO_ROOT/dist"
WORK="$REPO_ROOT/build/pyinstaller"

# Sozlanadigan:
#   SYSTOP_SKIP_SMOKE=1   smoke testni tashlab ketish
#   SYSTOP_PY=python3.12  venv fallback uchun interpretator
: "${SYSTOP_SKIP_SMOKE:=0}"
: "${SYSTOP_PY:=python3}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mXATO: %s\033[0m\n' "$*" >&2; exit 1; }

# Muhitni tayyorlaydi va global PYRUN massivini o'rnatadi.
# uv bo'lsa — vaqtinchalik overlay (loyiha venv'iga tegmaydi).
# uv bo'lmasa — build/.buildenv ichida oddiy venv.
prepare_env() {
  if command -v uv >/dev/null 2>&1; then
    log "uv topildi — vaqtinchalik build muhiti (loyiha .venv'iga tegilmaydi)"
    PYRUN=(uv run --with pyinstaller)
    "${PYRUN[@]}" python -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
  else
    local venv="$REPO_ROOT/build/.buildenv"
    log "uv yo'q — venv fallback: $venv"
    command -v "$SYSTOP_PY" >/dev/null 2>&1 || die "$SYSTOP_PY topilmadi (SYSTOP_PY bilan ko'rsating)"
    [ -x "$venv/bin/python" ] || "$SYSTOP_PY" -m venv "$venv"
    "$venv/bin/python" -m pip install --upgrade --quiet pip wheel
    # Loyihaning o'zi + build-only qaramlik. `-e .` emas, `.` — muzlatilgan
    # binar editable-path'ga bog'lanib qolmasin.
    "$venv/bin/python" -m pip install --quiet "$REPO_ROOT" pyinstaller
    PYRUN=("$venv/bin/python" -m)
    "$venv/bin/python" -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
  fi
}

# PyInstaller'ni spec bilan ishga tushiradi.
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
  [ -f "$DIST/systop" ] || die "binar yaratilmadi: $DIST/systop"
}

# Nomlangan nusxa yaratadi: systop-<os>-<arch>
label() {
  local osname="$1"
  local arch
  arch="$(uname -m)"
  ARTIFACT="$DIST/systop-${osname}-${arch}"
  cp -f "$DIST/systop" "$ARTIFACT"
  chmod +x "$ARTIFACT" "$DIST/systop"
  log "Artefakt: $ARTIFACT"
  ls -lh "$ARTIFACT" | awk '{print "    hajm:", $5}'
  # Xesh faylida FAQAT bazaviy nom bo'lsin — aks holda `shasum -c` boshqa
  # mashinada absolyut yo'lni izlab yiqiladi (build mashinasidagi yo'l).
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
    log "smoke test o'tkazib yuborildi (SYSTOP_SKIP_SMOKE=1)"
    return 0
  fi
  log "Smoke test (--help, --version, doctor --json, TUI PTY'da)"
  if [ "${PYRUN[0]}" = "uv" ]; then
    (cd "$REPO_ROOT" && "${PYRUN[@]}" python packaging/smoke_test.py "$DIST/systop")
  else
    (cd "$REPO_ROOT" && "$REPO_ROOT/build/.buildenv/bin/python" packaging/smoke_test.py "$DIST/systop")
  fi
}
