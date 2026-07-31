#!/bin/sh
# systop — a one-line installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/Azizbek16l/systop/master/install.sh | sh
#
# Configuration (via environment variables — the only way in pipe mode):
#   SYSTOP_VERSION=v0.10.0   exact release tag (default: latest)
#   SYSTOP_INSTALL_DIR=...   install directory (default: logic below)
#   SYSTOP_NO_SUDO=1         don't use sudo, install to ~/.local/bin
#
# WARNING — which SIDE OF THE PIPE you put the variable on matters:
#     SYSTOP_INSTALL_DIR=/opt/bin curl -fsSL ... | sh      # WRONG
#     curl -fsSL ... | SYSTOP_INSTALL_DIR=/opt/bin sh      # correct
# In the first form the variable is passed to `curl`; `sh` never sees it
# at all, and the script silently installs to the default directory.
#
# Uninstall:
#   curl -fsSL .../install.sh | sh -s -- --uninstall
#
# Written for POSIX `sh` (NOT bash): on Debian/Ubuntu `sh` = dash,
# on Alpine it's busybox ash. `[[ ]]`, arrays and `local` are DELIBERATELY not used.

set -eu

REPO="Azizbek16l/systop"
BIN_NAME="systop"

# --- appearance -------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_STEP=$(printf '\033[36m'); C_OK=$(printf '\033[32m')
    C_WARN=$(printf '\033[33m'); C_ERR=$(printf '\033[31m'); C_OFF=$(printf '\033[0m')
else
    C_STEP=''; C_OK=''; C_WARN=''; C_ERR=''; C_OFF=''
fi

step() { printf '%s==> %s%s\n' "$C_STEP" "$1" "$C_OFF"; }
ok()   { printf '%s    %s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn() { printf '%s    %s%s\n' "$C_WARN" "$1" "$C_OFF"; }
die()  { printf '%sERROR: %s%s\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }

# --- arguments ---------------------------------------------------------------

UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=1 ;;
        --version=*) SYSTOP_VERSION="${arg#--version=}" ;;
        --dir=*)     SYSTOP_INSTALL_DIR="${arg#--dir=}" ;;
        --help|-h)
            sed -n '2,20p' "$0" 2>/dev/null || printf 'Help is only available when run from the file.\n'
            exit 0 ;;
        *) die "unknown argument: $arg" ;;
    esac
done

VERSION="${SYSTOP_VERSION:-}"

# --- platform detection ------------------------------------------------------

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64|amd64) ASSET="systop-linux-x86_64" ;;
            aarch64|arm64)
                die "No prebuilt binary for Linux ARM64.
     Build from source:  git clone https://github.com/$REPO && cd systop && ./packaging/build-linux.sh" ;;
            *) die "unsupported architecture: $ARCH" ;;
        esac ;;
    Darwin)
        case "$ARCH" in
            arm64) ASSET="systop-macos-arm64" ;;
            x86_64)
                # No prebuilt binary for Intel Mac: GitHub retired the
                # `macos-13` runner and PyInstaller doesn't cross-compile.
                # Better to state the reason than to 404 and say "download
                # failed."
                die "No prebuilt binary for Intel Mac (the CI runner was retired).
     Build from source:  git clone https://github.com/$REPO && cd systop && ./packaging/build-macos.sh" ;;
            *) die "unsupported architecture: $ARCH" ;;
        esac ;;
    *) die "unsupported OS: $OS (use install.ps1 for Windows)" ;;
esac

# --- install directory --------------------------------------------------------
#
# Order: user-supplied > writable /usr/local/bin >
# /usr/local/bin with sudo > ~/.local/bin.
#
# sudo is NOT FORCED: a script reading from a pipe (`curl | sh`) holds
# stdin, so a sudo password prompt would hang the terminal. Instead we
# check in advance.

NEED_SUDO=0
if [ -n "${SYSTOP_INSTALL_DIR:-}" ]; then
    DEST="$SYSTOP_INSTALL_DIR"
elif [ "${SYSTOP_NO_SUDO:-0}" = "1" ]; then
    DEST="$HOME/.local/bin"
elif [ -w /usr/local/bin ] 2>/dev/null; then
    DEST="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    DEST="/usr/local/bin"; NEED_SUDO=1
else
    DEST="$HOME/.local/bin"
fi

TARGET="$DEST/$BIN_NAME"

# --- uninstall ----------------------------------------------------------------

if [ "$UNINSTALL" = "1" ]; then
    step "removing systop"
    for d in "$DEST" /usr/local/bin "$HOME/.local/bin"; do
        if [ -f "$d/$BIN_NAME" ]; then
            if [ -w "$d" ]; then rm -f "$d/$BIN_NAME"; else sudo rm -f "$d/$BIN_NAME"; fi
            ok "removed: $d/$BIN_NAME"
        fi
    done
    exit 0
fi

# --- download ------------------------------------------------------------------
#
# `releases/latest/download/...` — GitHub itself redirects to the latest
# release. `api.github.com` is DELIBERATELY not used: unauthenticated it's
# limited to 60 requests/hour, and a handful of machines behind a
# corporate NAT exhaust that in no time.
if [ -z "$VERSION" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
    VER_LABEL="latest"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
    VER_LABEL="$VERSION"
fi

if command -v curl >/dev/null 2>&1; then
    DL='curl -fsSL --retry 3 -o'
elif command -v wget >/dev/null 2>&1; then
    DL='wget -q -O'
else
    die "neither curl nor wget found"
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t systop)
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT INT TERM

step "downloading systop ($VER_LABEL, $ASSET)"
# shellcheck disable=SC2086
$DL "$TMP/$BIN_NAME" "$BASE/$ASSET" || die "download failed: $BASE/$ASSET"
SIZE=$(wc -c < "$TMP/$BIN_NAME" | tr -d ' ')
[ "$SIZE" -gt 1000000 ] || die "downloaded file is too small ($SIZE bytes) — release not found?"
ok "downloaded: $SIZE bytes"

# --- SHA256 verification -------------------------------------------------------
# Skipping verification is the most common installer flaw: a half-
# downloaded or tampered file gets installed SILENTLY.

step "verifying SHA256"
if command -v sha256sum >/dev/null 2>&1; then
    HASH_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    HASH_CMD="shasum -a 256"
else
    HASH_CMD=""
fi

VERIFIED=0
if [ -n "$HASH_CMD" ]; then
    # shellcheck disable=SC2086
    if $DL "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" 2>/dev/null; then
        EXPECTED=$(grep -E "[[:space:]]\*?$ASSET\$" "$TMP/SHA256SUMS.txt" 2>/dev/null | awk '{print $1}' | head -1)
        ACTUAL=$($HASH_CMD "$TMP/$BIN_NAME" | awk '{print $1}')
        if [ -z "$EXPECTED" ]; then
            warn "SHA256SUMS.txt has no entry for '$ASSET' — cannot verify"
        elif [ "$EXPECTED" != "$ACTUAL" ]; then
            die "SHA256 MISMATCH.
     Expected: $EXPECTED
     Got:      $ACTUAL
     File NOT installed."
        else
            ok "sha256 matches: $(echo "$ACTUAL" | cut -c1-16)..."
            VERIFIED=1
        fi
    else
        warn "SHA256SUMS.txt could not be fetched — continuing without verification"
    fi
else
    warn "sha256sum/shasum not found — cannot verify"
fi
[ "$VERIFIED" = "1" ] || warn "WARNING: the download was not verified."

chmod +x "$TMP/$BIN_NAME"

# macOS: the downloaded file gets a quarantine flag and Gatekeeper says
# "damaged / cannot be opened". The binary is ad-hoc signed (not an Apple
# Developer ID), so we strip the flag.
if [ "$OS" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$TMP/$BIN_NAME" 2>/dev/null || true
fi

# --- does it work? ---------------------------------------------------------
# We test it BEFORE putting it on PATH. The most common failure on
# Linux is a glibc mismatch; it needs to be reported with the specific
# cause, not "systop doesn't work".

step "verifying the binary"
if ! VER_OUT=$("$TMP/$BIN_NAME" --version 2>&1); then
    case "$VER_OUT" in
        *GLIBC*|*glibc*)
            die "This binary requires a NEWER glibc than what's on your system.
     $VER_OUT
     You have: $(ldd --version 2>/dev/null | head -1)
     Fix: build from source —
       git clone https://github.com/$REPO && cd systop && ./packaging/build-linux.sh" ;;
        *) die "binary failed to run: $VER_OUT" ;;
    esac
fi
ok "$VER_OUT"

# --- installing --------------------------------------------------------------

step "installing: $TARGET"
if [ "$NEED_SUDO" = "1" ]; then
    warn "requesting sudo to write to /usr/local/bin"
    sudo install -m 0755 "$TMP/$BIN_NAME" "$TARGET" || die "install failed"
else
    mkdir -p "$DEST"
    install -m 0755 "$TMP/$BIN_NAME" "$TARGET" 2>/dev/null \
        || { cp "$TMP/$BIN_NAME" "$TARGET" && chmod 0755 "$TARGET"; } \
        || die "install failed: $TARGET"
fi
ok "$TARGET"

# --- PATH ------------------------------------------------------------------
# A POSIX shell cannot change another process's PATH, and silently writing
# to the user's rc file is rude. So we give an explicit instruction instead.

case ":$PATH:" in
    *":$DEST:"*) ;;
    *)
        printf '\n%sPATH setup needed%s — %s is not yet on PATH:\n' "$C_WARN" "$C_OFF" "$DEST"
        SHELL_NAME=$(basename "${SHELL:-sh}")
        case "$SHELL_NAME" in
            zsh)  RC="$HOME/.zshrc" ;;
            bash) RC="$HOME/.bashrc" ;;
            fish) RC="$HOME/.config/fish/config.fish" ;;
            *)    RC="$HOME/.profile" ;;
        esac
        if [ "$SHELL_NAME" = "fish" ]; then
            printf '\n  echo \x27fish_add_path %s\x27 >> %s\n' "$DEST" "$RC"
        else
            printf '\n  echo \x27export PATH="%s:$PATH"\x27 >> %s\n' "$DEST" "$RC"
        fi
        printf '  exec %s\n' "$SHELL_NAME"
        ;;
esac

printf '\n%sDone.%s\n' "$C_OK" "$C_OFF"
printf '  systop doctor        automatically find network problems\n'
printf '  systop wifi          Wi-Fi signal/SNR/channel\n'
printf '  systop lan -6        LAN inventory (IPv4 + IPv6)\n'
printf '  systop               full TUI dashboard\n'
