#!/usr/bin/env bash
# systop — standalone onefile binary for macOS.
#
# RUNS ON MACOS. The built binary belongs to the HOST architecture:
# arm64 on Apple Silicon, x86_64 on Intel Mac. Universal2 needs a
# universal2 CPython (the python.org installer) — see the note below.
#
# Usage:
#     ./packaging/build-macos.sh
#
# Output:
#     dist/systop                     (primary)
#     dist/systop-macos-arm64         (labeled copy + .sha256)
#
# SIGNING / GATEKEEPER: the binary is ad-hoc signed. Sent to another Mac,
# the quarantine flag makes it say "damaged / cannot be opened". Fix:
#   - on the user's side:  xattr -d com.apple.quarantine /usr/local/bin/systop
#   - the proper fix:      codesign + notarytool with an Apple Developer ID
# To automate this, fill in codesign_identity in the spec file.

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

[ "$(uname -s)" = "Darwin" ] || die "this script is for macOS (current: $(uname -s)).
  For Linux: packaging/build-linux.sh
  For Windows: packaging/build-windows.ps1 (on Windows) or GitHub Actions."

prepare_env
build
label "macos"
smoke

log "Done. To distribute:"
printf '    sudo install -m 0755 %s /usr/local/bin/systop\n' "$ARTIFACT"
printf '    (on another Mac) xattr -d com.apple.quarantine /usr/local/bin/systop\n'
printf '    codesign status: %s\n' "$(codesign -dv "$ARTIFACT" 2>&1 | grep -i 'signature' | head -1 || echo 'ad-hoc / unsigned')"
