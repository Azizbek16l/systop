#!/usr/bin/env bash
# systop — macOS uchun standalone onefile binar.
#
# MACOS'DA ISHGA TUSHIRILADI. Yig'ilgan binar HOST arxitekturasiga tegishli:
# Apple Silicon'da arm64, Intel Mac'da x86_64. Universal2 uchun universal2
# CPython kerak (python.org o'rnatuvchisi) — pastdagi izohga qarang.
#
# Ishlatish:
#     ./packaging/build-macos.sh
#
# Natija:
#     dist/systop                     (asosiy)
#     dist/systop-macos-arm64         (nomlangan nusxa + .sha256)
#
# IMZOLASH / GATEKEEPER: binar ad-hoc imzolangan. Boshqa Mac'ga yuborilsa
# quarantine bayrog'i tufayli "damaged / cannot be opened" chiqadi. Yechim:
#   - foydalanuvchi tomonida:  xattr -d com.apple.quarantine /usr/local/bin/systop
#   - to'g'ri yechim:          Apple Developer ID bilan codesign + notarytool
# Buni avtomatlashtirish uchun spec'dagi codesign_identity ni to'ldiring.

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

[ "$(uname -s)" = "Darwin" ] || die "bu skript macOS uchun (hozir: $(uname -s)).
  Linux uchun: packaging/build-linux.sh
  Windows uchun: packaging/build-windows.ps1 (Windows'da) yoki GitHub Actions."

prepare_env
build
label "macos"
smoke

log "Tayyor. Tarqatish:"
printf '    sudo install -m 0755 %s /usr/local/bin/systop\n' "$ARTIFACT"
printf '    (boshqa Mac'"'"'da) xattr -d com.apple.quarantine /usr/local/bin/systop\n'
printf '    codesign holati: %s\n' "$(codesign -dv "$ARTIFACT" 2>&1 | grep -i 'signature' | head -1 || echo 'ad-hoc / imzosiz')"
