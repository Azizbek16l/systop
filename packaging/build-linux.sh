#!/usr/bin/env bash
# systop — Linux uchun standalone onefile binar.
#
# LINUX'DA ISHGA TUSHIRILADI. macOS yoki Windows'dan Linux binari yasab
# BO'LMAYDI: PyInstaller cross-compile qilmaydi (bootloader + CPython
# kutubxonasi host OS'niki). Shuning uchun skript boshida OS tekshiriladi.
#
# Ishlatish:
#     ./packaging/build-linux.sh
#
# Natija:
#     dist/systop                     (asosiy)
#     dist/systop-linux-x86_64        (nomlangan nusxa + .sha256)
#
# GLIBC ESLATMA: binar yig'ilgan mashinaning glibc versiyasidan PASTROQ
# tizimlarda ishlamaydi (`GLIBC_2.XX not found`). Eng eski qo'llab-quvvatlanadigan
# distroda yoki manylinux konteynerida yig'ing. GitHub Actions ubuntu-latest
# hozircha eng keng mos variant.

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

[ "$(uname -s)" = "Linux" ] || die "bu skript Linux uchun (hozir: $(uname -s)).
  macOS uchun: packaging/build-macos.sh
  Windows uchun: packaging/build-windows.ps1 (Windows'da) yoki GitHub Actions."

prepare_env
build
label "linux"
smoke

log "Tayyor. Tarqatish: faylni /usr/local/bin/systop ga qo'ying (chmod +x)."
printf '    sudo install -m 0755 %s /usr/local/bin/systop\n' "$ARTIFACT"
printf '    glibc: %s\n' "$(ldd --version 2>/dev/null | head -1 || echo 'aniqlanmadi')"
