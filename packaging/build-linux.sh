#!/usr/bin/env bash
# systop — standalone onefile binary for Linux.
#
# RUNS ON LINUX. You CANNOT build a Linux binary from macOS or Windows:
# PyInstaller does not cross-compile (the bootloader + CPython library
# belong to the host OS). Hence the OS check at the start of the script.
#
# Usage:
#     ./packaging/build-linux.sh
#
# Output:
#     dist/systop                     (primary)
#     dist/systop-linux-x86_64        (labeled copy + .sha256)
#
# GLIBC NOTE: the binary will not run on systems with a glibc version
# OLDER than the build machine's (`GLIBC_2.XX not found`). Build on the
# oldest distro you support, or in a manylinux container. GitHub Actions'
# ubuntu-latest is currently the broadest-compatible option.

set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

[ "$(uname -s)" = "Linux" ] || die "this script is for Linux (current: $(uname -s)).
  For macOS: packaging/build-macos.sh
  For Windows: packaging/build-windows.ps1 (on Windows) or GitHub Actions."

prepare_env
build
label "linux"
smoke

log "Done. To distribute: put the file at /usr/local/bin/systop (chmod +x)."
printf '    sudo install -m 0755 %s /usr/local/bin/systop\n' "$ARTIFACT"
printf '    glibc: %s\n' "$(ldd --version 2>/dev/null | head -1 || echo 'undetermined')"
