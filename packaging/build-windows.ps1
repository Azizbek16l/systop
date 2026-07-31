<#
.SYNOPSIS
    systop — standalone onefile .exe for Windows.

.DESCRIPTION
    RUNS ON WINDOWS. You CANNOT build a Windows .exe from macOS or Linux —
    PyInstaller does not cross-compile: it uses the host OS's CPython
    library and a bootloader compiled for the host. If no Windows machine
    is available, the windows-latest matrix in .github/workflows/release.yml
    is the only correct path.

    (Trying it via Wine "looks like it works," but the result is unreliable:
     C extensions such as psutil/icmplib link incorrectly under Wine. We
     DELIBERATELY did not add this — an untestable artifact is worse than none.)

.EXAMPLE
    .\packaging\build-windows.ps1

.OUTPUTS
    dist\systop.exe
    dist\systop-windows-<arch>.exe   (+ .sha256)
#>

[CmdletBinding()]
param(
    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$LASTEXITCODE = 0

function Log($msg)  { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Die($msg)  { Write-Host "`nERROR: $msg" -ForegroundColor Red; exit 1 }

# OS check. NOTE: $IsWindows only exists on PowerShell 6+. On Windows
# PowerShell 5.1 (the default on most Windows machines) it is undefined, and
# referencing it under StrictMode throws an ERROR — hence checking the
# version first.
$onWindows = $true
if ($PSVersionTable.PSVersion.Major -ge 6) { $onWindows = $IsWindows }
if (-not $onWindows) {
    Die "this script is for Windows. Linux: packaging/build-linux.sh, macOS: packaging/build-macos.sh"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Spec     = Join-Path $RepoRoot "packaging\systop.spec"
$Dist     = Join-Path $RepoRoot "dist"
$Work     = Join-Path $RepoRoot "build\pyinstaller"
$Exe      = Join-Path $Dist "systop.exe"

if (-not (Test-Path $Spec)) { Die "spec not found: $Spec" }

Push-Location $RepoRoot
try {
    # --- Environment: throwaway overlay if uv is present, venv fallback otherwise --------
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        Log "uv found — using a throwaway build environment (leaves the project .venv untouched)"
        $UseUv = $true
        & uv run --with pyinstaller python -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
        if ($LASTEXITCODE -ne 0) { Die "could not prepare the uv environment" }
    } else {
        $UseUv = $false
        $VenvDir = Join-Path $RepoRoot "build\.buildenv"
        $VenvPy  = Join-Path $VenvDir "Scripts\python.exe"
        Log "uv not found — venv fallback: $VenvDir"
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
        if (-not $py) { Die "python not found (python.org or winget install Python.Python.3.12)" }
        if (-not (Test-Path $VenvPy)) { & $py.Source -m venv $VenvDir }
        & $VenvPy -m pip install --upgrade --quiet pip wheel
        # `.` not `-e .` — a frozen .exe must not end up bound to the editable path.
        & $VenvPy -m pip install --quiet "$RepoRoot" pyinstaller
        if ($LASTEXITCODE -ne 0) { Die "pip install failed" }
        & $VenvPy -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
    }

    # --- Build ----------------------------------------------------------------
    Log "PyInstaller (onefile, console=True) — $Spec"
    if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
    if ($UseUv) {
        & uv run --with pyinstaller pyinstaller --noconfirm --clean `
            --distpath $Dist --workpath $Work $Spec
    } else {
        & $VenvPy -m PyInstaller --noconfirm --clean `
            --distpath $Dist --workpath $Work $Spec
    }
    if ($LASTEXITCODE -ne 0) { Die "PyInstaller failed" }
    if (-not (Test-Path $Exe)) { Die ".exe was not created: $Exe" }

    # --- Labeled copy + SHA256 --------------------------------------------
    $arch = $env:PROCESSOR_ARCHITECTURE.ToLower()
    if ($arch -eq "amd64") { $arch = "x86_64" }
    $Artifact = Join-Path $Dist "systop-windows-$arch.exe"
    Copy-Item -Force $Exe $Artifact
    $size = (Get-Item $Artifact).Length
    Log "Artifact: $Artifact"
    Write-Host ("    size: {0:N0} bytes ({1:N1} MiB)" -f $size, ($size / 1MB))
    $hash = (Get-FileHash -Algorithm SHA256 $Artifact).Hash.ToLower()
    "$hash  $(Split-Path -Leaf $Artifact)" | Set-Content "$Artifact.sha256"
    Write-Host "    sha256: $hash"

    # --- Smoke test -----------------------------------------------------------
    if (-not $SkipSmoke) {
        Log "Smoke test (--help, --version, doctor --json, bundle TOC)"
        # Note: the test that opens the TUI in a PTY is skipped on Windows
        # (no POSIX pty), but the bundle TOC check still guarantees
        # styles.tcss is present — the #1 cause of the TUI failing to start.
        if ($UseUv) {
            & uv run --with pyinstaller python packaging\smoke_test.py $Exe
        } else {
            & $VenvPy packaging\smoke_test.py $Exe
        }
        if ($LASTEXITCODE -ne 0) { Die "smoke test failed" }
    }

    Log "Done. Distribution options:"
    Write-Host "    1) Put the file in a folder on PATH — for example, not C:\Windows\System32, but:"
    Write-Host "       mkdir `$env:LOCALAPPDATA\Programs\systop; copy $Artifact `$env:LOCALAPPDATA\Programs\systop\systop.exe"
    Write-Host "       and add that folder to PATH."
    Write-Host "    2) A scoop / winget manifest (see README.md)."
    Write-Host ""
    Write-Host "    NOTE: the .exe is unsigned -> SmartScreen shows a 'Windows protected your PC'"
    Write-Host "    warning. Fix: an Authenticode code-signing certificate"
    Write-Host "    (with EV, reputation is immediate), or the user clicks 'More info -> Run anyway'."
}
finally {
    Pop-Location
}
