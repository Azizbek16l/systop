<#
.SYNOPSIS
    systop — Windows uchun standalone onefile .exe.

.DESCRIPTION
    WINDOWS'DA ISHGA TUSHIRILADI. macOS yoki Linux'dan Windows .exe yasab
    BO'LMAYDI — PyInstaller cross-compile qilmaydi: u host OS'ning CPython
    kutubxonasini va host uchun kompilyatsiya qilingan bootloader'ni ishlatadi.
    Agar Windows mashina bo'lmasa, .github/workflows/release.yml dagi
    windows-latest matritsasi yagona to'g'ri yo'l.

    (Wine orqali urinish "ishlaydigandek" ko'rinadi, lekin natija ishonchsiz:
     psutil/icmplib kabi C-kengaytmalar Wine ostida noto'g'ri bog'lanadi. Biz
     buni ATAYIN qo'shmadik — sinadigan artefakt yo'qdan battar.)

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
function Die($msg)  { Write-Host "`nXATO: $msg" -ForegroundColor Red; exit 1 }

# OS tekshiruvi. DIQQAT: $IsWindows faqat PowerShell 6+ da mavjud. Windows
# PowerShell 5.1 (ko'p Windows'da default) da u aniqlanmagan va StrictMode
# ostida unga murojaat XATO beradi — shuning uchun avval versiyani tekshiramiz.
$onWindows = $true
if ($PSVersionTable.PSVersion.Major -ge 6) { $onWindows = $IsWindows }
if (-not $onWindows) {
    Die "bu skript Windows uchun. Linux: packaging/build-linux.sh, macOS: packaging/build-macos.sh"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Spec     = Join-Path $RepoRoot "packaging\systop.spec"
$Dist     = Join-Path $RepoRoot "dist"
$Work     = Join-Path $RepoRoot "build\pyinstaller"
$Exe      = Join-Path $Dist "systop.exe"

if (-not (Test-Path $Spec)) { Die "spec topilmadi: $Spec" }

Push-Location $RepoRoot
try {
    # --- Muhit: uv bo'lsa vaqtinchalik overlay, bo'lmasa venv fallback --------
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        Log "uv topildi — vaqtinchalik build muhiti (loyiha .venv'iga tegilmaydi)"
        $UseUv = $true
        & uv run --with pyinstaller python -c "import PyInstaller,systop; print('pyinstaller', PyInstaller.__version__)"
        if ($LASTEXITCODE -ne 0) { Die "uv muhitini tayyorlab bo'lmadi" }
    } else {
        $UseUv = $false
        $VenvDir = Join-Path $RepoRoot "build\.buildenv"
        $VenvPy  = Join-Path $VenvDir "Scripts\python.exe"
        Log "uv yo'q — venv fallback: $VenvDir"
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
        if (-not $py) { Die "python topilmadi (python.org yoki winget install Python.Python.3.12)" }
        if (-not (Test-Path $VenvPy)) { & $py.Source -m venv $VenvDir }
        & $VenvPy -m pip install --upgrade --quiet pip wheel
        # `-e .` emas, `.` — muzlatilgan .exe editable-path'ga bog'lanmasin.
        & $VenvPy -m pip install --quiet "$RepoRoot" pyinstaller
        if ($LASTEXITCODE -ne 0) { Die "pip install yiqildi" }
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
    if ($LASTEXITCODE -ne 0) { Die "PyInstaller yiqildi" }
    if (-not (Test-Path $Exe)) { Die ".exe yaratilmadi: $Exe" }

    # --- Nomlangan nusxa + SHA256 --------------------------------------------
    $arch = $env:PROCESSOR_ARCHITECTURE.ToLower()
    if ($arch -eq "amd64") { $arch = "x86_64" }
    $Artifact = Join-Path $Dist "systop-windows-$arch.exe"
    Copy-Item -Force $Exe $Artifact
    $size = (Get-Item $Artifact).Length
    Log "Artefakt: $Artifact"
    Write-Host ("    hajm: {0:N0} bayt ({1:N1} MiB)" -f $size, ($size / 1MB))
    $hash = (Get-FileHash -Algorithm SHA256 $Artifact).Hash.ToLower()
    "$hash  $(Split-Path -Leaf $Artifact)" | Set-Content "$Artifact.sha256"
    Write-Host "    sha256: $hash"

    # --- Smoke test -----------------------------------------------------------
    if (-not $SkipSmoke) {
        Log "Smoke test (--help, --version, doctor --json, bundle TOC)"
        # Eslatma: TUI'ni PTY'da ochish testi Windows'da o'tkazib yuboriladi
        # (POSIX pty yo'q), lekin bundle TOC tekshiruvi styles.tcss borligini
        # baribir kafolatlaydi — TUI yiqilishining #1 sababi shu.
        if ($UseUv) {
            & uv run --with pyinstaller python packaging\smoke_test.py $Exe
        } else {
            & $VenvPy packaging\smoke_test.py $Exe
        }
        if ($LASTEXITCODE -ne 0) { Die "smoke test yiqildi" }
    }

    Log "Tayyor. Tarqatish variantlari:"
    Write-Host "    1) Faylni PATH'dagi papkaga qo'ying, masalan C:\Windows\System32 emas, balki:"
    Write-Host "       mkdir `$env:LOCALAPPDATA\Programs\systop; copy $Artifact `$env:LOCALAPPDATA\Programs\systop\systop.exe"
    Write-Host "       va o'sha papkani PATH'ga qo'shing."
    Write-Host "    2) scoop / winget manifesti (README.md ga qarang)."
    Write-Host ""
    Write-Host "    ESLATMA: .exe imzolanmagan -> SmartScreen 'Windows protected your PC'"
    Write-Host "    ogohlantirishini beradi. Yechim: Authenticode kod-imzolash sertifikati"
    Write-Host "    (EV bo'lsa reputatsiya darhol), yoki foydalanuvchi 'More info -> Run anyway'."
}
finally {
    Pop-Location
}
