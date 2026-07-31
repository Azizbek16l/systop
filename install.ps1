<#
.SYNOPSIS
    systop — a one-line installer for Windows (admin NOT REQUIRED).

.DESCRIPTION
    Downloads the binary from the latest release, verifies it via SHA256,
    places it in a user directory, and adds it to PATH.

    ADMIN IS NOT REQUIRED: the binary lands in `%LOCALAPPDATA%\Programs\systop`
    and PATH is changed only in USER scope. This is deliberate — installing
    a sysadmin tool should not require domain administrator rights.

.EXAMPLE
    # Simplest — from PowerShell:
    irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1 | iex

.EXAMPLE
    # From CMD:
    powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1 | iex"

.EXAMPLE
    # With an argument (`param` doesn't work through a pipe, hence the scriptblock):
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1))) -Version v0.10.0

.EXAMPLE
    # Uninstall:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1))) -Uninstall

.NOTES
    Can also be configured via environment variables (convenient in pipe mode):
        $env:SYSTOP_VERSION = 'v0.10.0'
        $env:SYSTOP_INSTALL_DIR = 'C:\Tools\systop'
#>
[CmdletBinding()]
param(
    # Exact release tag (e.g. 'v0.10.0'). If not given — the latest one.
    [string]$Version = $env:SYSTOP_VERSION,

    # Install directory. If not given, %LOCALAPPDATA%\Programs\systop.
    [string]$Dir = $env:SYSTOP_INSTALL_DIR,

    # Don't add to PATH (only place the file).
    [switch]$NoPath,

    # Remove what was installed.
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'Azizbek16l/systop'
$AppName = 'systop'
$ExeName = 'systop.exe'

# --- appearance -------------------------------------------------------------

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }
function Die($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# --- environment check -------------------------------------------------------

# PowerShell 5.1 (the Windows default) does not enable TLS 1.2 by default, and
# GitHub has rejected TLS 1.0/1.1 since 2018 -> "The request was aborted:
# Could not create SSL/TLS secure channel". This one line is what makes the
# whole installer work on older Windows 10 machines.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose "Could not set TLS 1.2 (not required on PowerShell 7+)"
}

function Get-TargetAsset {
    <#
      For Windows the release has ONLY an x86_64 artifact.

      ARM64 Windows (Surface Pro X, Dev Kit) can run x64 binaries via
      hardware emulation, so we don't reject it — but we don't stay SILENT
      either: we say it will run slower. A hidden degradation is wrong in
      a sysadmin tool.
    #>
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq 'ARM64') {
        Write-Warn2 "ARM64 detected — the x64 binary will run via emulation (slower)."
    } elseif ($arch -ne 'AMD64') {
        Die "Unsupported architecture: $arch (AMD64 or ARM64 required)"
    }
    return 'systop-windows-x86_64.exe'
}

function Get-BaseUrl {
    param([string]$Tag)
    if ([string]::IsNullOrWhiteSpace($Tag)) {
        # `releases/latest/download/...` — GitHub itself redirects to the
        # latest release. The API (`api.github.com`) is DELIBERATELY not
        # used: it's limited to 60 unauthenticated requests/hour, and 50
        # machines behind a corporate NAT exhaust that in no time.
        return "https://github.com/$Repo/releases/latest/download"
    }
    return "https://github.com/$Repo/releases/download/$Tag"
}

function Invoke-Download {
    param([string]$Url, [string]$OutFile)
    try {
        # -UseBasicParsing is REQUIRED on PowerShell 5.1: without it, it
        # invokes the Internet Explorer engine, and IE always crashes on
        # servers where it was never launched (Server Core).
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    } catch {
        Die "Download failed: $Url`n     $($_.Exception.Message)"
    }
}

# --- PATH management ---------------------------------------------------------

function Add-ToUserPath {
    param([string]$Directory)

    # NOTE: we read the USER PATH from the registry, NOT `$env:Path` (the
    # current process's). `$env:Path` is the Machine + User merge; writing
    # it back into User scope would copy system paths into the user profile
    # and then produce a duplicate the next time the Machine PATH changes.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) { $userPath = '' }

    $parts = $userPath -split ';' | Where-Object { $_ -ne '' }
    if ($parts -contains $Directory) {
        Write-Ok "already on PATH"
        return $false
    }

    $newPath = if ($userPath -eq '') { $Directory } else { "$userPath;$Directory" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')

    # Broadcast WM_SETTINGCHANGE so open Explorer/terminal windows learn
    # about the change. Without it, PATH only becomes visible after the
    # NEXT login, and the user thinks "it didn't install".
    try {
        if (-not ('Win32.NativeMethods' -as [type])) {
            Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
        }
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x1A
        $SMTO_ABORTIFHUNG = 0x0002
        $result = [UIntPtr]::Zero
        [void][Win32.NativeMethods]::SendMessageTimeout(
            $HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, 'Environment',
            $SMTO_ABORTIFHUNG, 5000, [ref]$result)
    } catch {
        Write-Verbose "WM_SETTINGCHANGE not sent: $($_.Exception.Message)"
    }
    return $true
}

function Remove-FromUserPath {
    param([string]$Directory)
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrEmpty($userPath)) { return }
    $parts = $userPath -split ';' | Where-Object { $_ -ne '' -and $_ -ne $Directory }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}

# --- main flow -----------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
}
$targetExe = Join-Path $Dir $ExeName

if ($Uninstall) {
    Write-Step "removing systop"
    if (Test-Path $targetExe) {
        Remove-Item $targetExe -Force
        Write-Ok "removed: $targetExe"
    } else {
        Write-Warn2 "binary not found: $targetExe"
    }
    Remove-FromUserPath $Dir
    if ((Test-Path $Dir) -and -not (Get-ChildItem $Dir -Force)) {
        Remove-Item $Dir -Force
    }
    Write-Ok "PATH cleaned up. Open a new terminal."
    exit 0
}

$asset = Get-TargetAsset
$base = Get-BaseUrl -Tag $Version
$verLabel = if ([string]::IsNullOrWhiteSpace($Version)) { 'latest' } else { $Version }

Write-Step "downloading systop ($verLabel, $asset)"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("systop-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $tmpExe = Join-Path $tmp $ExeName
    $tmpSums = Join-Path $tmp 'SHA256SUMS.txt'

    Invoke-Download -Url "$base/$asset" -OutFile $tmpExe
    $size = (Get-Item $tmpExe).Length
    Write-Ok ("downloaded: {0:N0} bytes" -f $size)

    # --- SHA256 verification -------------------------------------------------
    # Skipping verification is the most common installer flaw. A half-
    # downloaded or tampered file gets installed SILENTLY.
    Write-Step "verifying SHA256"
    $verified = $false
    try {
        Invoke-Download -Url "$base/SHA256SUMS.txt" -OutFile $tmpSums
        $actual = (Get-FileHash -Path $tmpExe -Algorithm SHA256).Hash.ToLower()
        $expected = $null
        foreach ($line in Get-Content $tmpSums) {
            # Format: "<hash>  <file name>"
            $f = ($line -split '\s+') | Where-Object { $_ -ne '' }
            if ($f.Count -ge 2 -and $f[-1] -like "*$asset") { $expected = $f[0].ToLower(); break }
        }
        if ($null -eq $expected) {
            Write-Warn2 "SHA256SUMS.txt has no entry for '$asset' — cannot verify"
        } elseif ($actual -ne $expected) {
            Die "SHA256 MISMATCH. Expected: $expected`n     Got:      $actual`n     File NOT installed."
        } else {
            Write-Ok "sha256 matches: $($actual.Substring(0,16))..."
            $verified = $true
        }
    } catch {
        Write-Warn2 "SHA256SUMS.txt could not be fetched — continuing without verification"
    }
    if (-not $verified) {
        Write-Warn2 "WARNING: the download was not verified."
    }

    # --- does it work? -------------------------------------------------------
    # We test it BEFORE adding it to PATH: better to stop right here than to
    # install a broken binary and then go hunting for "why doesn't it work".
    Write-Step "verifying the binary"
    try {
        $out = & $tmpExe --version 2>&1
        if ($LASTEXITCODE -ne 0) { throw "exit=$LASTEXITCODE" }
        Write-Ok "$out"
    } catch {
        Die "Binary failed to run: $($_.Exception.Message)"
    }

    # --- installing ----------------------------------------------------------
    Write-Step "installing: $Dir"
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    try {
        Move-Item -Path $tmpExe -Destination $targetExe -Force
    } catch {
        # Can't replace a running systop.exe (file in use).
        Die "Could not write the file — systop may be running.`n     Close all systop windows and try again."
    }
    Write-Ok "$targetExe"

    if (-not $NoPath) {
        Write-Step "configuring PATH (user scope only, no admin required)"
        $added = Add-ToUserPath -Directory $Dir
        if ($added) { Write-Ok "added: $Dir" }
        # Also take effect immediately in the current session.
        if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }
    }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host '  systop doctor        automatically find network problems'
Write-Host '  systop wifi          Wi-Fi signal/SNR/channel'
Write-Host '  systop lan -6        LAN inventory (IPv4 + IPv6)'
Write-Host '  systop               full TUI dashboard'
Write-Host ''
Write-Host 'Note: the PATH change takes effect in a NEW terminal window.' -ForegroundColor Yellow
