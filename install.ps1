<#
.SYNOPSIS
    systop — Windows uchun bir qatorlik o'rnatgich (admin KERAK EMAS).

.DESCRIPTION
    Eng so'nggi relisedan binarni yuklab oladi, SHA256 bo'yicha tekshiradi,
    foydalanuvchi katalogiga qo'yadi va PATH'ga qo'shadi.

    ADMIN TALAB QILINMAYDI: binar `%LOCALAPPDATA%\Programs\systop` ga
    tushadi va PATH faqat FOYDALANUVCHI doirasida o'zgaradi. Bu ataylab —
    sysadmin tooli o'rnatish uchun domen administratori huquqini talab
    qilmasligi kerak.

.EXAMPLE
    # Eng oddiy — PowerShell'da:
    irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1 | iex

.EXAMPLE
    # CMD'dan:
    powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1 | iex"

.EXAMPLE
    # Argument bilan (quvur orqali `param` ishlamaydi, shuning uchun scriptblock):
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1))) -Version v0.10.0

.EXAMPLE
    # O'chirish:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Azizbek16l/systop/master/install.ps1))) -Uninstall

.NOTES
    Muhit o'zgaruvchilari bilan ham boshqariladi (quvur rejimida qulay):
        $env:SYSTOP_VERSION = 'v0.10.0'
        $env:SYSTOP_INSTALL_DIR = 'C:\Tools\systop'
#>
[CmdletBinding()]
param(
    # Aniq relise tegi (masalan 'v0.10.0'). Berilmasa — eng so'nggisi.
    [string]$Version = $env:SYSTOP_VERSION,

    # O'rnatish katalogi. Berilmasa %LOCALAPPDATA%\Programs\systop.
    [string]$Dir = $env:SYSTOP_INSTALL_DIR,

    # PATH'ga qo'shmaslik (faqat faylni qo'yish).
    [switch]$NoPath,

    # O'rnatilganini olib tashlash.
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'Azizbek16l/systop'
$AppName = 'systop'
$ExeName = 'systop.exe'

# --- ko'rinish -------------------------------------------------------------

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }
function Die($msg) { Write-Host "XATO: $msg" -ForegroundColor Red; exit 1 }

# --- muhit tekshiruvi ------------------------------------------------------

# PowerShell 5.1 (Windows'dagi standart) TLS 1.2 ni default yoqmaydi va
# GitHub 2018-dan beri TLS 1.0/1.1 ni rad etadi -> "The request was aborted:
# Could not create SSL/TLS secure channel". Bu bitta qator butun o'rnatishni
# eski Windows 10 mashinalarda ishlashga majbur qiladi.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose "TLS 1.2 o'rnatib bo'lmadi (PowerShell 7+ da shart emas)"
}

function Get-TargetAsset {
    <#
      Windows uchun relise'da FAQAT x86_64 artefakti bor.

      ARM64 Windows (Surface Pro X, Dev Kit) x64 binarlarni apparat
      emulyatsiyasi bilan ishlata oladi, shuning uchun uni rad etmaymiz —
      lekin JIM ham o'tmaymiz: sekinroq ishlashini aytamiz. Yashirin
      degradatsiya sysadmin toolida noto'g'ri.
    #>
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq 'ARM64') {
        Write-Warn2 "ARM64 aniqlandi — x64 binar emulyatsiya orqali ishlaydi (sekinroq)."
    } elseif ($arch -ne 'AMD64') {
        Die "Qo'llab-quvvatlanmaydigan arxitektura: $arch (AMD64 yoki ARM64 kerak)"
    }
    return 'systop-windows-x86_64.exe'
}

function Get-BaseUrl {
    param([string]$Tag)
    if ([string]::IsNullOrWhiteSpace($Tag)) {
        # `releases/latest/download/...` GitHub'ning o'zi eng so'nggi relisega
        # yo'naltiradi. API (`api.github.com`) ATAYIN ishlatilmaydi: u
        # autentifikatsiyasiz soatiga 60 so'rov bilan cheklangan va korporativ
        # NAT ortidagi 50 mashina uni bir zumda tugatadi.
        return "https://github.com/$Repo/releases/latest/download"
    }
    return "https://github.com/$Repo/releases/download/$Tag"
}

function Invoke-Download {
    param([string]$Url, [string]$OutFile)
    try {
        # -UseBasicParsing PowerShell 5.1 da SHART: usiz Internet Explorer
        # dvigatelini chaqiradi va IE hech qachon ishga tushirilmagan
        # serverlarda (Server Core) yiqiladi.
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    } catch {
        Die "Yuklab bo'lmadi: $Url`n     $($_.Exception.Message)"
    }
}

# --- PATH boshqaruvi -------------------------------------------------------

function Add-ToUserPath {
    param([string]$Directory)

    # DIQQAT: `$env:Path` (joriy jarayonniki) EMAS, ro'yxatdagi FOYDALANUVCHI
    # PATH'i o'qiladi. `$env:Path` — Machine + User birlashmasi; uni User
    # doirasiga qaytarib yozish tizim yo'llarini foydalanuvchi profiliga
    # ko'chirib, keyin Machine PATH o'zgarganda ikki nusxa yasaydi.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) { $userPath = '' }

    $parts = $userPath -split ';' | Where-Object { $_ -ne '' }
    if ($parts -contains $Directory) {
        Write-Ok "PATH'da allaqachon bor"
        return $false
    }

    $newPath = if ($userPath -eq '') { $Directory } else { "$userPath;$Directory" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')

    # Ochiq turgan Explorer/terminal oynalari o'zgarishni bilishi uchun
    # WM_SETTINGCHANGE broadcast qilamiz. Usiz PATH faqat KEYINGI
    # login'dan keyin ko'rinadi va odam "o'rnatilmadi" deb o'ylaydi.
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
        Write-Verbose "WM_SETTINGCHANGE yuborilmadi: $($_.Exception.Message)"
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

# --- asosiy oqim -----------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
}
$targetExe = Join-Path $Dir $ExeName

if ($Uninstall) {
    Write-Step "systop o'chirilmoqda"
    if (Test-Path $targetExe) {
        Remove-Item $targetExe -Force
        Write-Ok "o'chirildi: $targetExe"
    } else {
        Write-Warn2 "binar topilmadi: $targetExe"
    }
    Remove-FromUserPath $Dir
    if ((Test-Path $Dir) -and -not (Get-ChildItem $Dir -Force)) {
        Remove-Item $Dir -Force
    }
    Write-Ok "PATH tozalandi. Yangi terminal oching."
    exit 0
}

$asset = Get-TargetAsset
$base = Get-BaseUrl -Tag $Version
$verLabel = if ([string]::IsNullOrWhiteSpace($Version)) { 'eng so`nggi' } else { $Version }

Write-Step "systop yuklab olinmoqda ($verLabel, $asset)"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("systop-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $tmpExe = Join-Path $tmp $ExeName
    $tmpSums = Join-Path $tmp 'SHA256SUMS.txt'

    Invoke-Download -Url "$base/$asset" -OutFile $tmpExe
    $size = (Get-Item $tmpExe).Length
    Write-Ok ("yuklandi: {0:N0} bayt" -f $size)

    # --- SHA256 tekshiruvi -------------------------------------------------
    # Yuklashni tekshirmaslik — o'rnatgichdagi eng keng tarqalgan kamchilik.
    # Yarim yuklangan yoki almashtirilgan fayl JIMGINA o'rnatiladi.
    Write-Step "SHA256 tekshirilmoqda"
    $verified = $false
    try {
        Invoke-Download -Url "$base/SHA256SUMS.txt" -OutFile $tmpSums
        $actual = (Get-FileHash -Path $tmpExe -Algorithm SHA256).Hash.ToLower()
        $expected = $null
        foreach ($line in Get-Content $tmpSums) {
            # Format: "<hash>  <fayl nomi>"
            $f = ($line -split '\s+') | Where-Object { $_ -ne '' }
            if ($f.Count -ge 2 -and $f[-1] -like "*$asset") { $expected = $f[0].ToLower(); break }
        }
        if ($null -eq $expected) {
            Write-Warn2 "SHA256SUMS.txt da '$asset' yozuvi topilmadi — tekshirib bo'lmadi"
        } elseif ($actual -ne $expected) {
            Die "SHA256 MOS KELMADI. Kutilgan: $expected`n     Olingan:  $actual`n     Fayl o'rnatilMADI."
        } else {
            Write-Ok "sha256 mos: $($actual.Substring(0,16))..."
            $verified = $true
        }
    } catch {
        Write-Warn2 "SHA256SUMS.txt olinmadi — tekshiruvsiz davom etilyapti"
    }
    if (-not $verified) {
        Write-Warn2 "OGOHLANTIRISH: yuklama tekshirilmadi."
    }

    # --- ishlaydimi? -------------------------------------------------------
    # PATH'ga qo'shishdan OLDIN sinaymiz: buzuq binarni o'rnatib, keyin
    # "nega ishlamaydi" deb qidirishdan ko'ra shu yerda to'xtash yaxshi.
    Write-Step "binar tekshirilmoqda"
    try {
        $out = & $tmpExe --version 2>&1
        if ($LASTEXITCODE -ne 0) { throw "exit=$LASTEXITCODE" }
        Write-Ok "$out"
    } catch {
        Die "Binar ishga tushmadi: $($_.Exception.Message)"
    }

    # --- joyiga qo'yish ----------------------------------------------------
    Write-Step "o'rnatilmoqda: $Dir"
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    try {
        Move-Item -Path $tmpExe -Destination $targetExe -Force
    } catch {
        # Ishlab turgan systop.exe ni almashtirib bo'lmaydi (fayl band).
        Die "Faylni yozib bo'lmadi — systop ishlab turgan bo'lishi mumkin.`n     Barcha systop oynalarini yoping va qayta urinib ko'ring."
    }
    Write-Ok "$targetExe"

    if (-not $NoPath) {
        Write-Step "PATH sozlanmoqda (faqat foydalanuvchi doirasi, admin kerak emas)"
        $added = Add-ToUserPath -Directory $Dir
        if ($added) { Write-Ok "qo'shildi: $Dir" }
        # Joriy sessiyada ham darhol ishlasin.
        if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }
    }
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Tayyor.' -ForegroundColor Green
Write-Host '  systop doctor        tarmoq muammolarini avtomatik topish'
Write-Host '  systop wifi          Wi-Fi signal/SNR/kanal'
Write-Host '  systop lan -6        LAN inventari (IPv4 + IPv6)'
Write-Host '  systop               to`liq TUI dashboard'
Write-Host ''
Write-Host 'Eslatma: PATH o`zgarishi YANGI terminal oynasida kuchga kiradi.' -ForegroundColor Yellow
