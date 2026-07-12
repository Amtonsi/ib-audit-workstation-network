[CmdletBinding()]
param(
    [switch]$IConfirmRights,
    [ValidateSet("internal", "redistribution")]
    [string]$Purpose = "internal",
    [switch]$IncludeNpcapOem,
    [string]$DistPath = "outputs\dist-licensed",
    [string]$WorkPath = "build\pyinstaller\work-licensed"
)

$ErrorActionPreference = "Stop"

if (-not $IConfirmRights) {
    throw "Укажите -IConfirmRights только если у вас есть права на использование компонентов для выбранной цели."
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$nmapExe = Join-Path $projectRoot "tools\nmap\nmap.exe"
$nmapLicense = Join-Path $projectRoot "tools\nmap\LICENSE"
$tsharkExe = Join-Path $projectRoot "tools\wireshark\tshark.exe"
$wiresharkLicense = Join-Path $projectRoot "tools\wireshark\COPYING.txt"

$required = @($nmapExe, $nmapLicense, $tsharkExe, $wiresharkLicense)
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
if ($missing.Count) {
    throw "Отсутствуют обязательные локальные файлы: $($missing -join ', ')"
}

$bundledFreeNpcap = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot "tools\nmap") -Filter "npcap*.exe" -File -ErrorAction SilentlyContinue)
if ($bundledFreeNpcap.Count) {
    Write-Warning "Npcap из tools\nmap будет исключён из EXE независимо от содержимого каталога."
}

if ($IncludeNpcapOem) {
    $npcapOemDir = Join-Path $projectRoot "tools\npcap-oem"
    if (-not (Test-Path -LiteralPath $npcapOemDir -PathType Container)) {
        throw "Для -IncludeNpcapOem требуется локальный каталог tools\npcap-oem."
    }
    if (-not (Get-ChildItem -LiteralPath $npcapOemDir -Filter "*.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        throw "В tools\npcap-oem не найден OEM-установщик."
    }
}

if ($Purpose -eq "redistribution") {
    Write-Warning "Подтверждение должно охватывать внешнее распространение именно этого продукта и всех включённых компонентов."
}

$oldProfile = $env:IB_AUDIT_BUILD_PROFILE
$oldAck = $env:IB_AUDIT_LICENSE_ACK
$oldNpcap = $env:IB_AUDIT_INCLUDE_NPCAP_OEM

try {
    $env:IB_AUDIT_BUILD_PROFILE = "licensed-local"
    $env:IB_AUDIT_LICENSE_ACK = "I_HAVE_DISTRIBUTION_RIGHTS"
    $env:IB_AUDIT_INCLUDE_NPCAP_OEM = if ($IncludeNpcapOem) { "1" } else { "0" }

    Push-Location $projectRoot
    try {
        & python -m PyInstaller build\pyinstaller\IBAuditWorkstation.spec --noconfirm --clean --distpath $DistPath --workpath $WorkPath
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller завершился с кодом $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:IB_AUDIT_BUILD_PROFILE = $oldProfile
    $env:IB_AUDIT_LICENSE_ACK = $oldAck
    $env:IB_AUDIT_INCLUDE_NPCAP_OEM = $oldNpcap
}

Write-Host "Лицензированная локальная сборка создана: $DistPath"
