<#
.SYNOPSIS
    Builds the FileSentinel Standalone Executable (.exe) and Windows Installer (.msi).

.DESCRIPTION
    1. Verifies/downloads portable WiX Toolset binaries into tools\wix
    2. Runs PyInstaller to compile FileSentinel.exe with embedded templates, static files, icons, and PE version resource
    3. Runs WiX candle and light to generate FileSentinel-Setup.msi
    4. Applies Authenticode code-signing to both binaries
    5. Outputs all distribution packages into the dist\ directory
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   FileSentinel DLP - Automated Build Pipeline (.exe & .msi)" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Check Python & PyInstaller
Write-Host "[1/5] Checking Python environment and dependencies..." -ForegroundColor Yellow
$py = Get-Command python -ErrorAction SilentlyContinue
if (!$py) {
    Write-Error "Python was not found in PATH. Please install Python 3.10+."
}

$hasPyInstaller = python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Installing PyInstaller..." -ForegroundColor DarkGray
    python -m pip install pyinstaller
}

# 2. Check/Download WiX Toolset (portable binaries)
Write-Host "[2/5] Ensuring WiX Toolset binaries..." -ForegroundColor Yellow
$WixDir = Join-Path $ScriptDir "tools\wix"
$CandleExe = Join-Path $WixDir "candle.exe"
$LightExe = Join-Path $WixDir "light.exe"

if (!(Test-Path $CandleExe) -or !(Test-Path $LightExe)) {
    Write-Host "  Downloading portable WiX 3.11 binaries..." -ForegroundColor DarkGray
    if (!(Test-Path $WixDir)) { New-Item -ItemType Directory -Path $WixDir -Force | Out-Null }
    $ZipPath = Join-Path $WixDir "wix.zip"
    Invoke-WebRequest -Uri "https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip" -OutFile $ZipPath
    Expand-Archive -Path $ZipPath -DestinationPath $WixDir -Force
    Remove-Item $ZipPath -Force
}
Write-Host "  WiX Toolset ready." -ForegroundColor Green

# 3. Build Standalone Executable (.exe)
Write-Host "[3/5] Building FileSentinel.exe with PyInstaller & PE Version Info..." -ForegroundColor Yellow
$VersionFile = Join-Path $ScriptDir "installer\version_info.txt"

python -m PyInstaller `
    --noconsole `
    --onefile `
    --name "FileSentinel" `
    --icon "assets/icon.ico" `
    --version-file "$VersionFile" `
    --collect-all "webview" `
    --collect-all "pystray" `
    --add-data "dashboard/templates;dashboard/templates" `
    --add-data "dashboard/static;dashboard/static" `
    --add-data "assets;assets" `
    main.py

if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed."
}
Write-Host "  FileSentinel.exe generated successfully." -ForegroundColor Green

# 4. Compile Windows MSI Installer (.msi)
Write-Host "[4/5] Compiling Windows Installer (.msi) with WiX..." -ForegroundColor Yellow
$InstallerDir = Join-Path $ScriptDir "installer"
$WixObj = Join-Path $InstallerDir "FileSentinel.wixobj"
$WxsFile = Join-Path $InstallerDir "FileSentinel.wxs"
$MsiOutput = Join-Path $ScriptDir "dist\FileSentinel-Setup.msi"

& $CandleExe -nologo -arch x64 -ext WixUIExtension $WxsFile -out $WixObj
if ($LASTEXITCODE -ne 0) { Write-Error "WiX candle compilation failed." }

& $LightExe -nologo -ext WixUIExtension -sice:ICE69 -out $MsiOutput $WixObj
if ($LASTEXITCODE -ne 0) { Write-Error "WiX light linking failed." }

# Cleanup intermediate obj file
if (Test-Path $WixObj) { Remove-Item $WixObj -Force }

# 5. Apply Authenticode Digital Signatures
Write-Host "[5/5] Applying Authenticode Code Signing..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Select-Object -First 1
if (!$cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=FileSentinel Security, O=FileSentinel, C=US" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)
}

if ($cert) {
    Set-AuthenticodeSignature -FilePath "dist\FileSentinel.exe" -Certificate $cert | Out-Null
    Set-AuthenticodeSignature -FilePath "dist\FileSentinel-Setup.msi" -Certificate $cert | Out-Null
    Write-Host "  Digital signatures applied to FileSentinel.exe and FileSentinel-Setup.msi." -ForegroundColor Green
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "   BUILD SUCCESSFUL!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
$ExeItem = Get-Item "dist\FileSentinel.exe"
$MsiItem = Get-Item "dist\FileSentinel-Setup.msi"

Write-Host ("  Standalone Executable : {0} ({1:N2} MB)" -f $ExeItem.FullName, ($ExeItem.Length / 1MB)) -ForegroundColor Cyan
Write-Host ("  Windows Installer MSI : {0} ({1:N2} MB)" -f $MsiItem.FullName, ($MsiItem.Length / 1MB)) -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Green
