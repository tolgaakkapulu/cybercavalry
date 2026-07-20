<#
.SYNOPSIS
    CYBERCavalry — Windows one-shot installer.

.DESCRIPTION
    Mirrors deploy/linux/install_rhel.sh but targeting Windows Server 2019/2022
    (or Windows 10/11 for dev). Creates the venv, installs offline wheels,
    seeds .env, generates a self-signed certificate if needed, runs migrate +
    collectstatic, opens the firewall port, and (optionally) registers the
    WinSW service.

    Manual steps still required before running this script:
      1. Install Python 3.11 or 3.12 for all users, added to PATH
      2. Extract the release zip so this script lives at
         C:\CYBERCavalry\deploy\windows\install_windows.ps1
      3. (Service install) Place WinSW-x64.exe next to this script and
         rename it to CYBERCavalry.exe

.PARAMETER InstallDir
    Where the project is extracted. Default: C:\CYBERCavalry.

.PARAMETER HttpsPort
    Listening TCP port for the HTTPS service. Default: 8443.

.PARAMETER SkipService
    Skip the WinSW service install step (do everything else). Useful for
    dev machines where you just want to run `manage_server.py start`.

.PARAMETER SkipFirewall
    Skip the Windows Firewall rule step (for hosts behind an external
    firewall or when the rule already exists).

.EXAMPLE
    # Elevated PowerShell in the CYBERCavalry directory
    .\deploy\windows\install_windows.ps1

.EXAMPLE
    .\deploy\windows\install_windows.ps1 -InstallDir 'D:\CyberCav' -HttpsPort 9443
#>

[CmdletBinding()]
param(
    [string]$InstallDir  = 'C:\CYBERCavalry',
    [int]   $HttpsPort   = 8443,
    [switch]$SkipService,
    [switch]$SkipFirewall
)

$ErrorActionPreference = 'Stop'

# ── Coloured log helpers ───────────────────────────────────────────
function Info   { param($m) Write-Host "[..]  $m" -ForegroundColor Cyan }
function Ok     { param($m) Write-Host "[OK]  $m" -ForegroundColor Green }
function Warn   { param($m) Write-Host "[!]   $m" -ForegroundColor Yellow }
function Fail   { param($m) Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Step   { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# ── Pre-flight ─────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Fail 'This script must be run from an elevated PowerShell (Administrator).'
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Fail 'python not found on PATH. Install Python 3.11+ from python.org first.'
}

if (-not (Test-Path $InstallDir)) {
    Fail "Install directory not found: $InstallDir  (extract the release zip there first)."
}

Set-Location $InstallDir

# ── 1. Venv ────────────────────────────────────────────────────────
Step '1/8 Virtual environment'
if (Test-Path 'venv') {
    Info 'Removing existing venv...'
    Remove-Item -Recurse -Force venv
}
python -m venv venv
if (-not (Test-Path 'venv\Scripts\python.exe')) {
    Fail 'venv creation failed.'
}
Ok 'venv created.'

# ── 2. Wheel-set detection ─────────────────────────────────────────
Step '2/8 Python version + wheel set'
$py = '.\venv\Scripts\python.exe'
# NOTE: Avoid Python f-strings here — PowerShell 5.1's native-command
# argument parser strips double-quotes even inside single-quoted PS
# strings, so `f"{...}"` reaches Python as `f{...}` and blows up as a
# SyntaxError. Plain str() concatenation with double-quoted PS wrapping
# is safe on both PowerShell 5.1 and 7.
$pyTag = 'py' + (& $py -c "import sys; print(str(sys.version_info.major)+str(sys.version_info.minor))").Trim()
$wheelsDir = Join-Path $InstallDir "deploy\wheels\$pyTag"
if (-not (Test-Path $wheelsDir)) {
    Fail "Wheel bundle not found: $wheelsDir  (available: $(Get-ChildItem "$InstallDir\deploy\wheels" -ErrorAction SilentlyContinue | ForEach-Object Name))"
}
Ok "Wheel set: $pyTag  (from $wheelsDir)"

# ── 3. Dependencies (offline) ──────────────────────────────────────
Step '3/8 Dependencies'
& $py -m pip install --no-index --find-links "$wheelsDir\" --upgrade pip | Out-Null
& $py -m pip install --no-index --find-links "$wheelsDir\" `
    -r requirements.txt waitress
if ($LASTEXITCODE -ne 0) { Fail 'pip install failed. Inspect the output above.' }
$pkgCount = (& $py -m pip list --format=freeze | Measure-Object -Line).Lines
Ok "Dependencies installed ($pkgCount packages)."

# ── 4. .env ────────────────────────────────────────────────────────
Step '4/8 .env'
if ((Test-Path '.env') -and ((Get-Item '.env').Length -gt 0)) {
    Info 'Existing .env preserved.'
} else {
    # `secrets.token_urlsafe(64)` gives us ~85 chars of URL-safe base64
    # entropy — same practical strength as the custom character-set
    # approach, but as a single-liner that avoids PowerShell here-string
    # quoting hazards on 5.1.
    function New-RandomKey {
        (& $py -c "import secrets; print(secrets.token_urlsafe(64))").Trim()
    }
    $secretKey = New-RandomKey
    $fieldKey  = New-RandomKey
    $serverIp  = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp, Manual `
                  -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -notlike '169.254*' } |
                  Select-Object -First 1).IPAddress
    if (-not $serverIp) { $serverIp = '127.0.0.1' }

    @"
SECRET_KEY=$secretKey
FIELD_ENCRYPTION_KEY=$fieldKey
DEBUG=False
ALLOWED_HOSTS=$serverIp,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://${serverIp}:$HttpsPort,https://127.0.0.1:$HttpsPort

# SECURE_SSL_REDIRECT=True   # enable when behind a reverse proxy
# REDIS_URL=redis://127.0.0.1:6379/1   # DatabaseCache is the fallback

ADMIN_ALLOWED_IPS=127.0.0.1,::1

SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem
"@ | Out-File -Encoding utf8 -FilePath '.env' -Force
    Ok '.env created (SECRET_KEY + FIELD_ENCRYPTION_KEY generated).'
}

# ── 5. Certificates ────────────────────────────────────────────────
Step '5/8 SSL certificate'
New-Item -ItemType Directory -Force -Path 'certs' | Out-Null
if ((Test-Path 'certs\cert.pem') -and (Test-Path 'certs\key.pem')) {
    Info 'Certificates already present; leaving them untouched.'
} else {
    & $py generate_cert.py
    if (Test-Path 'certs\key.pem') {
        # Tighten ACL on the private key
        icacls 'certs\key.pem' /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
        Ok 'Self-signed certificate generated and ACLs tightened.'
    } else {
        Warn 'Certificate generation did not produce certs\key.pem — check generate_cert.py output.'
    }
}

# ── 6. DB + cache + seed + static ──────────────────────────────────
Step '6/8 Database, cache, seed, static'
& $py manage.py migrate --noinput
& $py manage.py createcachetable
try { & $py manage.py seed_initial_data } catch { Warn "seed_initial_data skipped: $_" }
& $py manage.py collectstatic --noinput | Out-Null
Ok 'DB ready, cache table created, static files collected.'

# ── 7. Firewall ────────────────────────────────────────────────────
Step '7/8 Firewall'
if ($SkipFirewall) {
    Info 'Firewall step skipped (-SkipFirewall).'
} else {
    $existing = Get-NetFirewallRule -DisplayName 'CYBERCavalry HTTPS' -ErrorAction SilentlyContinue
    if ($existing) {
        Info 'Firewall rule already exists.'
    } else {
        New-NetFirewallRule -DisplayName 'CYBERCavalry HTTPS' `
            -Direction Inbound -Protocol TCP -LocalPort $HttpsPort -Action Allow | Out-Null
        Ok "Firewall: TCP/$HttpsPort opened."
    }
}

# ── 8. Windows service (WinSW) ─────────────────────────────────────
Step '8/8 Windows service'
if ($SkipService) {
    Info 'Service registration skipped (-SkipService).'
} else {
    $svcExe = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.exe'
    $svcXml = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.xml'
    $svcXmlSrc = Join-Path $InstallDir 'deploy\windows\cybercavalry-service.xml'

    if (-not (Test-Path $svcExe)) {
        Warn "WinSW binary not found at $svcExe."
        Warn 'Download WinSW-x64.exe from https://github.com/winsw/winsw/releases,'
        Warn "rename it to CYBERCavalry.exe and place it at $svcExe, then re-run this script."
    } else {
        if (-not (Test-Path $svcXml)) {
            Copy-Item $svcXmlSrc $svcXml
        }
        # (Re-)install
        & $svcExe uninstall 2>$null | Out-Null
        & $svcExe install
        & $svcExe start
        Start-Sleep -Seconds 3
        $status = (Get-Service CYBERCavalry -ErrorAction SilentlyContinue).Status
        if ($status -eq 'Running') {
            Ok 'CYBERCavalry service is running.'
        } else {
            Warn "Service status: $status. Check logs\service.wrapper.log for details."
        }
    }
}

# ── Summary ────────────────────────────────────────────────────────
Write-Host ''
Write-Host '=== Installation complete ===' -ForegroundColor Green
Write-Host ''
Write-Host "  Access:  https://$(hostname):$HttpsPort/" -ForegroundColor Cyan
Write-Host ''
Write-Host '  Service commands:'
Write-Host '    Get-Service CYBERCavalry'
Write-Host '    Restart-Service CYBERCavalry'
Write-Host '    Get-Content logs\service.wrapper.log -Wait'
Write-Host ''
Write-Host '  Final step — create the superuser (interactive):' -ForegroundColor Yellow
Write-Host "    cd $InstallDir"
Write-Host '    .\venv\Scripts\python.exe manage.py createsuperuser'
Write-Host ''
