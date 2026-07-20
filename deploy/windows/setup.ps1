<#
.SYNOPSIS
    CYBERCavalry -- Windows setup (install + update in one script).

.EXAMPLE
    # Fresh install (elevated PowerShell)
    powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action install

.EXAMPLE
    # In-place update (preserves .env, db, certs, logs)
    powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action update

.NOTES
    Prerequisites (install once, before running this script):
      - Python 3.11+ on PATH  (python.org installer, "Install for all users" + "Add to PATH")
      - The project extracted to $InstallDir (default: C:\CYBERCavalry)
      - WinSW-x64.exe copied to $InstallDir\deploy\windows\CYBERCavalry.exe
        (download from https://github.com/winsw/winsw/releases)
#>
param(
    [Parameter(Mandatory=$true)][ValidateSet('install','update')]
    [string]$Action,
    [string]$InstallDir = 'C:\CYBERCavalry',
    [int]$HttpsPort     = 8443
)

$ErrorActionPreference = 'Stop'

# -- Helpers --------------------------------------------------------
function Log  { param($m) Write-Host "[*]  $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[!]  $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "[X]  $m" -ForegroundColor Red; exit 1 }

# -- Pre-flight -----------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
if (-not $isAdmin)                                     { Die 'Run from elevated PowerShell (Administrator).' }
if (-not (Get-Command python -EA SilentlyContinue))    { Die 'python not on PATH. Install Python 3.11+ first.' }
if (-not (Test-Path $InstallDir))                      { Die "$InstallDir not found. Extract the release zip there first." }

Set-Location $InstallDir
$svcName = 'CYBERCavalry'
$py  = Join-Path $InstallDir 'venv\Scripts\python.exe'
$pip = Join-Path $InstallDir 'venv\Scripts\pip.exe'

# -- Shared helpers -------------------------------------------------
function Install-Deps {
    # NOTE: avoid Python f-strings -- PS 5.1 native-arg parser strips inner "
    $tag = 'py' + (& $py -c "import sys; print(str(sys.version_info.major)+str(sys.version_info.minor))").Trim()
    $wheels = Join-Path $InstallDir "deploy\wheels\$tag"
    if (-not (Test-Path $wheels)) {
        $available = (Get-ChildItem "$InstallDir\deploy\wheels" -Directory -EA SilentlyContinue |
                      ForEach-Object { $_.Name }) -join ', '
        if (-not $available) { $available = '(none)' }
        Die @"
Wheel bundle missing: $wheels
Your Python is $tag but only these bundles ship in this release: $available.

Fix — install a matching Python version and rerun. On Windows, use the py
launcher to keep multiple versions side by side:
    winget install Python.Python.3.11    # or python.org installer
    py -3.11 --version                    # verify
    Remove-Item -Recurse -Force '$InstallDir\venv'
    `$env:PATH = 'C:\Python311;C:\Python311\Scripts;' + `$env:PATH
    # then re-run this script.

Alternatively, on a connected workstation regenerate the bundle with the
target Python major.minor:
    python deploy\prepare_offline_bundle.py --py $($tag.Substring(2))
"@
    }
    & $pip install --no-index --find-links "$wheels\" --upgrade pip | Out-Null
    & $pip install --no-index --find-links "$wheels\" -r "$InstallDir\requirements.txt" waitress
    if ($LASTEXITCODE -ne 0) { Die 'pip install failed.' }
    Ok "dependencies from $tag"
}

function New-Venv {
    python -m venv "$InstallDir\venv"
    if (-not (Test-Path $py)) { Die 'venv creation failed.' }
    Install-Deps
}

function Write-Env {
    $k1 = (& $py -c "import secrets; print(secrets.token_urlsafe(64))").Trim()
    $k2 = (& $py -c "import secrets; print(secrets.token_urlsafe(64))").Trim()
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual -EA SilentlyContinue |
           Where-Object { $_.IPAddress -notlike '169.254*' } |
           Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = '127.0.0.1' }
    @"
SECRET_KEY=$k1
FIELD_ENCRYPTION_KEY=$k2
DEBUG=False
ALLOWED_HOSTS=$ip,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://${ip}:$HttpsPort,https://127.0.0.1:$HttpsPort
ADMIN_ALLOWED_IPS=127.0.0.1,::1
SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem
"@ | Out-File -Encoding utf8 -FilePath (Join-Path $InstallDir '.env') -Force
    Ok '.env created with fresh keys'
}

function Open-Firewall {
    if (Get-NetFirewallRule -DisplayName 'CYBERCavalry HTTPS' -EA SilentlyContinue) { return }
    New-NetFirewallRule -DisplayName 'CYBERCavalry HTTPS' `
        -Direction Inbound -Protocol TCP -LocalPort $HttpsPort -Action Allow | Out-Null
    Ok "firewall: TCP/$HttpsPort opened"
}

function Install-Service {
    $svcExe = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.exe'
    $svcXml = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.xml'
    $srcXml = Join-Path $InstallDir 'deploy\windows\cybercavalry-service.xml'
    if (-not (Test-Path $svcExe)) {
        Warn "WinSW binary missing at $svcExe."
        Warn 'Download WinSW-x64.exe from https://github.com/winsw/winsw/releases,'
        Warn "rename to CYBERCavalry.exe, place at $svcExe, then re-run this script."
        return $false
    }
    if (-not (Test-Path $svcXml)) { Copy-Item $srcXml $svcXml }
    & $svcExe uninstall 2>$null | Out-Null
    & $svcExe install
    & $svcExe start
    Start-Sleep -Seconds 3
    $status = (Get-Service $svcName -EA SilentlyContinue).Status
    if ($status -eq 'Running') { Ok "$svcName is running"; return $true }
    Warn "service status: $status  (check logs\service.wrapper.log)"
    return $false
}

# -- install --------------------------------------------------------
function Invoke-Install {
    Log "install  (python $(python --version 2>&1 | ForEach-Object { $_.Split(' ')[1] }))"

    if (Test-Path "$InstallDir\venv") { Remove-Item -Recurse -Force "$InstallDir\venv" }
    New-Venv

    if (-not (Test-Path "$InstallDir\.env") -or (Get-Item "$InstallDir\.env").Length -eq 0) {
        Write-Env
    } else {
        Log 'existing .env preserved'
    }

    New-Item -ItemType Directory -Force -Path "$InstallDir\certs" | Out-Null
    if (-not (Test-Path "$InstallDir\certs\cert.pem")) {
        & $py "$InstallDir\generate_cert.py"
        if (Test-Path "$InstallDir\certs\key.pem") {
            icacls "$InstallDir\certs\key.pem" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
            Ok 'self-signed certificate generated'
        }
    }

    & $py manage.py migrate --noinput
    & $py manage.py createcachetable
    try { & $py manage.py seed_initial_data } catch { Warn "seed_initial_data skipped: $_" }
    & $py manage.py collectstatic --noinput | Out-Null
    Ok 'database + static ready'

    Open-Firewall
    Install-Service | Out-Null

    Write-Host ''
    Ok 'install complete'
    Write-Host "    Access:      https://${env:COMPUTERNAME}:$HttpsPort/"
    Write-Host "    Service:     Get-Service $svcName"
    Write-Host '    Create superuser:'
    Write-Host "      cd $InstallDir; .\venv\Scripts\python.exe manage.py createsuperuser"
}

# -- update ---------------------------------------------------------
function Invoke-Update {
    Log 'update'
    if (-not (Test-Path "$InstallDir\venv")) { Die "venv missing -- run '$($MyInvocation.MyCommand.Name) -Action install' first." }

    # Rollback snapshot
    $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $rollback = Join-Path 'C:\CYBERCavalry-rollback' $stamp
    New-Item -ItemType Directory -Force -Path $rollback | Out-Null
    try { & $py manage.py backup_db --force } catch { Warn 'app backup_db failed -- snapshot only' }
    robocopy $InstallDir $rollback /E /XD venv backups __pycache__ | Out-Null
    Ok "snapshot: $rollback"

    Stop-Service $svcName -EA SilentlyContinue

    # Extract new zip (expected to be at $env:USERPROFILE\Downloads or supplied via other means)
    $zip = Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Filter 'CYBERCavalry_v*.zip' -EA SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $zip) { Die 'No CYBERCavalry_v*.zip in Downloads folder.' }
    $tmp = Join-Path $env:TEMP "cc-upd-$stamp"
    Expand-Archive -Path $zip.FullName -DestinationPath $tmp -Force
    $newSrc = Join-Path $tmp 'CYBERCavalry'
    if (-not (Test-Path $newSrc)) { Die 'unexpected zip layout' }

    # Sync -- preserve .env, venv, certs, logs, backups, db
    $roboArgs = @($newSrc, $InstallDir, '/MIR',
        '/XF', '.env', 'cybercavalry.db', 'cybercavalry.db-wal', 'cybercavalry.db-shm',
        '/XD', "$InstallDir\venv", "$InstallDir\certs", "$InstallDir\logs", "$InstallDir\backups")
    robocopy @roboArgs | Out-Null
    if ($LASTEXITCODE -ge 8) { Die "robocopy failed ($LASTEXITCODE)" }
    Remove-Item -Recurse -Force $tmp
    Ok 'code synced'

    # venv health pre-flight (broken shebangs / stale interpreter -> rebuild)
    $pipOk = $true
    try { & $pip --version 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { $pipOk = $false } } catch { $pipOk = $false }
    if (-not $pipOk) {
        Warn 'venv broken -- rebuilding'
        Remove-Item -Recurse -Force "$InstallDir\venv"
        New-Venv
    } else {
        Install-Deps
    }

    & $py manage.py migrate --noinput
    & $py manage.py collectstatic --noinput | Out-Null
    if (Test-Path "$InstallDir\certs\key.pem") {
        icacls "$InstallDir\certs\key.pem" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
    }

    Start-Service $svcName
    Start-Sleep -Seconds 3
    $status = (Get-Service $svcName).Status
    if ($status -ne 'Running') {
        Die "service failed to restart. Rollback:  robocopy $rollback $InstallDir /MIR /XD venv"
    }
    Ok "update complete (rollback: $rollback)"
}

# -- Dispatch -------------------------------------------------------
switch ($Action) {
    'install' { Invoke-Install }
    'update'  { Invoke-Update  }
}
