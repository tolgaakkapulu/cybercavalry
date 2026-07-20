<#
.SYNOPSIS
    CYBERCavalry — Windows in-place update script.

.DESCRIPTION
    Mirrors deploy/linux/update_rhel.sh. Preserves .env, certs\, logs\,
    backups\ and the SQLite DB; refreshes application code, venv
    dependencies, static files and migrations. Takes a full code
    snapshot under C:\CYBERCavalry-rollback\<timestamp> before touching
    anything so you can revert if the upgrade misbehaves.

    Prerequisites:
      * The system was previously installed via install_windows.ps1
      * The new-version zip is available at $ZipSource

.PARAMETER InstallDir
    Where CYBERCavalry lives. Default: C:\CYBERCavalry.

.PARAMETER ZipSource
    Directory containing the new CYBERCavalry_v*.zip. Default:
    C:\CYBERCavalry-releases.

.PARAMETER RollbackRoot
    Where per-update snapshots go. Default: C:\CYBERCavalry-rollback.

.EXAMPLE
    .\deploy\windows\update_windows.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallDir   = 'C:\CYBERCavalry',
    [string]$ZipSource    = 'C:\CYBERCavalry-releases',
    [string]$RollbackRoot = 'C:\CYBERCavalry-rollback'
)

$ErrorActionPreference = 'Stop'

function Info { param($m) Write-Host "[..]  $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "[OK]  $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[!]   $m" -ForegroundColor Yellow }
function Fail { param($m) Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Step { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# ── Pre-flight ─────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Fail 'This script must be run from an elevated PowerShell (Administrator).'
}

if (-not (Test-Path $InstallDir))          { Fail "$InstallDir not found. Run install_windows.ps1 first." }
if (-not (Test-Path "$InstallDir\venv"))   { Fail "$InstallDir\venv not found. Run install_windows.ps1 first." }

$zip = Get-ChildItem -Path $ZipSource -Filter 'CYBERCavalry_v*.zip' -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Fail "No CYBERCavalry_v*.zip found under $ZipSource." }
Info "Update package: $($zip.FullName)"

$py  = Join-Path $InstallDir 'venv\Scripts\python.exe'
$pip = Join-Path $InstallDir 'venv\Scripts\pip.exe'

# Paths preserved across the sync (robocopy /XF /XD)
$preserveFiles = @('.env', 'cybercavalry.db', 'cybercavalry.db-wal', 'cybercavalry.db-shm')
$preserveDirs  = @('venv', 'certs', 'logs', 'backups')

# ── 1. Pre-update backup ───────────────────────────────────────────
Step '1/8 Pre-update backup'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$rollbackPath = Join-Path $RollbackRoot $stamp
New-Item -ItemType Directory -Force -Path $rollbackPath | Out-Null

# DB snapshot via the app's own backup_service
if (Test-Path "$InstallDir\cybercavalry.db") {
    try {
        Push-Location $InstallDir
        & $py manage.py backup_db --force
    } catch {
        Warn "backup_db failed: $_ — falling back to raw file copy."
    } finally {
        Pop-Location
    }
}

Info "Taking code snapshot: $rollbackPath"
# Robocopy: /MIR would mirror; here we want a snapshot MINUS venv and backups
robocopy $InstallDir $rollbackPath /E /XD venv backups __pycache__ | Out-Null
Ok "Backup taken: $rollbackPath"

# ── 2. Stop the service ────────────────────────────────────────────
Step '2/8 Stop the service'
try {
    Stop-Service CYBERCavalry -ErrorAction Stop
    Ok 'CYBERCavalry stopped.'
} catch {
    Warn "Service was not running (or absent): $_"
}

# ── 3. Extract the new version ─────────────────────────────────────
Step '3/8 Extract the new version'
$extractTmp = Join-Path $env:TEMP "cc-update-$stamp"
New-Item -ItemType Directory -Force -Path $extractTmp | Out-Null
Expand-Archive -Path $zip.FullName -DestinationPath $extractTmp -Force
$newSrc = Join-Path $extractTmp 'CYBERCavalry'
if (-not (Test-Path $newSrc)) {
    Fail "Zip does not contain a CYBERCavalry\ directory — unexpected layout."
}
Ok "Extracted to: $newSrc"

# ── 4. Sync the code (preserving protected paths) ──────────────────
Step '4/8 Code sync'
$xf = $preserveFiles -join ' '
$xd = ($preserveDirs | ForEach-Object { Join-Path $InstallDir $_ }) -join ' '
# /MIR = mirror; excludes keep .env/certs/logs/db intact
$roboArgs = @($newSrc, $InstallDir, '/MIR', '/XF') + $preserveFiles + @('/XD') + ($preserveDirs | ForEach-Object { Join-Path $InstallDir $_ })
robocopy @roboArgs | Out-Null
# robocopy exit codes 0-7 = success; 8+ = errors
if ($LASTEXITCODE -ge 8) { Fail "robocopy failed with exit code $LASTEXITCODE" }
Remove-Item -Recurse -Force $extractTmp
Ok 'Code updated (.env, certs, logs, db, backups, venv preserved).'

# ── 5. Refresh dependencies (with venv health pre-flight) ──────────
Step '5/8 Dependencies'

# Pre-flight: is pip actually usable? If the deploy directory was moved
# or the base Python was rebuilt, the venv's shebangs / DLL references
# can go stale and pip fails immediately. Rebuild in that case so the
# offline install below has a clean starting point.
$pipHealthy = $true
try {
    & $pip --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $pipHealthy = $false }
} catch {
    $pipHealthy = $false
}

if (-not $pipHealthy) {
    Warn 'venv appears broken (pip refuses to run) — rebuilding from scratch.'
    Remove-Item -Recurse -Force "$InstallDir\venv"
    python -m venv "$InstallDir\venv"
    & $py -m ensurepip --upgrade 2>&1 | Out-Null
    Ok 'venv rebuilt.'
}

# NOTE: See install_windows.ps1 for why we avoid Python f-strings here.
$pyTag = 'py' + (& $py -c "import sys; print(str(sys.version_info.major)+str(sys.version_info.minor))").Trim()
$wheelsDir = Join-Path $InstallDir "deploy\wheels\$pyTag"
if (Test-Path $wheelsDir) {
    & $pip install --no-index --find-links "$wheelsDir\" `
        --upgrade -r "$InstallDir\requirements.txt" waitress | Out-Null
    Ok "Dependencies refreshed (from wheel set $pyTag)."
} else {
    Warn "Wheel directory missing ($wheelsDir) — dependency refresh skipped."
}

# ── 6. Certificate ACL refresh ─────────────────────────────────────
Step '6/8 Certificate ACLs'
if (Test-Path "$InstallDir\certs\key.pem") {
    icacls "$InstallDir\certs\key.pem" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
    Ok 'Private-key ACL re-tightened.'
} else {
    Info 'No private key present — skipped.'
}

# ── 7. Migration + static ──────────────────────────────────────────
Step '7/8 Migration + static'
Push-Location $InstallDir
& $py manage.py migrate --noinput
try { & $py manage.py createcachetable | Out-Null } catch { }
& $py manage.py collectstatic --noinput | Out-Null
Pop-Location
Ok 'Migrations applied, static files collected.'

# ── 8. Start the service + health check ────────────────────────────
Step '8/8 Start the service'
try {
    Start-Service CYBERCavalry
    Start-Sleep -Seconds 3
    $status = (Get-Service CYBERCavalry).Status
    if ($status -eq 'Running') {
        Ok 'CYBERCavalry is running.'
        Write-Host ''
        Write-Host '=== Update complete ===' -ForegroundColor Green
        Write-Host "  Rollback snapshot: $rollbackPath" -ForegroundColor Cyan
        Write-Host '  To roll back:'
        Write-Host "    Stop-Service CYBERCavalry"
        Write-Host "    robocopy $rollbackPath $InstallDir /MIR /XD venv"
        Write-Host "    Start-Service CYBERCavalry"
    } else {
        Fail "Service status: $status. Check logs\service.wrapper.log for details."
    }
} catch {
    Fail "Service failed to start: $_"
}
