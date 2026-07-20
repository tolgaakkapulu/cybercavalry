<#
.SYNOPSIS
    CYBERCavalry -- Windows setup (install + update in one script).

.PARAMETER Action
    install | update

.PARAMETER InstallDir
    Deployment root. Default: C:\CYBERCavalry.

.PARAMETER HttpsPort
    TLS listening port. Default: 8443.

.PARAMETER ZipSource
    Directory to search for CYBERCavalry_v*.zip during -Action update.
    Default: %USERPROFILE%\Downloads.

.PARAMETER RollbackDir
    Where per-update snapshots are written. Default: C:\CYBERCavalry-rollback.

.PARAMETER PythonExe
    Force a specific Python interpreter (full path or "py -3.X"). Auto-
    detected against available wheel bundles when omitted.

.EXAMPLE
    # Fresh install (elevated PowerShell), all defaults
    powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action install

.EXAMPLE
    # Custom install dir + non-default zip source
    powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 `
        -Action install -InstallDir 'D:\CYBERCavalry' -PythonExe 'py -3.11'

.EXAMPLE
    # In-place update (preserves .env, db, certs, logs)
    powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 `
        -Action update -InstallDir 'D:\CYBERCavalry' -ZipSource 'D:\releases'

.NOTES
    Prerequisites (install once, before running this script):
      - Python 3.11+ on PATH  (python.org installer, "Install for all users" + "Add to PATH")
      - The project extracted to -InstallDir  (default: C:\CYBERCavalry)
      - WinSW-x64.exe auto-downloaded on first install when internet is
        available; otherwise fetch manually from
        https://github.com/winsw/winsw/releases and drop as
        CYBERCavalry.exe in deploy\windows\.
#>
param(
    [Parameter(Mandatory=$true)][ValidateSet('install','update')]
    [string]$Action,
    # Deployment root. Left empty (the default) the script auto-derives it
    # from its own location -- so `git clone; cd CYBERCavalry;
    # .\deploy\windows\setup.ps1 -Action install` just works with no flags.
    # Override to install to a different directory (e.g. 'D:\CYBERCavalry').
    [string]$InstallDir   = '',
    # TLS listening port for the WinSW-managed service.
    [int]   $HttpsPort    = 8443,
    # Where to look for `CYBERCavalry_v*.zip` during -Action update.
    # Default: current user's Downloads folder.
    [string]$ZipSource    = (Join-Path $env:USERPROFILE 'Downloads'),
    # Where per-update rollback snapshots are written.
    [string]$RollbackDir  = 'C:\CYBERCavalry-rollback',
    # Force a specific interpreter for venv creation. Two accepted forms:
    #   -PythonExe "C:\Python311\python.exe"     (full path)
    #   -PythonExe "py -3.11"                    (py launcher + version)
    # Left empty (the default) the script tries `py -3.X` for every wheel
    # bundle available under deploy\wheels\ and picks the first that answers
    # `--version`. Falls back to the default `python` on PATH otherwise.
    [string]$PythonExe    = ''
)

# We call a lot of native commands (python, pip, WinSW, icacls, robocopy).
# PowerShell 5.1 turns every native stderr write into a NativeCommandError,
# so `Stop` would kill the script even on benign pip warnings like "you
# should upgrade pip". Standard PS pattern for shell scripts: use Continue
# and check $LASTEXITCODE explicitly (Die on non-zero for critical steps).
$ErrorActionPreference = 'Continue'

# -- Helpers --------------------------------------------------------
function Log  { param($m) Write-Host "[*]  $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[!]  $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "[X]  $m" -ForegroundColor Red; exit 1 }

# -- Pre-flight -----------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
if (-not $isAdmin)                                     { Die 'Run from elevated PowerShell (Administrator).' }
if (-not (Get-Command python -EA SilentlyContinue))    { Die 'python not on PATH. Install Python 3.11+ first.' }

# Resolve $InstallDir. Explicit -InstallDir wins. Otherwise derive from the
# script's own location (project root = script's grandparent) so a
# `git clone; cd CYBERCavalry; .\deploy\windows\setup.ps1 -Action install`
# flow works without any extra flag.
if (-not $InstallDir) {
    if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot '..\..\requirements.txt'))) {
        $InstallDir = (Get-Item (Join-Path $PSScriptRoot '..\..')).FullName.TrimEnd('\')
        Log "auto-detected project root: $InstallDir"
    } else {
        $InstallDir = 'C:\CYBERCavalry'
    }
}
if (-not (Test-Path $InstallDir)) { Die "$InstallDir not found. Clone the repo (git clone ...) or extract the release zip first, then re-run." }

Set-Location $InstallDir
$svcName = 'CYBERCavalry'
$py  = Join-Path $InstallDir 'venv\Scripts\python.exe'
$pip = Join-Path $InstallDir 'venv\Scripts\pip.exe'

# -- Shared helpers -------------------------------------------------
function Invoke-Pip {
    # Wrapper around `python -m pip <args>`. Always uses `$py -m pip` --
    # never the pip.exe launcher -- because Windows locks pip.exe while it
    # tries to self-upgrade ("To modify pip, please run ...").
    #
    # CRITICAL: pipe pip's output through Out-Host so it prints to the
    # console but is NOT captured into the function's return value.
    # PowerShell functions accumulate every write to the success stream as
    # part of their return -- if we just did `& $py -m pip @PipArgs; return
    # $LASTEXITCODE`, the caller would receive an array of [pip stdout
    # lines..., 0] and `if ($rc -ne 0)` would compare an array to 0 and
    # trigger a false "install failed" every single time.
    param([Parameter(ValueFromRemainingArguments=$true)] $PipArgs)
    & $py -m pip @PipArgs 2>&1 | Out-Host
    return $LASTEXITCODE
}

function Install-Deps {
    # NOTE: avoid Python f-strings -- PS 5.1 native-arg parser strips inner "
    $tag = 'py' + (& $py -c "import sys; print(str(sys.version_info.major)+str(sys.version_info.minor))").Trim()
    $wheels = Join-Path $InstallDir "deploy\wheels\$tag"

    # Three install strategies, picked automatically:
    #   1. No bundle at all for this Python -> install straight from PyPI
    #      (typical dev/eval on a Windows box with internet access).
    #   2. Bundle exists, all wheels install cleanly -> fully offline.
    #      (typical air-gapped deployment.)
    #   3. Bundle exists but is missing wheels (usually a Linux-only bundle
    #      being installed on Windows) -> retry with PyPI as fallback.
    # For (2)/(3) the bundle needs Windows wheels; generate one with:
    #   python deploy\prepare_offline_bundle.py --os windows --py 311

    # Self-upgrade pip using `python -m pip` (never `pip.exe`, which is
    # locked while running and returns "To modify pip, please run ..."
    # errors). --disable-pip-version-check silences the "you should
    # upgrade pip" warnings that PS 5.1 would otherwise treat as errors.
    Invoke-Pip install --disable-pip-version-check --upgrade pip | Out-Null

    if (-not (Test-Path $wheels)) {
        $available = (Get-ChildItem "$InstallDir\deploy\wheels" -Directory -EA SilentlyContinue |
                      ForEach-Object { $_.Name }) -join ', '
        if (-not $available) { $available = 'none' }
        Warn "No wheel bundle for $tag (available: $available). Installing directly from PyPI."
        $rc = Invoke-Pip install --disable-pip-version-check `
            -r "$InstallDir\requirements.txt" hypercorn
        if ($rc -ne 0) { Die "pip install from PyPI failed (exit $rc). Check internet connectivity and package availability." }
        Ok "dependencies from PyPI ($tag)"
        return
    }

    $rc = Invoke-Pip install --disable-pip-version-check `
        --no-index --find-links "$wheels\" `
        -r "$InstallDir\requirements.txt" hypercorn
    if ($rc -ne 0) {
        Warn 'offline install incomplete (Linux-only wheel bundle?) -- retrying with PyPI as fallback'
        $rc = Invoke-Pip install --disable-pip-version-check `
            --find-links "$wheels\" `
            -r "$InstallDir\requirements.txt" hypercorn
        if ($rc -ne 0) { Die "pip install failed even with PyPI fallback (exit $rc). Check network + package availability." }
        Ok "dependencies: $tag bundle + PyPI fallback"
    } else {
        Ok "dependencies from $tag (fully offline)"
    }
}

function Get-BundleVersions {
    # Return e.g. @('3.11','3.9') for bundles found under deploy\wheels\pyXY\
    Get-ChildItem "$InstallDir\deploy\wheels" -Directory -Name -EA SilentlyContinue |
        Where-Object { $_ -match '^py(\d)(\d+)$' } |
        ForEach-Object {
            if ($_ -match '^py(\d)(\d+)$') { "$($Matches[1]).$($Matches[2])" }
        }
}

function Test-PythonMatch {
    # Return $true if the given exe reports "Python <expectedVersion>" (e.g. 3.11)
    param([string]$Exe, [string]$Version)
    if (-not (Test-Path $Exe)) { return $false }
    try {
        $out = & $Exe --version 2>&1
        return ($LASTEXITCODE -eq 0 -and $out -match "Python\s+$([regex]::Escape($Version))(\.|$)")
    } catch { return $false }
}

function Resolve-Python {
    # 1. Honour explicit -PythonExe if provided
    if ($PythonExe) { return $PythonExe }
    # 2. Try to match every wheel bundle we have against, in order:
    #    a) `py -3.X` (Windows launcher)
    #    b) common install paths (python.org, winget, Store)
    $bundleVersions = Get-BundleVersions
    $tag = { param($v) 'py' + ($v -replace '\.','') }
    $searchPaths = @(
        'C:\Python{0}\python.exe',
        'C:\Program Files\Python{0}\python.exe',
        "$env:LOCALAPPDATA\Programs\Python\Python{0}\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python{0}-arm64\python.exe"
    )
    foreach ($v in $bundleVersions) {
        # a) py launcher -- cheapest test, single command
        try {
            $out = & py "-$v" --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $out -match "Python $v") {
                Log "matched wheel bundle $(& $tag $v) -> py -$v"
                return "py -$v"
            }
        } catch { }
        # b) common install paths (drop the dot: 3.11 -> 311)
        $short = $v -replace '\.',''
        foreach ($tpl in $searchPaths) {
            $candidate = $tpl -f $short
            if (Test-PythonMatch -Exe $candidate -Version $v) {
                Log "matched wheel bundle $(& $tag $v) -> $candidate"
                return $candidate
            }
        }
    }
    # 3. Fall back to whatever `python` is on PATH
    Log 'no bundle-matching Python found; using default `python` on PATH'
    return 'python'
}

function Invoke-Python {
    param([string]$Chooser, [Parameter(ValueFromRemainingArguments=$true)] $Args)
    if ($Chooser -like 'py -*') {
        $ver = ($Chooser -split ' ',2)[1]
        & py $ver @Args
    } else {
        & $Chooser @Args
    }
}

function New-Venv {
    $chooser = Resolve-Python
    Invoke-Python $chooser -m venv "$InstallDir\venv"
    if (-not (Test-Path $py)) { Die "venv creation failed (chooser=$chooser)." }
    $venvVer = (& $py --version 2>&1).ToString().Trim()
    Log "venv Python: $venvVer  (chooser: $chooser)"
    Install-Deps
}

function Write-Env {
    $k1 = (& $py -c "import secrets; print(secrets.token_urlsafe(64))").Trim()
    $k2 = (& $py -c "import secrets; print(secrets.token_urlsafe(64))").Trim()
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual -EA SilentlyContinue |
           Where-Object { $_.IPAddress -notlike '169.254*' } |
           Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = '127.0.0.1' }
    # Pulled out to avoid needing to escape the many double-quotes inside a
    # PS double-quoted here-string.
    $ldapAttrMap = '{"first_name": "givenName", "last_name": "sn", "email": "mail"}'
    $ldapFilter  = '(sAMAccountName=%(user)s)'
    $content = @"
# =============================================================
#  CYBERCavalry -- runtime configuration
#  Auto-generated by deploy\windows\setup.ps1 on first install.
#  Regenerate by deleting this file and re-running setup.
#  NEVER commit .env -- it lives outside git via .gitignore.
# =============================================================

# -- Core Django ----------------------------------------------
SECRET_KEY=$k1
DEBUG=False
ALLOWED_HOSTS=$ip,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://${ip}:$HttpsPort,https://127.0.0.1:$HttpsPort

# -- Database (SQLite by default; use postgres://user:pass@host/db in prod)
DATABASE_URL=sqlite:///cybercavalry.db

# -- Encryption key for secret Settings (SMTP/API keys/LDAP pw) --------
# If lost, existing encrypted secrets in the DB cannot be decrypted.
# Treat this key like an HSM key.
FIELD_ENCRYPTION_KEY=$k2

# -- Admin panel path & access -------------------------------
# ADMIN_PATH is loaded from here so the real URL never appears in source.
ADMIN_PATH=admin-console/
ADMIN_ALLOWED_IPS=127.0.0.1,::1

# -- SSL certificates (paths relative to the project root) ---
SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem

# -- LDAP (optional -- leave LDAP_ENABLED=False to skip) -----
LDAP_ENABLED=False
LDAP_SERVER_URI=ldaps://dc01.example.corp:636
LDAP_BIND_DN=CN=svc-cybercavalry,OU=ServiceAccounts,DC=example,DC=corp
LDAP_BIND_PASSWORD=change-me
LDAP_USER_SEARCH_BASE=OU=Users,DC=example,DC=corp
LDAP_USER_SEARCH_FILTER=$ldapFilter
LDAP_USER_ATTR_MAP=$ldapAttrMap
"@
    # CRITICAL: PowerShell 5.1's `Out-File -Encoding utf8` writes UTF-8 WITH
    # a BOM (bytes EF BB BF at the start). django-environ can't parse a BOM
    # and treats the first key/value line as "Invalid line", which surfaces
    # as `ImproperlyConfigured: Set the SECRET_KEY environment variable`
    # even though SECRET_KEY is right there in the file.
    # PS 5.1 has no built-in way to write UTF-8 without BOM; use .NET API.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $InstallDir '.env'), $content, $utf8NoBom)
    Ok '.env created with fresh keys + full parameter template'
}

function Open-Firewall {
    if (Get-NetFirewallRule -DisplayName 'CYBERCavalry HTTPS' -EA SilentlyContinue) { return }
    New-NetFirewallRule -DisplayName 'CYBERCavalry HTTPS' `
        -Direction Inbound -Protocol TCP -LocalPort $HttpsPort -Action Allow | Out-Null
    Ok "firewall: TCP/$HttpsPort opened"
}

function Get-WinSW {
    # Fetch WinSW-x64.exe from the winsw project's GitHub Releases and drop
    # it in deploy\windows\CYBERCavalry.exe (WinSW binds config-file to its
    # own basename, so the .exe must be renamed to CYBERCavalry.exe to
    # match the sibling CYBERCavalry.xml). Skips the download when the
    # binary is already present.
    # We pin v2.12.0 because WinSW v3+ switched the config format to YAML
    # and this project ships an XML service definition.
    $svcExe = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.exe'
    if (Test-Path $svcExe) { return $true }
    $url = 'https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe'
    Log "WinSW binary missing -- downloading v2.12.0 from GitHub..."
    try {
        # PS 5.1 defaults to TLS 1.0/1.1 which GitHub Releases no longer accepts.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $svcExe -UseBasicParsing
    } catch {
        Warn "WinSW download failed: $($_.Exception.Message)"
        return $false
    }
    if (Test-Path $svcExe) { Ok "WinSW installed at $svcExe"; return $true }
    return $false
}

function Install-Service {
    $svcExe = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.exe'
    $svcXml = Join-Path $InstallDir 'deploy\windows\CYBERCavalry.xml'
    $srcXml = Join-Path $InstallDir 'deploy\windows\cybercavalry-service.xml'

    if (-not (Get-WinSW)) {
        Warn "Cannot register the Windows service without WinSW."
        Warn "Manual fallback:"
        Warn "  1. Download https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
        Warn "  2. Rename to CYBERCavalry.exe and place at $svcExe"
        Warn "  3. Re-run this setup script (install), or manually:"
        Warn "       Copy-Item '$srcXml' '$svcXml'"
        Warn "       & '$svcExe' install; & '$svcExe' start"
        return $false
    }

    # Materialise the service XML with THIS deployment's paths + port.
    # The template ships with the default C:\CYBERCavalry and port 8443
    # placeholders; if the user picked a non-default -InstallDir or
    # -HttpsPort we have to substitute those or WinSW will look for
    # python.exe in the wrong place and fail with "Sistem belirtilen
    # dosyayi bulamiyor" / "The system cannot find the file specified".
    # Overwrite every time so re-runs pick up path/port changes.
    $xmlContent = Get-Content $srcXml -Raw
    $xmlContent = $xmlContent.Replace('C:\CYBERCavalry', $InstallDir)
    # Hypercorn bind form: --bind 0.0.0.0:PORT
    $xmlContent = $xmlContent.Replace('0.0.0.0:8443', "0.0.0.0:$HttpsPort")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($svcXml, $xmlContent, $utf8NoBom)

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
    # The venv Python (set by Resolve-Python inside New-Venv) is what actually
    # matters -- report that AFTER creation, not the default `python` on PATH
    # (which may be a different major.minor when -PythonExe was supplied).
    Log 'install starting'

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
    if ($LASTEXITCODE -ne 0) { Die "manage.py migrate failed (exit $LASTEXITCODE)" }
    & $py manage.py createcachetable
    if ($LASTEXITCODE -ne 0) { Warn "createcachetable returned $LASTEXITCODE (usually fine on re-runs)" }
    & $py manage.py seed_initial_data
    if ($LASTEXITCODE -ne 0) { Warn "seed_initial_data returned $LASTEXITCODE (skipping is fine on re-installs)" }
    & $py manage.py collectstatic --noinput | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "collectstatic failed (exit $LASTEXITCODE)" }
    Ok 'database + static ready'

    Open-Firewall
    Install-Service | Out-Null

    Write-Host ''
    Ok 'install complete'
    Write-Host "    Access:      https://${env:COMPUTERNAME}:$HttpsPort/"
    Write-Host '    Login:       admin / admin  (change the password immediately in Users)'
    Write-Host "    Service:     Get-Service $svcName"
}

# -- update ---------------------------------------------------------
function Invoke-Update {
    Log 'update'
    if (-not (Test-Path "$InstallDir\venv")) { Die "venv missing -- run '$($MyInvocation.MyCommand.Name) -Action install' first." }

    # Rollback snapshot
    $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $rollback = Join-Path $RollbackDir $stamp
    New-Item -ItemType Directory -Force -Path $rollback | Out-Null
    try { & $py manage.py backup_db --force } catch { Warn 'app backup_db failed -- snapshot only' }
    robocopy $InstallDir $rollback /E /XD venv backups __pycache__ | Out-Null
    Ok "snapshot: $rollback"

    Stop-Service $svcName -EA SilentlyContinue

    # Extract new zip -- default location is $env:USERPROFILE\Downloads,
    # overridable with -ZipSource.
    $zip = Get-ChildItem -Path $ZipSource -Filter 'CYBERCavalry_v*.zip' -EA SilentlyContinue |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $zip) { Die "No CYBERCavalry_v*.zip in $ZipSource" }
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
    if ($LASTEXITCODE -ne 0) { Die "manage.py migrate failed (exit $LASTEXITCODE)" }
    & $py manage.py collectstatic --noinput | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "collectstatic failed (exit $LASTEXITCODE)" }
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
