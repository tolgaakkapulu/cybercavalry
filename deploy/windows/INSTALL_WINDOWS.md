# CYBERCavalry — Windows Installation Guide

This guide covers running CYBERCavalry on **Windows Server 2019 / 2022**
(also Windows 10 / 11 for dev + evaluation) as a persistent service.
It **assumes the target host has no internet access** — required Python
wheels are prepared on a connected workstation and transferred over.

Architecture:

```
client  ─HTTPS(8443)─►  waitress (cybercavalry service)  ─►  Django WSGI
                              │
                              ├─ SQLite or PostgreSQL
                              └─ (optional) Redis
```

| Parameter          | Value                                           |
|--------------------|-------------------------------------------------|
| Target OS          | Windows Server 2019 / 2022 (or Windows 10 / 11) |
| Python             | 3.11 or 3.12                                    |
| Service user       | `NT SERVICE\CYBERCavalry` (WinSW auto-created)  |
| Install directory  | `C:\CYBERCavalry`                               |
| Service name       | `CYBERCavalry`                                  |
| Listening port     | `8443/tcp` (HTTPS)                              |

> **Windows vs. Linux differences** (baked in throughout this guide)
> - `gunicorn` does not run on Windows — we use **`waitress`** instead
> - No `systemd`; we use **WinSW** (a battle-tested Windows service wrapper)
> - No SELinux — nothing to relabel
> - PowerShell is the primary shell — the installer script is `.ps1`

---

## 0. Preparation — On a Connected Workstation

Same as the Linux flow — the offline wheel bundle is cross-platform.
See [`deploy/README.md`](../README.md) for the shared bundling step.
Once you have the zip, transfer it to the target Windows host along
with [WinSW](https://github.com/winsw/winsw/releases) (see step 8).

---

## 1. Prerequisites on the Target Host

### 1.1 Python 3.11

Download the Python 3.11.x installer from the connected workstation:
- https://www.python.org/downloads/windows/ → `Windows installer (64-bit)`

Copy the installer to the target host and run it with these checkboxes:

- ✔ **Install for all users**
- ✔ **Add Python to PATH**
- Optionally uncheck "Install launcher for all users" if you don't need `py`

Verify:

```powershell
python --version
# Python 3.11.9 (or similar)
```

### 1.2 Enable long paths (recommended)

Windows historically caps paths at 260 chars — Python virtualenvs plus
deep site-packages can bump into that. Enable long paths once:

```powershell
# Run in elevated PowerShell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

Reboot for it to take effect (or just proceed — most flows still work).

### 1.3 (Optional) Redis

If you want Redis-backed cache instead of the DatabaseCache fallback:

- **Memurai** (commercial Redis-compatible for Windows) — https://www.memurai.com/
- Or **WSL2** with `sudo apt install redis-server`
- Or just skip it — DatabaseCache is fine for single-node deployments

---

## 2. Deploy the Project

Assuming you have `CYBERCavalry_v1.0.0_YYYY.MM.DD_N.zip` on the host:

```powershell
# Run in elevated PowerShell
$InstallDir = "C:\CYBERCavalry"
$ZipPath    = "$env:USERPROFILE\Downloads\CYBERCavalry_v1.0.0_*.zip"

# Extract
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Expand-Archive -Path (Get-Item $ZipPath).FullName -DestinationPath $env:TEMP\cc-extract -Force
Copy-Item -Path "$env:TEMP\cc-extract\CYBERCavalry\*" -Destination $InstallDir -Recurse -Force
Remove-Item -Recurse -Force "$env:TEMP\cc-extract"

# Verify layout
Get-ChildItem $InstallDir
```

---

## 3. Virtualenv and Dependencies (Offline)

```powershell
Set-Location C:\CYBERCavalry

# Fresh venv
python -m venv venv

# Detect Python major.minor so we pick the right wheel bundle (py39 / py311)
$PyTag = "py" + (& .\venv\Scripts\python.exe -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')").Trim()
$WheelsDir = "C:\CYBERCavalry\deploy\wheels\$PyTag"

Write-Host "Wheel set: $PyTag  (from $WheelsDir)"
if (-not (Test-Path $WheelsDir)) {
    Write-Error "Wheel directory missing: $WheelsDir"
    exit 1
}

# Upgrade pip from the wheel bundle
.\venv\Scripts\pip install --no-index --find-links "$WheelsDir\" --upgrade pip

# Install every dependency including waitress (Windows WSGI runner)
.\venv\Scripts\pip install --no-index --find-links "$WheelsDir\" `
    -r requirements.txt waitress

# Verify
.\venv\Scripts\pip list | Select-Object -First 20
```

> If pip complains about missing wheels, the bundle probably shipped only
> `manylinux` wheels — some pure-Python packages are cross-platform, but
> a few need Windows wheels. Re-run
> `python deploy/prepare_offline_bundle.py --py 311 --platform win_amd64`
> on your connected workstation (or fetch missing wheels directly with
> `pip download --platform win_amd64 --only-binary :all: <pkg>`).

---

## 4. `.env` Configuration

```powershell
# Create a fresh SECRET_KEY and FIELD_ENCRYPTION_KEY
$SecretKey = & .\venv\Scripts\python.exe -c @"
import secrets, string
chars = string.ascii_letters + string.digits + '!@#$%^&*(-_=+)'
print(''.join(secrets.choice(chars) for _ in range(64)))
"@

$FieldKey = & .\venv\Scripts\python.exe -c @"
import secrets, string
chars = string.ascii_letters + string.digits + '!@#$%^&*(-_=+)'
print(''.join(secrets.choice(chars) for _ in range(64)))
"@

$ServerIP = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual `
              | Where-Object { $_.IPAddress -notlike '169.254*' } `
              | Select-Object -First 1).IPAddress

# Write .env (overwrite mode — remove `-Force` to preserve an existing file)
@"
SECRET_KEY=$SecretKey
FIELD_ENCRYPTION_KEY=$FieldKey
DEBUG=False
ALLOWED_HOSTS=$ServerIP,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://$ServerIP,https://127.0.0.1

# Uncomment when a reverse proxy sits in front
# SECURE_SSL_REDIRECT=True

# Redis (uncomment if Memurai/WSL Redis is running)
# REDIS_URL=redis://127.0.0.1:6379/1

ADMIN_ALLOWED_IPS=127.0.0.1,::1

SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem
"@ | Out-File -Encoding utf8 -FilePath .env -Force
```

---

## 5. SSL Certificate

### Development / internal network (self-signed)

```powershell
.\venv\Scripts\python.exe generate_cert.py
```

### Production (real CA-signed certificate)

Place your PEM files under `C:\CYBERCavalry\certs\`:

```powershell
Copy-Item fullchain.pem C:\CYBERCavalry\certs\cert.pem
Copy-Item privkey.pem   C:\CYBERCavalry\certs\key.pem
# Restrict private-key access to Administrators + SYSTEM
icacls C:\CYBERCavalry\certs\key.pem /inheritance:r /grant:r "Administrators:F" "SYSTEM:F"
```

---

## 6. Database, Cache Table, Seed, Static

```powershell
Set-Location C:\CYBERCavalry
.\venv\Scripts\python.exe manage.py migrate
.\venv\Scripts\python.exe manage.py createcachetable
.\venv\Scripts\python.exe manage.py seed_initial_data
.\venv\Scripts\python.exe manage.py collectstatic --noinput
.\venv\Scripts\python.exe manage.py createsuperuser
```

---

## 7. Firewall

```powershell
# Elevated PowerShell
New-NetFirewallRule -DisplayName "CYBERCavalry HTTPS" `
    -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

---

## 8. Install as a Windows Service (WinSW)

WinSW wraps any executable into a native Windows service. It is a
single self-contained `.exe` — no dependencies.

### 8.1 Fetch WinSW

Download `WinSW-x64.exe` from https://github.com/winsw/winsw/releases
(pick the latest v2.x or v3.x) and copy it to
`C:\CYBERCavalry\deploy\windows\CYBERCavalry.exe` (rename intentional —
WinSW picks up its config file by matching its own filename).

The XML config in this folder (`cybercavalry-service.xml`) already
targets waitress. Copy/rename alongside the exe:

```powershell
Set-Location C:\CYBERCavalry\deploy\windows
Copy-Item cybercavalry-service.xml CYBERCavalry.xml
```

### 8.2 Install and start the service

```powershell
Set-Location C:\CYBERCavalry\deploy\windows
.\CYBERCavalry.exe install
.\CYBERCavalry.exe start
Get-Service CYBERCavalry
```

### 8.3 Service management cheatsheet

```powershell
Get-Service CYBERCavalry                  # current status
Start-Service CYBERCavalry
Stop-Service CYBERCavalry
Restart-Service CYBERCavalry
Get-Content C:\CYBERCavalry\logs\service.wrapper.log -Wait   # live wrapper log
Get-Content C:\CYBERCavalry\logs\cybercavalry.log -Wait      # application log
```

---

## 9. Browser Access

```
https://<server-ip>:8443/
```

Self-signed certificate → your browser will warn on the first visit; add
a permanent exception (dev/eval) or install the real certificate.

---

## 10. Update Workflow

Use the accompanying [`update_windows.ps1`](update_windows.ps1) script,
or perform the same steps manually:

```powershell
# Elevated PowerShell
Set-Location C:\CYBERCavalry

Stop-Service CYBERCavalry
# ... extract the new zip into a temp folder, then robocopy across
# excluding .env / certs / logs / db / venv (see update_windows.ps1)
.\venv\Scripts\pip install --no-index --find-links deploy\wheels\py311\ `
    --upgrade -r requirements.txt waitress
.\venv\Scripts\python.exe manage.py migrate --noinput
.\venv\Scripts\python.exe manage.py collectstatic --noinput
Start-Service CYBERCavalry
```

---

## 11. Troubleshooting

| Symptom                                              | Fix |
|------------------------------------------------------|-----|
| Service stuck at "Starting"                          | `Get-Content C:\CYBERCavalry\logs\service.wrapper.log -Tail 60` |
| `Address already in use`                             | `Get-NetTCPConnection -LocalPort 8443` |
| `Permission denied: certs\key.pem`                   | Re-run the `icacls` command from step 5 |
| `OperationalError: no such table`                    | `.\venv\Scripts\python.exe manage.py migrate` |
| Admin page returns 404                               | Update `ADMIN_ALLOWED_IPS` in `.env` |
| CSRF 403 in the browser                              | Check `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` in `.env` |
| PowerShell script blocked                            | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| `No matching distribution found`                     | Make sure step 0 ran with the same Python major.minor as the target host |

---

## 12. Notes

- **Waitress vs. gunicorn.** Waitress is a pure-Python multi-threaded
  WSGI server maintained by the Pylons project. It handles concurrency
  via threads (default 4), not worker processes — perfect for Windows,
  and it plays nice with APScheduler (which must not be duplicated
  across workers).
- **Single-process only.** As with the Linux setup, don't run more than
  one CYBERCavalry service on the same host — APScheduler runs
  in-process; multiple copies would fire each job multiple times.
- **PostgreSQL.** Same as Linux: set
  `DATABASE_URL=postgres://user:pass@host/dbname` in `.env`, then
  `pip install psycopg2-binary` and re-run `manage.py migrate`.
