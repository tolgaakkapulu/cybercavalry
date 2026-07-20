# Deployment Guide

One script per platform, one command each — that's the whole installer.

```
deploy/
├── README.md                       ← you are here
├── prepare_offline_bundle.py       ← downloads Python wheels (cross-platform)
├── wheels/                         ← generated
├── linux/
│   ├── setup.sh                    ← install + update (RHEL & Debian)
│   └── cybercavalry.service        ← systemd unit
└── windows/
    ├── setup.ps1                   ← install + update (Windows 10+/Server 2019+)
    └── cybercavalry-service.xml    ← WinSW config
```

---

## Prerequisites

Before running `setup.sh` / `setup.ps1`, the **target host** needs:

| Requirement | Linux | Windows |
|---|---|---|
| Python 3.9+ | `dnf/apt install python3 python3-venv` | [python.org installer](https://www.python.org/downloads/windows/), "Add to PATH" |
| unzip | `dnf/apt install unzip` | built-in |
| Release zip | placed under `/home/cavalry.svc/` | project extracted to `C:\CYBERCavalry\` |
| Wheel bundle | inside `deploy/wheels/` (see below) | same |
| (Windows only) WinSW | — | `WinSW-x64.exe` renamed to `CYBERCavalry.exe` under `deploy\windows\` — [download](https://github.com/winsw/winsw/releases) |

**Prepare the offline wheel bundle** on a machine that HAS internet, then copy `deploy/` to the offline target:

```bash
python deploy/prepare_offline_bundle.py           # Python 3.9 + 3.11
python deploy/prepare_offline_bundle.py --py 311  # 3.11 only
```

---

## 🐧 Linux — RHEL / AlmaLinux / Rocky / Debian / Ubuntu

The script auto-detects your distro (RHEL vs Debian family) and handles
`dnf`/`apt`, `firewalld`/`ufw`, SELinux (RHEL only) accordingly.

**Fresh install:**
```bash
sudo bash deploy/linux/setup.sh install
```

**Update (preserves `.env`, database, certificates, logs, backups):**
```bash
sudo bash deploy/linux/setup.sh update
```

Both commands end with a health check — if the service doesn't come up
you'll see the last 30 lines of `journalctl` in your terminal.

**After first install** — create the superuser (interactive):
```bash
sudo -u cavalry /data/cybercavalry/venv/bin/python /data/cybercavalry/manage.py createsuperuser
```

---

## 🪟 Windows — Server 2019 / 2022 / Windows 10 / 11

**One-shot install (elevated PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action install
```

**Update:**
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action update
```

The `-ExecutionPolicy Bypass` bit is a one-shot exception — nothing
persistent is changed. Alternatively, run this once and drop the flag:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
Get-ChildItem -Path .\deploy\ -Recurse | Unblock-File
```
(`Unblock-File` strips the "downloaded from internet" tag `git clone`
adds — needed once for `RemoteSigned` to accept the scripts.)

**After first install** — create the superuser:
```powershell
cd C:\CYBERCavalry
.\venv\Scripts\python.exe manage.py createsuperuser
```

---

## Access After Install

- **URL:** `https://<server-ip>:8443/`
- **Service:**
  - Linux:   `sudo systemctl status cybercavalry` · `sudo journalctl -u cybercavalry -f`
  - Windows: `Get-Service CYBERCavalry` · `Get-Content C:\CYBERCavalry\logs\service.wrapper.log -Wait`
- **Log files:** `logs/cybercavalry.log` · `logs/access.log` · `logs/error.log`
- **First-run configuration:** log in as the superuser you just created,
  then set your AbuseIPDB / VirusTotal keys, SMTP, LDAP, brand color etc.
  from Settings.

---

## What Gets Preserved on Update

Both `setup.sh update` and `setup.ps1 -Action update` keep everything
under these paths untouched:

- `.env` (secrets, database URL, LDAP config)
- `venv/` (rebuilt only if pip is broken)
- `certs/` (your TLS certificates)
- `logs/` (rotated log files)
- `backups/` (DB snapshots)
- `cybercavalry.db*` (SQLite database, if used)

Everything else is overwritten with the new release content.

A rollback snapshot is written to `/data/rollback/<timestamp>` (Linux)
or `C:\CYBERCavalry-rollback\<timestamp>` (Windows) so you can undo a
bad upgrade by restoring that directory with `rsync`/`robocopy`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `service failed to start` | `sudo journalctl -u cybercavalry -n 100` (Linux) / `Get-Content C:\CYBERCavalry\logs\service.wrapper.log -Tail 100` (Windows) |
| `No CYBERCavalry_v*.zip` | Copy the release zip to `/home/cavalry.svc/` (Linux) or `$env:USERPROFILE\Downloads` (Windows update) |
| `Wheel bundle missing` | Re-run `python deploy/prepare_offline_bundle.py` on your connected workstation with the same Python major.minor as the target host |
| `File ... cannot be loaded` (Windows) | Use `powershell -ExecutionPolicy Bypass -File .\setup.ps1 ...` |
| `File ... is not digitally signed` (Windows) | `Get-ChildItem -Path deploy\ -Recurse \| Unblock-File`, then re-run |
| `Permission denied` on `certs/key.pem` | Linux: `chown cavalry:cavalry certs/*.pem` — Windows: `icacls certs\key.pem /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F'` |
| SELinux AVC denial (RHEL) | `sudo ausearch -m AVC -ts recent` — the installer applies labels automatically, but if you moved the install dir manually run `sudo restorecon -Rv /data/cybercavalry/venv` |

---

## Notes

- **Worker count is 1** on both platforms because APScheduler runs
  in-process; extra workers would double up scheduled jobs. Raise
  threads (`--threads` on Linux gunicorn, `--threads` on Windows
  waitress) if you need more concurrency.
- **Redis is optional.** When absent, Django's `DatabaseCache` handles
  the rate-limit / lockout store instead — perfectly fine for a single
  node.
- **Reverse proxy?** If you put nginx/Caddy/IIS in front:
  set `SECURE_SSL_REDIRECT=True` in `.env`, strip the `--certfile`
  arguments from the service (Linux) or from the WinSW XML (Windows),
  and add the proxy IP to `TRUSTED_PROXIES`.
