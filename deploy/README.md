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
| Python **3.9 or 3.11** (must match a shipped wheel bundle — see note below) | `dnf install python3.11` / `apt install python3.11 python3.11-venv` | [python.org 3.11 installer](https://www.python.org/downloads/release/python-3119/), tick **"Add to PATH"** |
| unzip | `dnf/apt install unzip` | built-in |
| Release zip | placed under `/home/cavalry.svc/` | project extracted to `C:\CYBERCavalry\` |
| Wheel bundle | inside `deploy/wheels/` (see below) | same |
| (Windows only) WinSW | — | `WinSW-x64.exe` renamed to `CYBERCavalry.exe` under `deploy\windows\` — [download](https://github.com/winsw/winsw/releases) |

> **Why 3.9 or 3.11 specifically?** The offline wheel bundle in this
> repository is prepared for exactly these two versions (matching RHEL
> 9's default `python3` and its AppStream `python3.11`). If your target
> runs anything else — 3.10, 3.12, 3.13, 3.14 — you have two choices:
> install a matching interpreter, or regenerate the bundle with
> `python deploy/prepare_offline_bundle.py --py <XY>` on a connected
> workstation. The setup script will refuse to continue with a message
> listing the available bundles if there's a mismatch.

**Prepare the offline wheel bundle** on a machine that HAS internet, then copy `deploy/` to the offline target:

```bash
python deploy/prepare_offline_bundle.py           # Python 3.9 + 3.11
python deploy/prepare_offline_bundle.py --py 311  # 3.11 only
python deploy/prepare_offline_bundle.py --py 312  # add 3.12 to the bundle
```

---

## 🐧 Linux — RHEL / Debian / Ubuntu

The script auto-detects your distro (RHEL vs Debian family) and handles
`dnf`/`apt`, `firewalld`/`ufw`, SELinux (RHEL only) accordingly. It also
auto-detects whether it's being run from a **git clone** (dev/eval flow)
or against a **release zip** in `--zip-source` (air-gapped production).

**Fresh install from a git clone:**
```bash
git clone https://github.com/tolgaakkapulu/CYBERCavalry.git
cd CYBERCavalry
sudo bash deploy/linux/setup.sh install
```
The script rsyncs the checkout into `/data/cybercavalry` (default) and
takes it from there. Pass `--install-dir /opt/cybercavalry` (or any
path) to install to a different location.

**Fresh install from a release zip (air-gapped / production):**
```bash
# Drop CYBERCavalry_v*.zip into /home/cavalry.svc/ first
sudo bash deploy/linux/setup.sh install
```

**Update (preserves `.env`, database, certificates, logs, backups):**
```bash
cd CYBERCavalry           # inside the git checkout
sudo bash deploy/linux/setup.sh update
```

**Custom install directory / zip source (both actions):**
```bash
sudo bash deploy/linux/setup.sh install \
    --install-dir /opt/cybercavalry \
    --zip-source  /tmp/releases

sudo bash deploy/linux/setup.sh update \
    --install-dir /opt/cybercavalry \
    --zip-source  /tmp/releases
```

Every knob is a `--flag value` pair — `--install-dir`, `--zip-source`,
`--rollback-dir`, `--https-port`, `--service-user`, `--service-name`,
`--reinstall-deps`. Run `sudo bash deploy/linux/setup.sh --help` for the
full list.

**Fast updates skip pip.** `setup.sh update` no longer runs pip by
default — the existing venv already holds every package needed for
runtime, and touching pip on an air-gapped box just risks hanging on
wheels / PyPI. The update flow is: stop → sync code → migrate →
collectstatic → clear `__pycache__` → restart. Pass `--reinstall-deps`
explicitly when `requirements.txt` actually gained or dropped a package,
and only then do you need `deploy/wheels/` (or PyPI reachability). The
script warns you at update-time when `requirements.txt` has changed
since the last install so you know when to pass the flag.

Both commands end with a health check — if the service doesn't come up
you'll see the last 30 lines of `journalctl` in your terminal.

**After first install** — a default administrator is seeded automatically:

| username | password | role  |
| -------- | -------- | ----- |
| `admin`  | `admin`  | admin |

Log in at `https://<server-ip>:8443/` and change the password **immediately** under
your profile → *Change password*. The `seed_initial_data` step runs on every
install; on re-runs the existing user is preserved.

---

## 🪟 Windows — Server 2019 / 2022 / Windows 10 / 11

**One-shot install from a git clone (elevated PowerShell):**
```powershell
git clone https://github.com/tolgaakkapulu/CYBERCavalry.git
cd CYBERCavalry
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action install
```
When `-InstallDir` is omitted the script auto-detects the project root
from its own location, so the checkout you just cloned is what gets
installed — no extra flag needed.

If you keep multiple Python versions on the box, point at the one you want:
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 `
    -Action install `
    -PythonExe 'C:\Users\<you>\AppData\Local\Programs\Python\Python311\python.exe'
```

Every knob is a PowerShell parameter — override as needed:
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 `
    -Action install `
    -InstallDir 'D:\CYBERCavalry' `
    -HttpsPort  9443 `
    -PythonExe  'py -3.11'

powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 `
    -Action update `
    -InstallDir  'D:\CYBERCavalry' `
    -ZipSource   'D:\releases' `
    -RollbackDir 'D:\CYBERCavalry-rollback'
```

The setup script tries three strategies automatically:
1. **No wheel bundle for your Python** — installs directly from PyPI (typical dev/eval)
2. **Bundle exists and complete** — fully offline install
3. **Bundle exists but missing wheels** (usually a Linux bundle on Windows) — offline + PyPI fallback

For a truly air-gapped Windows install, generate a Windows-native bundle on a
connected machine first:
```powershell
python .\deploy\prepare_offline_bundle.py --os windows --py 311
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

**After first install** — a default administrator is seeded automatically
(`admin` / `admin`). Log in at `https://<server-ip>:8443/` and change the
password **immediately** under your profile → *Change password*.

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
- `media/` (uploaded brand logo / background / login image)
- `deploy/wheels/` (offline wheel bundle — an incoming zip with an empty `wheels/` no longer wipes what's on the target)

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
| `Wheel bundle missing` | Only surfaces when you passed `--reinstall-deps` (or the venv was so broken it had to be rebuilt). Re-run `python deploy/prepare_offline_bundle.py` on your connected workstation with the same Python major.minor as the target host |
| `unexpected zip layout` | Rebuild the release with `python manage_server.py release` — the current builder always writes the top-level folder as `CYBERCavalry/`, regardless of your local dev directory name |
| `install_deps: entering` never appears in update log | Update is skipping pip by design; that message only prints when pip actually runs (broken venv or `--reinstall-deps`) |
| `File ... cannot be loaded` (Windows) | Use `powershell -ExecutionPolicy Bypass -File .\setup.ps1 ...` |
| `File ... is not digitally signed` (Windows) | `Get-ChildItem -Path deploy\ -Recurse \| Unblock-File`, then re-run |
| `Permission denied` on `certs/key.pem` | Linux: `chown cavalry:cavalry certs/*.pem` — Windows: `icacls certs\key.pem /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F'` |
| SELinux AVC denial (RHEL) | `sudo ausearch -m AVC -ts recent` — the installer applies labels automatically, but if you moved the install dir manually run `sudo restorecon -Rv /data/cybercavalry/venv` |

---

## Notes

- **Worker count is 1** on both platforms because APScheduler runs
  in-process; extra workers would double up scheduled jobs. Raise
  threads (`--threads` on Linux gunicorn) or worker concurrency on
  Windows (hypercorn ASGI, native TLS on 8443) if you need more.
- **Redis is optional.** When absent, Django's `DatabaseCache` handles
  the rate-limit / lockout store instead — perfectly fine for a single
  node.
- **Reverse proxy?** If you put nginx/Caddy/IIS in front:
  set `SECURE_SSL_REDIRECT=True` in `.env`, strip the `--certfile`
  arguments from the service (Linux) or from the WinSW XML (Windows),
  and add the proxy IP to `TRUSTED_PROXIES`.
