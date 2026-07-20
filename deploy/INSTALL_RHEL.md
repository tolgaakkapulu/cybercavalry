# CYBER Cavalry — Red Hat Linux Installation Guide

This document covers running CYBER Cavalry on **RHEL 9.5** (or AlmaLinux/Rocky
Linux 9.x) as a service managed by `systemctl start cybercavalry`.
It **assumes the target host has no internet access** — required packages are
prepared on an external machine and transferred over.

Architecture:

```
client  ─HTTPS(8443)─►  gunicorn (cybercavalry.service)  ─►  Django WSGI
                              │
                              ├─ SQLite or PostgreSQL
                              └─ Redis (cache & rate-limit)
```

| Parameter          | Value                       |
|--------------------|-----------------------------|
| Target OS          | RHEL 9.5 (offline)          |
| Python             | 3.11                        |
| Service user       | `cavalry`                   |
| Install directory  | `/data/cybercavalry`        |
| Service name       | `cybercavalry.service`      |
| Listening port     | `8443/tcp` (HTTPS)          |

---

## 0. Preparation — On a Connected Machine (Windows / Linux / macOS)

These steps run **on your development machine**. The resulting zip archive is
transferred to the target RHEL 9.5 server via USB / network share.

### 0.1 Collect Python wheel packages

```powershell
# Windows PowerShell:
cd "C:\...\CYBERCavalry"
python deploy\prepare_offline_bundle.py
```

```bash
# Linux/macOS:
cd /path/to/CYBERCavalry
python3 deploy/prepare_offline_bundle.py
```

The script downloads `manylinux_2_28` wheels targeting RHEL 9 / Python 3.11 /
x86_64 into `deploy/wheels/` (~60-100 MB) and generates `deploy/wheels.lock.txt`.

### 0.2 Collect system RPMs *(optional — only if the target RHEL has no offline repo)*

Run this on **a RHEL 9.5 VM with internet access** (RPMs cannot be downloaded
from Windows — they are RHEL-specific):

```bash
mkdir -p rpms
sudo dnf install -y --downloadonly --downloaddir=rpms \
    python3.11 python3.11-pip python3.11-devel \
    gcc make openssl-devel libffi-devel \
    redis git tar unzip \
    policycoreutils-python-utils firewalld
```

> If you do not have a RHEL subscription, you can use an AlmaLinux/Rocky 9.5
> VM — the same package names apply.

### 0.3 Archive everything into a single zip

```powershell
python manage_server.py release
```

This produces `VERSIONS/CYBERCavalry_v1.0.0_YYYY.MM.DD_N.zip`;
the `deploy/wheels/` directory is included in the archive automatically.
Transfer the RPMs separately.

---

## 1. System Packages (Target RHEL 9.5)

**If the target machine has a local Satellite/repo:**
```bash
sudo dnf install -y \
    python3.11 python3.11-pip python3.11-devel \
    gcc make openssl-devel libffi-devel \
    redis git tar unzip \
    policycoreutils-python-utils firewalld
```

**Fully offline** (if you brought the RPMs from step 0.2):
```bash
# After copying the RPMs to the server:
cd /tmp/rpms
sudo dnf install -y --disablerepo='*' ./*.rpm
```

> RHEL 9.5 ships the Python 3.11 AppStream module — it can be installed directly.

---

## 2. Service User

```bash
sudo useradd --system --home-dir /data/cybercavalry \
    --shell /sbin/nologin --comment "CYBER Cavalry service user" cavalry
```

---

## 3. Deploying the Project

```bash
# (a) From the zip archive:
sudo mkdir -p /data/cybercavalry
sudo unzip CYBERCavalry_v1.0.0_*.zip -d /tmp/cybercavalry
sudo cp -r /tmp/cybercavalry/CYBERCavalry/. /data/cybercavalry/
sudo rm -rf /tmp/cybercavalry

# (b) or from git:
# sudo -u cavalry git clone https://your-repo/CYBERCavalry.git /data/cybercavalry

sudo chown -R cavalry:cavalry /data/cybercavalry
sudo chmod 750 /data/cybercavalry
sudo install -d -o cavalry -g cavalry -m 750 /data/cybercavalry/logs /data/cybercavalry/certs
```

---

## 4. Virtualenv and Dependencies (Offline)

The bundle you prepared in step 0.1 contains two separate wheel sets:

```
/data/cybercavalry/deploy/wheels/
    ├── py39/      ← for RHEL 9.x default Python (3.9)
    └── py311/     ← if you installed python3.11 from AppStream
```

The correct directory is **selected automatically** based on the target
machine's Python version:

```bash
# Which Python? (RHEL 9 default = 3.9, AppStream python3.11 = 3.11)
PY_TAG=py$(python3 -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
echo "Target wheel set: $PY_TAG"   # py39 or py311

# Remove any stale/broken venv
sudo rm -rf /data/cybercavalry/venv

# Create the venv (uses the system python3)
sudo -u cavalry python3 -m venv /data/cybercavalry/venv

# Upgrade pip from wheels/ (no internet required)
sudo -u cavalry /data/cybercavalry/venv/bin/pip install \
    --no-index --find-links /data/cybercavalry/deploy/wheels/$PY_TAG/ \
    --upgrade pip

# Install all dependencies (including gunicorn) offline
sudo -u cavalry /data/cybercavalry/venv/bin/pip install \
    --no-index --find-links /data/cybercavalry/deploy/wheels/$PY_TAG/ \
    -r /data/cybercavalry/requirements.txt gunicorn

# Verify
sudo -u cavalry /data/cybercavalry/venv/bin/pip list
```

> **Note — `manage_server.py setup` does not work on Linux.** That script is
> for Windows (it looks for `venv/Scripts/python.exe`). On Linux, always use
> the manual commands in this guide.

> If you get a missing-wheel error: check whether your target Python version
> is in the bundle (`ls /data/cybercavalry/deploy/wheels/`).
> If not, add it on the connected machine with
> `python deploy/prepare_offline_bundle.py --py 39`.

---

## 5. `.env` Configuration

```bash
# Copy the template (or create it by hand if absent)
sudo -u cavalry cp /data/cybercavalry/.env.example /data/cybercavalry/.env 2>/dev/null || \
    sudo -u cavalry touch /data/cybercavalry/.env
sudo chmod 640 /data/cybercavalry/.env

# Fresh SECRET_KEY
NEW_KEY=$(sudo -u cavalry /data/cybercavalry/venv/bin/python -c \
"import secrets,string; \
chars=string.ascii_letters+string.digits+'!@#\$%^&*(-_=+)'; \
print(''.join(secrets.choice(chars) for _ in range(64)))")

# Write/update the following lines in .env
sudo -u cavalry tee /data/cybercavalry/.env >/dev/null <<EOF
SECRET_KEY=${NEW_KEY}
DEBUG=False
ALLOWED_HOSTS=cavalry.example.com,$(hostname -I | awk '{print $1}'),127.0.0.1

# Set to True if you later add a reverse proxy in front
SECURE_SSL_REDIRECT=False

# Redis (optional but recommended — DatabaseCache is the fallback)
REDIS_URL=redis://127.0.0.1:6379/1

# Admin panel access (only these IPs see anything other than 404)
ADMIN_ALLOWED_IPS=127.0.0.1,::1

# Certificate paths
SSL_CERT_FILE=certs/cert.pem
SSL_KEY_FILE=certs/key.pem
EOF
```

---

## 6. SSL Certificate

### Development / internal network (self-signed)

```bash
sudo -u cavalry /data/cybercavalry/venv/bin/python /data/cybercavalry/generate_cert.py
```

### Production (real CA-signed certificate)

```bash
sudo install -o cavalry -g cavalry -m 644 fullchain.pem /data/cybercavalry/certs/cert.pem
sudo install -o cavalry -g cavalry -m 600 privkey.pem   /data/cybercavalry/certs/key.pem
```

---

## 7. Database, Cache Table, Seed, Static

```bash
cd /data/cybercavalry
sudo -u cavalry ./venv/bin/python manage.py migrate
sudo -u cavalry ./venv/bin/python manage.py createcachetable
sudo -u cavalry ./venv/bin/python manage.py seed_initial_data
sudo -u cavalry ./venv/bin/python manage.py collectstatic --noinput
sudo -u cavalry ./venv/bin/python manage.py createsuperuser
```

---

## 8. Enable Redis

```bash
sudo systemctl enable --now redis
sudo systemctl status redis
```

---

## 9. Install the systemd Service

```bash
sudo cp /data/cybercavalry/deploy/cybercavalry.service /etc/systemd/system/cybercavalry.service
sudo systemctl daemon-reload
sudo systemctl enable cybercavalry
sudo systemctl start cybercavalry
sudo systemctl status cybercavalry
```

---

## 10. Firewall (firewalld)

```bash
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

---

## 11. SELinux

`/data` is not a standard Linux path — SELinux labels it `default_t` and
systemd cannot execute binaries from that type. Therefore the venv binaries
and libraries must be given the correct labels by hand.

```bash
# Allow HTTPS on port 8443
sudo semanage port -a -t http_port_t -p tcp 8443 2>/dev/null || \
    sudo semanage port -m -t http_port_t -p tcp 8443

# venv binaries (gunicorn, python, pip) — bin_t
sudo semanage fcontext -a -t bin_t "/data/cybercavalry/venv/bin(/.*)?"

# venv libraries (.so files, site-packages) — lib_t
sudo semanage fcontext -a -t lib_t "/data/cybercavalry/venv/lib(/.*)?"
sudo semanage fcontext -a -t lib_t "/data/cybercavalry/venv/lib64(/.*)?"

# Log directory — var_log_t
sudo semanage fcontext -a -t var_log_t "/data/cybercavalry/logs(/.*)?"

# Apply all labels
sudo restorecon -Rv /data/cybercavalry/venv
sudo restorecon -Rv /data/cybercavalry/logs

# Verification — gunicorn should be bin_t
ls -lZ /data/cybercavalry/venv/bin/gunicorn

# If something goes wrong, check the AVC denials:
#   sudo ausearch -m AVC -ts recent
#   sudo sealert -l '*' | head -50
# For temporary diagnostics (NOT A PERMANENT FIX):
#   sudo setenforce 0
```

> If you deploy under `/opt/cybercavalry` instead, this venv-labeling step is
> not required — the SELinux default policy handles venvs under `/opt`
> correctly.

---

## 12. Service Management

```bash
sudo systemctl start    cybercavalry   # Start
sudo systemctl stop     cybercavalry   # Stop
sudo systemctl restart  cybercavalry   # Restart
sudo systemctl reload   cybercavalry   # Graceful worker reload (SIGHUP)
sudo systemctl status   cybercavalry   # Current status
sudo systemctl disable  cybercavalry   # Disable on boot
sudo journalctl -u cybercavalry -f     # Live log stream
```

Application logs:

```bash
tail -f /data/cybercavalry/logs/cybercavalry.log
tail -f /data/cybercavalry/logs/access.log
tail -f /data/cybercavalry/logs/error.log
```

Browser access:

```
https://<server-ip>:8443/
```

---

## 13. Update Workflow (Offline)

Prepare the new version on the connected machine → move the zip via USB →
extract on the target server.

```bash
# On the target RHEL 9.5 server:
sudo systemctl stop cybercavalry
sudo unzip -o /tmp/CYBERCavalry_v1.0.1_*.zip -d /tmp/cybercavalry
sudo -u cavalry rsync -a --delete \
    --exclude '.env' --exclude 'venv/' --exclude 'certs/' \
    --exclude 'logs/' --exclude 'cybercavalry.db' \
    /tmp/cybercavalry/CYBERCavalry/ /data/cybercavalry/

# If dependencies changed, refresh the packages offline
sudo -u cavalry /data/cybercavalry/venv/bin/pip install \
    --no-index --find-links /data/cybercavalry/deploy/wheels/ \
    --upgrade -r /data/cybercavalry/requirements.txt gunicorn

sudo systemctl start cybercavalry   # ExecStartPre runs migrate + collectstatic automatically
sudo systemctl status cybercavalry
```

---

## 14. Troubleshooting

| Symptom                                  | Fix |
|------------------------------------------|-----|
| `Active: failed`                         | `journalctl -u cybercavalry -n 100` |
| `Address already in use`                 | `ss -tlnp \| grep 8443` to find the conflicting process |
| `Permission denied: certs/key.pem`       | `chown cavalry:cavalry certs/* && chmod 600 certs/key.pem` |
| `OperationalError: no such table`        | `sudo -u cavalry venv/bin/python manage.py migrate` |
| Admin page returns 404                   | Update the `ADMIN_ALLOWED_IPS` list in `.env` |
| CSRF 403 in the browser                  | Check `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` in `.env` |
| SELinux AVC denial                       | `ausearch -m AVC -ts recent`; derive a policy with `audit2allow` |
| `SELinux is preventing ... execute access on gunicorn` | Missing venv labels — run the `bin_t`/`lib_t` steps in section 11 |
| APScheduler jobs fire twice              | Ensure `--workers` is **1** in `cybercavalry.service` |
| `connection refused` (Redis)             | `systemctl status redis`; is `REDIS_URL` in `.env` correct? |
| `No matching distribution found`         | Make sure you ran 0.1 with **Python 3.11**; cross-check against `deploy/wheels.lock.txt` |
| `Could not fetch URL` (pip)              | The `--no-index` flag was forgotten; the command should include `--no-index --find-links deploy/wheels/` |

---

## 15. Notes

- **Offline bundle:** `deploy/prepare_offline_bundle.py` must be re-run every
  time `requirements.txt` changes; otherwise dependency resolution fails on
  the target. The `deploy/wheels/` directory must always travel together with
  `wheels.lock.txt`.
- **Worker count is 1** because APScheduler runs in-process; with multiple
  workers each worker starts its own scheduler and jobs fire repeatedly. If
  you need more concurrency, raise `--threads` instead.
- If you later add a reverse proxy (nginx/HAProxy): switch gunicorn to
  `--bind 127.0.0.1:8000` (HTTP), drop the certificate arguments, set
  `SECURE_SSL_REDIRECT=True` in `.env`, and add the proxy IP to the
  `TRUSTED_PROXIES` list.
- To move to PostgreSQL: set `DATABASE_URL=postgres://user:pass@host/dbname`
  in `.env`, then `pip install psycopg2-binary && manage.py migrate`.
