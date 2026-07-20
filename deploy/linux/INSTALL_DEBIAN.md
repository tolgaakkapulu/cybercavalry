# CYBER Cavalry — Debian / Ubuntu Installation Guide

This document covers running CYBER Cavalry on **Debian 12+** or
**Ubuntu 22.04+** as a service managed by `systemctl start cybercavalry`.
It **assumes the target host has no internet access** — required
packages are prepared on an external machine and transferred over.

Architecture:

```
client  ─HTTPS(8443)─►  gunicorn (cybercavalry.service)  ─►  Django WSGI
                              │
                              ├─ SQLite or PostgreSQL
                              └─ Redis (cache & rate-limit)
```

| Parameter          | Value                       |
|--------------------|-----------------------------|
| Target OS          | Debian 12 / 13, Ubuntu 22.04 / 24.04 |
| Python             | 3.11 (or 3.12)              |
| Service user       | `cavalry`                   |
| Install directory  | `/data/cybercavalry`        |
| Service name       | `cybercavalry.service`      |
| Listening port     | `8443/tcp` (HTTPS)          |

> **Debian vs. RHEL** — the main practical differences the scripts
> handle for you:
> - `apt` instead of `dnf`
> - No SELinux — Debian's default AppArmor profiles do not restrict
>   what CYBERCavalry needs
> - `ufw` instead of `firewalld`
> - Service user shell is `/usr/sbin/nologin`
> - Redis service is named `redis-server`

---

## 0. Preparation — On a Connected Machine (Windows / Linux / macOS)

Identical to the RHEL flow — the offline wheel bundle is cross-distro
as long as the same Python major.minor is on both sides. See
[`deploy/README.md`](../README.md) for the shared bundling step.

```bash
python deploy/prepare_offline_bundle.py             # both Python 3.9 and 3.11
python deploy/prepare_offline_bundle.py --py 311    # only 3.11
```

The wheels live under `deploy/wheels/py39/` and `deploy/wheels/py311/`;
copy the whole `deploy/wheels/` tree to the target Debian host along
with the release zip.

---

## 1. System Packages (Target Debian / Ubuntu Host)

**If the target host has internet or a local apt mirror:**

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-dev \
    build-essential libssl-dev libffi-dev \
    redis-server git tar unzip ufw
```

On Debian 12 (bookworm) that gets you Python 3.11 by default. On
Ubuntu 22.04, `python3` is 3.10; add the deadsnakes PPA to install 3.11:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev
```

**Fully offline** — if you brought the `.deb` files from a connected
Debian VM, install them the same way:

```bash
# Fetch on the connected machine:
mkdir -p debs
sudo apt install --download-only -y --reinstall \
    python3 python3-venv python3-dev \
    build-essential libssl-dev libffi-dev \
    redis-server git tar unzip ufw
sudo cp /var/cache/apt/archives/*.deb debs/

# Then on the target host:
cd /tmp/debs
sudo dpkg -i *.deb
sudo apt-get install -f    # resolve any dependency issues
```

---

## 2. Service User

```bash
sudo useradd --system --home-dir /data/cybercavalry \
    --shell /usr/sbin/nologin --comment "CYBER Cavalry service user" cavalry
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

Same shape as the RHEL flow — the wheel set path picks between
`py39` and `py311` automatically:

```bash
PY_TAG=py$(python3 -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')
echo "Target wheel set: $PY_TAG"

sudo rm -rf /data/cybercavalry/venv
sudo -u cavalry python3 -m venv /data/cybercavalry/venv

sudo -u cavalry /data/cybercavalry/venv/bin/pip install \
    --no-index --find-links /data/cybercavalry/deploy/wheels/$PY_TAG/ \
    --upgrade pip

sudo -u cavalry /data/cybercavalry/venv/bin/pip install \
    --no-index --find-links /data/cybercavalry/deploy/wheels/$PY_TAG/ \
    -r /data/cybercavalry/requirements.txt gunicorn

sudo -u cavalry /data/cybercavalry/venv/bin/pip list
```

> `python3-venv` is a separate package on Debian/Ubuntu — if
> `python3 -m venv` complains about `ensurepip`, install it with
> `sudo apt install python3-venv` (or the matching `python3.11-venv`).

---

## 5. `.env` Configuration

```bash
sudo -u cavalry cp /data/cybercavalry/.env.example /data/cybercavalry/.env 2>/dev/null || \
    sudo -u cavalry touch /data/cybercavalry/.env
sudo chmod 640 /data/cybercavalry/.env

NEW_KEY=$(sudo -u cavalry /data/cybercavalry/venv/bin/python -c \
"import secrets,string; \
chars=string.ascii_letters+string.digits+'!@#\$%^&*(-_=+)'; \
print(''.join(secrets.choice(chars) for _ in range(64)))")

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
sudo systemctl enable --now redis-server
sudo systemctl status redis-server
```

---

## 9. Install the systemd Service

```bash
sudo cp /data/cybercavalry/deploy/linux/cybercavalry.service /etc/systemd/system/cybercavalry.service
sudo systemctl daemon-reload
sudo systemctl enable cybercavalry
sudo systemctl start cybercavalry
sudo systemctl status cybercavalry
```

---

## 10. Firewall (ufw)

```bash
sudo ufw allow 8443/tcp
sudo ufw enable    # only if it's not already active
sudo ufw status
```

If you use `nftables` or `iptables` directly instead, open TCP/8443
with your usual tooling — no distro-specific magic required.

---

## 11. AppArmor (usually nothing to do)

Debian/Ubuntu ship AppArmor by default. CYBERCavalry runs entirely
inside its venv, reads/writes only under `/data/cybercavalry/`, and
does not need any dedicated AppArmor profile. The unconfined default
covers it.

If you have a hardened host with mandatory profiles, verify with:

```bash
sudo aa-status | grep -i cavalry     # should return nothing (unconfined)
```

There is **no equivalent of the RHEL SELinux relabelling step** — you
can skip it entirely.

---

## 12. Service Management

```bash
sudo systemctl start    cybercavalry
sudo systemctl stop     cybercavalry
sudo systemctl restart  cybercavalry
sudo systemctl reload   cybercavalry
sudo systemctl status   cybercavalry
sudo systemctl disable  cybercavalry
sudo journalctl -u cybercavalry -f
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

Same shape as the RHEL update — run the accompanying
[`update_debian.sh`](update_debian.sh) script, or perform manually:

```bash
sudo systemctl stop cybercavalry
sudo unzip -o /tmp/CYBERCavalry_v1.0.1_*.zip -d /tmp/cybercavalry
sudo -u cavalry rsync -a --delete \
    --exclude '.env' --exclude 'venv/' --exclude 'certs/' \
    --exclude 'logs/' --exclude 'cybercavalry.db' \
    /tmp/cybercavalry/CYBERCavalry/ /data/cybercavalry/

sudo -u cavalry /data/cybercavalry/venv/bin/pip install \
    --no-index --find-links /data/cybercavalry/deploy/wheels/ \
    --upgrade -r /data/cybercavalry/requirements.txt gunicorn

sudo systemctl start cybercavalry
sudo systemctl status cybercavalry
```

---

## 14. Troubleshooting

| Symptom                                  | Fix |
|------------------------------------------|-----|
| `Active: failed`                         | `journalctl -u cybercavalry -n 100` |
| `Address already in use`                 | `ss -tlnp \| grep 8443` |
| `Permission denied: certs/key.pem`       | `chown cavalry:cavalry certs/* && chmod 600 certs/key.pem` |
| `OperationalError: no such table`        | `sudo -u cavalry venv/bin/python manage.py migrate` |
| Admin page returns 404                   | Update `ADMIN_ALLOWED_IPS` in `.env` |
| CSRF 403 in the browser                  | Check `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` in `.env` |
| `ensurepip is not available`             | `sudo apt install python3-venv` (or `python3.11-venv`) |
| APScheduler jobs fire twice              | Ensure `--workers` is **1** in `cybercavalry.service` |
| `connection refused` (Redis)             | `systemctl status redis-server`; is `REDIS_URL` in `.env` correct? |
| `No matching distribution found`         | Make sure step 0 ran with the same Python major.minor as the target host |
| `Could not fetch URL` (pip)              | The `--no-index` flag was forgotten; the command should include `--no-index --find-links deploy/wheels/` |

---

## 15. Notes

- **AppArmor:** Debian/Ubuntu enforce AppArmor by default; the unconfined
  profile CYBERCavalry runs under needs no changes. If you deploy under
  a mandatory profile (rare), whitelist reads/writes under
  `/data/cybercavalry/` and network sockets on TCP/8443.
- **Ubuntu 22.04 Python:** the OS ships 3.10 by default. Either use the
  py39 wheel set with `python3.10` (works — 3.10 is ABI-compatible for
  most wheels tagged cp39/abi3), or install `python3.11` from the
  deadsnakes PPA and prefer the py311 wheel set.
- **Worker count is 1** for the same reason as RHEL: APScheduler runs
  in-process. Raise `--threads` for concurrency instead.
- **PostgreSQL:** same as RHEL — set
  `DATABASE_URL=postgres://user:pass@host/dbname` in `.env`, then
  `pip install psycopg2-binary` and `manage.py migrate`.
