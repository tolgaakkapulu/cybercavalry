<div align="center">

<img src="static/img/logo.png" alt="CYBERCavalry logo" width="120" />

# CYBERCavalry

**A self-hosted threat intelligence & blacklist management platform**

Aggregate, score and distribute IP / hash blacklists from a single Django control plane.

![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue.svg)
![Django](https://img.shields.io/badge/django-4.2%20LTS-092E20.svg)
![License](https://img.shields.io/badge/license-GPL%20v3-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20|%20Windows-lightgrey.svg)
![Built with Claude](https://img.shields.io/badge/built%20with-Claude-D97706?logo=anthropic&logoColor=white)

[Features](#-features) · [Screenshots](#-screenshots) · [Architecture](#-architecture) · [Installation](#-installation) · [Configuration](#-configuration) · [API](#-http-api) · [Deployment](#-production-deployment)

</div>

---

## ✨ Overview

CYBERCavalry is a batteries-included blacklist management platform for SOC and network teams. It ingests IP / file-hash indicators from your own tooling (SIEM, honeypots, firewall alerts) or external feeds, cross-checks each indicator against **AbuseIPDB** and **VirusTotal**, buckets it by confidence into short-term (24 h) and long-term (30 d) publish groups, and serves the resulting blacklists back to your enforcement points over a simple HTTP API.

Everything runs behind a clean web UI with role-based access, activity auditing, syslog forwarding and a full alerting story for quota and API-rate anomalies.

> **What it isn't:** an EDR, a SIEM, or a threat-intel marketplace. It's the plumbing layer that turns "IP X is bad" into "IP X is now on your firewall's deny list for 24 h" — with an audit trail.

---

## 🚀 Features

<table>
<tr>
<td width="50%" valign="top">

### 🎯 Blacklist Management
- **IP blacklist** with rolling 24 h and long-term 30 d groups
- **Hash blacklist** (MD5 / SHA-1 / SHA-256 / SHA-512) for malware IOCs
- **Whitelist** with CIDR overlap detection
- **Hit tracking** with rolling report count per IP
- **Automatic promotion** — repeat offenders escalated from 24 h → 30 d based on configurable threshold within an N-day window
- **Pinned entries** — admin overrides that survive automatic re-evaluation

</td>
<td width="50%" valign="top">

### 🧠 Threat Intelligence
- **AbuseIPDB** integration with per-score group assignment
- **VirusTotal** integration with malicious-engine threshold
- **Multi-key rotation** — stack N keys per provider, transparent failover on quota exhaustion
- **Automatic scoring** on ingest + scheduled bulk re-scoring
- **Cleanup rules** — retention by score band and age

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔔 Alerting & Observability
- **E-mail alerts** for quota exhaustion (AbuseIPDB / VirusTotal)
- **E-mail alerts** for API rate-limit abuse per caller
- **Activity log** with old/new diff for every configuration change
- **Syslog forwarding** — mirror `cybercavalry.log`, `error.log`, `access.log` streams to a RFC 3164 collector
- **Configurable cooldowns** so operators aren't paged twice for the same event

</td>
<td width="50%" valign="top">

### 🔐 Security & Access
- **LDAP** authentication (multiple base-DN support)
- **Role-based access control** (admin / operator / viewer)
- **Session timeouts** and lockout after failed attempts
- **API tokens** with per-token source-IP allowlists
- **Password policy** engine (length, character classes, rotation)
- **CSP-safe UI** — no inline `on*` handlers

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📊 Reporting
- **Dashboard** with dark / light theme, brand color, custom logo
- **PDF reports** — activity summary, per-group breakdowns
- **Charts** for hit trends, group distribution, top reporters
- **Auto-refresh** dashboard with a configurable polling interval

</td>
<td width="50%" valign="top">

### 🔧 Operations
- **Backup scheduler** — daily DB snapshots with retention
- **Automatic cleanup jobs** — prune expired entries
- **APScheduler-based** in-process background jobs (no Celery / Redis dependency required for the core)
- **Offline install bundle** for air-gapped environments

</td>
</tr>
</table>

---

## 📸 Screenshots

<div align="center">

### Login

Brand-aware sign-in with configurable background, logo and accent color. LDAP or local credentials, with failed-login lockout and session-timeout guards enforced from the first request.

![Login](images/login.png)

---

### Dashboard

At-a-glance operational view: 30 d / 24 h / whitelist counts, hit-count trends, top reporters and the most-recent blacklist / hashlist entries. Auto-refreshes at the interval set in Settings → General.

![Dashboard](images/dashboard.png)

---

### IP Blacklist

Every active IP with its group (24 h / 30 d / no-group), AbuseIPDB score, source, reporter and rolling 30-day hit count. Sortable columns, inline search, bulk actions and per-row score refresh — all governed by role.

![IP Blacklist](images/ip_blacklist.png)

---

### Hash Blacklist

Hash IOCs (MD5, SHA-1, SHA-256, SHA-512) with the malicious-engine count returned by VirusTotal. New hashes are scored automatically on ingest; the whole set is re-scored on the schedule you configure.

![Hash Blacklist](images/hash_blacklist.png)

---

### IP Whitelist

Allowlist for benign infrastructure (corporate egress, monitoring probes, upstream proxies). CIDR overlap detection prevents a whitelist entry from silently covering a blocked range.

![IP Whitelist](images/ip_whitelist.png)

</div>

---

## 🏗️ Architecture

**Component layout**

```
CYBERCavalry/
├── cybercavalry/         # Django project package (settings, urls, wsgi)
│   ├── settings/base.py  # LOGGING, INSTALLED_APPS, middleware chain
│   ├── log_filters.py    # Below-error filter for syslog / file split
│   └── urls.py
├── apps/
│   ├── accounts/         # Auth, LDAP, roles, sessions, API tokens
│   ├── api/              # Public HTTP API (report + consume endpoints)
│   ├── blacklist/        # IP entries, AbuseIPDB service, promotion logic
│   ├── hashlist/         # Hash entries, VirusTotal service
│   ├── whitelist/        # CIDR / IP allowlist with overlap detection
│   ├── dashboard/        # Landing page, charts, quick actions
│   ├── reports/          # PDF generator, activity exports
│   └── settings_app/     # Setting model, cache, alert & quota services
├── templates/            # Django templates (dark/light theme aware)
├── static/               # CSS, JS, brand assets
├── deploy/               # Linux/Windows install script, systemd unit, wheels bundle
└── manage_server.py      # Dev helper: setup / run / migrate / seed
```

---

## 🧰 Tech Stack

| Layer | Choice | Why |
| --- | --- | --- |
| Language | Python 3.10+ | Django 4.2 LTS compat window |
| Framework | Django 4.2 LTS | Long-term security backports |
| Database | SQLite (dev) / PostgreSQL (prod) | Zero-config dev, standard prod |
| Frontend | Alpine.js + vanilla CSS | No build step, CSP-friendly |
| Charts | Chart.js | Small footprint, no CDN required |
| Auth | Django sessions + LDAP (ldap3) | Works with existing corporate directories |
| Scheduler | APScheduler (in-process) | No external broker needed for core features |
| Templating | Django templates | Server-rendered pages, easy PDF export |
| PDF | ReportLab | Pure Python, no headless browser |

---

## 📋 Prerequisites

- **Python** 3.10, 3.11, or 3.12
- **pip** and `venv`
- **git**
- (Prod only) **PostgreSQL** 12+, **SMTP relay**, **Nginx / Traefik** or standalone Gunicorn with TLS
- (Optional) **LDAP** server for corporate SSO
- (Optional) **AbuseIPDB** and **VirusTotal** API keys — the platform works without them but automatic scoring is disabled

---

## ⚙️ Installation

One script per platform, one command each. Full walkthrough (including
prerequisites and the offline wheel bundle) lives at
[`deploy/README.md`](deploy/README.md).

**🐧 Linux — RHEL / Debian / Ubuntu**
```bash
sudo bash deploy/linux/setup.sh install     # first time
sudo bash deploy/linux/setup.sh update      # in-place upgrade
```
The script auto-detects your distro family and handles `dnf`/`apt`,
`firewalld`/`ufw`, and SELinux (RHEL only) automatically.

**🪟 Windows Server 2019 / 2022, Windows 10 / 11**
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action install
powershell -ExecutionPolicy Bypass -File .\deploy\windows\setup.ps1 -Action update
```

Both platforms preserve `.env`, database, TLS certificates, logs and
backups across updates, and write a rollback snapshot before touching
anything.

### Quick Start — Developer / Evaluation

For local development on any OS, `manage_server.py` skips the full
production dance:

```bash
git clone https://github.com/<your-user>/CYBERCavalry.git
cd CYBERCavalry
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows PowerShell
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env          # then fill in the secrets
python manage_server.py setup # migrate + seed + createsuperuser + collectstatic
python manage_server.py start # → https://127.0.0.1:8443
```

First login uses the superuser you created during `setup`. From there:

1. **Settings → Threat Intelligence** — paste your AbuseIPDB / VirusTotal keys, click *Check Key*
2. **Settings → LDAP** *(optional)* — wire your directory, click *Test LDAP*
3. **Settings → Actions → E-mail** — configure SMTP, click *Test SMTP*
4. **Accounts** — add operators / viewers as needed
5. **API tokens** — mint a token for your SIEM / honeypot to POST reports

---

## 🔧 Configuration

### Environment (`.env`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | — | **Required.** Django's cryptographic key. Generate with `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DEBUG` | `False` | Never `True` in production |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hostnames |
| `DATABASE_URL` | `sqlite:///cybercavalry.db` | `postgres://user:pass@host/db` in prod |
| `TIME_ZONE` | `UTC` | e.g. `Europe/Istanbul` |
| `LANGUAGE_CODE` | `en-us` | UI language |

### Runtime settings (Web UI)

Most operational settings live in the **Settings** page and are stored in the DB (encrypted for secrets). Highlights:

<details>
<summary><b>General</b> — brand, refresh intervals, timezone</summary>

- `general.platform_name` / `general.platform_name_suffix` — split brand name for the sidebar (e.g. `CYBER` + accent-colored `Cavalry`)
- `general.brand_color` — accent color (`#RRGGBB`)
- `general.brand_logo`, `general.brand_login`, `general.brand_background` — image uploads
- `general.dashboard_refresh_seconds` / `general.blacklist_refresh_seconds` — auto-polling cadence

</details>

<details>
<summary><b>LDAP</b> — corporate directory</summary>

- `ldap.server_uri` — `ldaps://dc01.corp.tld:636`
- `ldap.bind_dn` / `ldap.bind_password` — service account
- `ldap.user_search_bases` — one or more base DNs (newline-separated)
- `ldap.user_filter` — e.g. `(sAMAccountName={username})`

</details>

<details>
<summary><b>Threat Intelligence</b> — AbuseIPDB & VirusTotal</summary>

- `threat_intel.abuseipdb_api_key` — one or more keys (comma / newline separated for rotation)
- `threat_intel.abuseipdb_threshold_24h` — confidence score above which an IP enters the 24 h group (default `10`)
- `threat_intel.abuseipdb_threshold_30d` — score for the 30 d group (default `80`)
- `threat_intel.abuseipdb_promotion_threshold` + `_window_days` — auto-escalate persistent offenders (e.g. *3 reports in 7 days → 30 d group*)
- `threat_intel.virustotal_api_key` — one or more keys, rotated the same way
- `threat_intel.virustotal_detection_threshold` — minimum engines flagging a hash as malicious to keep it active
- `_schedule_enabled` + `_schedule_interval` — periodic re-scoring
- `_cleanup_*` — retention rules for stale, low-score entries

</details>

<details>
<summary><b>Actions</b> — alerts, e-mail, syslog</summary>

- E-mail tab: SMTP host / port / user / password / from / TLS
- Alerts → Quota: threshold `%`, cooldown, recipient list (`;`-separated)
- Alerts → Rate limit: per-caller RPM threshold, alert e-mail
- Syslog: host / port / protocol, per-stream toggles (activity / error / access)

</details>

<details>
<summary><b>Security</b></summary>

- `security.session_timeout` — minutes of idle
- `security.lockout_attempts` / `lockout_duration` — failed-login backoff
- API tokens: managed under **Accounts → API Tokens** with optional source-IP allowlist

</details>

---

## 🛣️ HTTP API

Two authentication modes, applied per endpoint:

- **Token + username** *(POST endpoints)* — headers `Authorization: Token <token>` and `X-Username: <user>` are both required. The token must belong to that user, the user must have the **API User** role, AND the requesting IP must be on the allowlist under Settings → Source IPs. Tokens are minted by an admin under **Accounts → User Management**.
- **Source IP only** *(GET endpoints)* — no token or username header. The requesting IP simply has to be on the allowlist. This lets firewalls, SIEMs and proxies pull the current blacklists without credential management.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET`  | `/api/status/`         | Source IP | Health check — platform version + counts |
| `POST` | `/api/report/ip/`      | Token + Source IP | Report an IP; auto-scores and buckets it |
| `POST` | `/api/report/hash/`    | Token + Source IP | Report a hash (MD5 / SHA-1 / SHA-256 / SHA-512) |
| `GET`  | `/api/blacklist/`      | Source IP | Full active IP blacklist (both groups) |
| `GET`  | `/api/blacklist/24h/`  | Source IP | Only the 24 h group |
| `GET`  | `/api/blacklist/30d/`  | Source IP | Only the 30 d group |
| `GET`  | `/api/hashlist/`       | Source IP | Full active hash blacklist |

**Example — reporting an IP from a honeypot:**

```bash
curl -X POST https://blacklist.example.com/api/report/ip/ \
  -H "Authorization: Token 9c1e0f...redacted" \
  -H "X-Username: honeypot-01" \
  -H "Content-Type: application/json" \
  -d '{"ip": "X.X.X.X", "reason": "SSH brute force"}'
```

Response:

```json
{
  "status": "blacklisted",
  "cidr": "X.X.X.X/32",
  "group": "24h",
  "score": 87,
  "message": "New blacklist entry created."
}
```

**Example — reporting a SHA-512 hash:**

```bash
curl -X POST https://blacklist.example.com/api/report/hash/ \
  -H "Authorization: Token 9c1e0f..." \
  -H "X-Username: edr-connector" \
  -H "Content-Type: application/json" \
  -d '{"hash": "9b71d224bd62f3785d96d46ad3ea3d73...", "type": "sha512", "reason": "Ransomware"}'
```

**Example — pulling the current 24 h blacklist from your firewall (no token, IP allowlist enforced):**

```bash
curl https://blacklist.example.com/api/blacklist/24h/ \
  | jq -r '.entries[].cidr' > /etc/firewall/deny_24h.txt
```

Full endpoint schemas — including request bodies, response shapes and error codes — render live under **Accounts → API Documentation** once you're logged in, and can be exported to PDF from the same page.

---

## 🏭 Production Deployment

Full walkthrough — prerequisites, offline wheel bundle, service
management, update flow, rollback — lives at
[`deploy/README.md`](deploy/README.md). At a glance:

| Platform | Runner | Service | Installer / Updater |
|---|---|---|---|
| RHEL 9.x · Debian 12+ · Ubuntu 22.04+ | gunicorn | systemd ([`cybercavalry.service`](deploy/linux/cybercavalry.service)) | [`deploy/linux/setup.sh install\|update`](deploy/linux/setup.sh) |
| Windows Server 2019 / 2022 · Windows 10 / 11 | waitress | WinSW ([`cybercavalry-service.xml`](deploy/windows/cybercavalry-service.xml)) | [`deploy/windows/setup.ps1 -Action install\|update`](deploy/windows/setup.ps1) |

Both platforms preserve `.env`, database, TLS certificates, logs and
backups across updates; the Linux service runs as an unprivileged
`cavalry` user with `NoNewPrivileges` + `PrivateTmp` hardening.

**Minimum production checklist:**

- [ ] `DEBUG=False`
- [ ] Strong `SECRET_KEY` from `secrets.token_urlsafe(50)`
- [ ] `ALLOWED_HOSTS` restricted to the actual FQDN
- [ ] PostgreSQL (not SQLite) as `DATABASE_URL`
- [ ] TLS certificates in `certs/` (real CA, not the bundled self-signed dev cert)
- [ ] SMTP configured and *Test SMTP* passes
- [ ] Backups enabled with off-host storage of `backups/`
- [ ] LDAP (or another SSO) instead of local passwords
- [ ] Syslog forwarding pointed at your SIEM
- [ ] API tokens rotated on a documented cadence

---

## 🛡️ Security

- Never commit your `.env`, `db.sqlite3`, `certs/*.pem`, or anything under `media/brand/`
- API-token authentication uses constant-time comparison
- Secret settings (SMTP password, LDAP bind password, API keys) are encrypted at rest with a key derived from `SECRET_KEY`
- Please report vulnerabilities privately — do **not** open a public issue

---

## 🗺️ Roadmap

- [ ] Prometheus `/metrics` endpoint
- [ ] Webhook fan-out on new blacklist entries
- [ ] Multi-tenant workspaces
- [ ] MISP integration
- [ ] Additional TI providers (Shodan, GreyNoise)

---

## 🤝 Contributing

Contributions are welcome. For anything non-trivial, please open an issue first so we can align on scope.

```bash
# fork, then
git checkout -b feat/short-description
# ... commit ...
python manage.py test
git push origin feat/short-description
# open a PR
```

---

## 🤝 Acknowledgments

Built as a collaboration between the developer — guiding security,
performance and design decisions — and **[Claude](https://claude.ai)**
by Anthropic, contributing as a pair-programming partner across
implementation, refactoring and documentation.

---

## 📄 License

GNU General Public License v3.0 — see [`LICENSE`](LICENSE) for the full text.

---

<div align="center">

**Built with ❤️ for SOC and network teams who want blacklist plumbing that just works.**

</div>
