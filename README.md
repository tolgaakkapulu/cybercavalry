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

Every active IP with its group (24 h / 30 d / no-group), AbuseIPDB score, source, reporter and rolling 7-day hit count. Sortable columns, inline search, bulk actions and per-row score refresh — all governed by role.

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

```mermaid
graph LR
    subgraph "External Feeds"
        SIEM[SIEM / Honeypot]
        MANUAL[Manual Import]
    end

    subgraph "CYBERCavalry"
        API[HTTP API]
        UI[Web UI]
        SCHED[APScheduler]
        DB[(SQLite / PostgreSQL)]
        LOG[Activity Log]
    end

    subgraph "Threat Intel"
        ABUSE[AbuseIPDB]
        VT[VirusTotal]
    end

    subgraph "Consumers"
        FW[Firewall]
        WAF[WAF / Proxy]
        EDR[EDR]
    end

    subgraph "Observability"
        SYSLOG[Syslog Collector]
        MAIL[SMTP]
    end

    SIEM -->|POST /api/report/ip| API
    MANUAL --> UI
    API --> DB
    UI --> DB
    SCHED --> DB
    SCHED -->|score refresh| ABUSE
    SCHED -->|hash lookup| VT
    API -->|GET /api/blacklist| FW
    API -->|GET /api/blacklist/24h| WAF
    API -->|GET /api/hashlist| EDR
    LOG --> SYSLOG
    SCHED -->|quota / rate alerts| MAIL
```

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
├── deploy/               # RHEL install script, systemd unit, wheels bundle
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

### 1. Clone & bootstrap

```bash
git clone https://github.com/<your-user>/CYBERCavalry.git
cd CYBERCavalry

python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows PowerShell
.\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure the environment

```bash
cp .env.example .env
# then edit .env — see the Configuration Reference below
```

### 3. First-run setup

The included `manage_server.py` helper wires the whole first-run flow together:

```bash
python manage_server.py setup
```

Which under the hood does:

```mermaid
sequenceDiagram
    autonumber
    participant You
    participant Setup as manage_server.py
    participant DB
    participant Static

    You->>Setup: setup
    Setup->>DB: migrate (apply all migrations)
    Setup->>DB: seed_initial_data (groups, roles, default settings)
    Setup->>DB: createsuperuser (interactive)
    Setup->>Static: collectstatic --noinput
    Setup-->>You: ✅ Ready — run `python manage_server.py run`
```

### 4. Start the dev server

```bash
python manage_server.py run
# → http://127.0.0.1:8000
```

First login uses the superuser you created in step 3. From there:

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
  -d '{"ip": "203.0.113.42", "reason": "SSH brute force"}'
```

Response:

```json
{
  "status": "blacklisted",
  "cidr": "203.0.113.42/32",
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
  -d '{"hash": "9b71d224bd62f3785d96d46ad3ea3d73...", "type": "sha512", "reason": "Emotet dropper"}'
```

**Example — pulling the current 24 h blacklist from your firewall (no token, IP allowlist enforced):**

```bash
curl https://blacklist.example.com/api/blacklist/24h/ \
  | jq -r '.entries[].cidr' > /etc/firewall/deny_24h.txt
```

Full endpoint schemas — including request bodies, response shapes and error codes — render live under **Accounts → API Documentation** once you're logged in, and can be exported to PDF from the same page.

---

## 🔄 Operational Workflows

### Automatic promotion (24 h → 30 d)

```mermaid
flowchart LR
    A[POST /api/report/ip/ arrives] --> B{Existing entry?}
    B -->|No| C[Create — group by AbuseIPDB score]
    B -->|Yes| D[hit_count++<br/>append timestamp]
    D --> E{Recent count ≥ threshold<br/>within window_days?}
    E -->|Yes| F[Promote to 30 d group]
    E -->|No| G[Keep current group]
    C --> H[Persist]
    F --> H
    G --> H
```

### Quota alert cycle

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Checking: hourly APScheduler tick
    Checking --> Idle: quota < threshold
    Checking --> Cooldown: quota ≥ threshold<br/>send email
    Cooldown --> Idle: cooldown_hours elapsed
    Cooldown --> Cooldown: still ≥ threshold<br/>(email suppressed)
```

---

## 🏭 Production Deployment

Deploy artefacts are split by target OS under [`deploy/`](deploy/) — see [`deploy/README.md`](deploy/README.md) for the overview and OS-selection matrix.

### 🐧 Linux (RHEL 9.x / AlmaLinux / Rocky Linux)

Runs behind **gunicorn** with native TLS, managed by **systemd**. Includes an offline wheel bundle for air-gapped installs, pre-flight `migrate` + `collectstatic`, and SELinux labelling automation.

- **[`deploy/linux/INSTALL_RHEL.md`](deploy/linux/INSTALL_RHEL.md)** — step-by-step guide
- **[`deploy/linux/install_rhel.sh`](deploy/linux/install_rhel.sh)** — one-shot installer
- **[`deploy/linux/update_rhel.sh`](deploy/linux/update_rhel.sh)** — in-place upgrade (with automatic venv-repair pre-flight)
- **[`deploy/linux/cybercavalry.service`](deploy/linux/cybercavalry.service)** — systemd unit

Runs as an unprivileged `cavalry` user, restarts on failure, and applies OS-level hardening (`NoNewPrivileges`, `PrivateTmp`).

### 🪟 Windows (Server 2019 / 2022, also Windows 10 / 11)

Runs behind **waitress** (pure-Python WSGI, Windows-friendly), managed by **WinSW** as a native Windows service. Uses the same offline wheel bundle as the Linux path.

- **[`deploy/windows/INSTALL_WINDOWS.md`](deploy/windows/INSTALL_WINDOWS.md)** — step-by-step guide
- **[`deploy/windows/install_windows.ps1`](deploy/windows/install_windows.ps1)** — one-shot PowerShell installer
- **[`deploy/windows/update_windows.ps1`](deploy/windows/update_windows.ps1)** — in-place upgrade with rollback snapshot
- **[`deploy/windows/cybercavalry-service.xml`](deploy/windows/cybercavalry-service.xml)** — WinSW service definition

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

CYBERCavalry was designed and built in close collaboration with
**[Claude](https://claude.ai)** by Anthropic. This project is an
intentional experiment in transparent, AI-assisted open source
development — the reality of how a lot of software gets written in
2026 — so it's called out here rather than hidden.

**What Claude helped with:**
- Iterating on the domain model (blacklist groups, promotion rules,
  quota-aware key rotation, cache/session/rate-limit layering)
- Generating and refactoring Django code across the apps, templates,
  admin UI, and management commands
- Diagnosing production issues (SELinux labelling, venv shebang
  rot after directory rename, VirusTotal quota misclassification)
- Drafting documentation — this README, the RHEL/Windows deployment
  guides, and inline code commentary
- Adversarial review of edge cases in the promotion / demotion,
  quota alerting and API-token flows

**What I own end-to-end:**
- The product vision and roadmap
- Every architectural and licensing decision
- All testing on real systems (RHEL 9.5 production, Windows dev)
- Every commit that goes into `main` — the code shipped here has been
  read, understood and taken responsibility for by a human
- Support, security response and long-term maintenance

If you're using this project, you're using code that was **co-written
with an AI** but **reviewed, tested and maintained by a person**. Bug
reports and PRs go to that person, not to the model.

---

## 📄 License

GNU General Public License v3.0 — see [`LICENSE`](LICENSE) for the full text.

You may freely run, study, modify and redistribute this project. If you
distribute it (in original or modified form), you MUST:

- Release your modifications under GPL v3 as well
- Provide access to the complete corresponding source code
- Preserve copyright notices and the GPL v3 license header

Any derivative work — direct fork, patched build, or bundled distribution —
must remain open source under GPL v3. Closed-source proprietary forks are
not permitted.

Note: GPL v3 applies to **distribution**. Running a modified copy privately
(e.g. inside a single organisation) without redistributing binaries does
not trigger the source-sharing requirement.

---

<div align="center">

**Built with ❤️ for SOC and network teams who want blacklist plumbing that just works.**

</div>
