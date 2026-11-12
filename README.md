<div align="center">

<img src="static/img/logo.png" alt="CYBERCavalry logo" width="120" />

# CYBERCavalry

**A self-hosted threat intelligence & blacklist management platform**

Aggregate, score and distribute IP / hash blacklists from a single Django control plane.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
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
- **URL blacklist** — malicious/phishing URLs with VirusTotal reputation lookups
- **Whitelist** with CIDR overlap detection
- **Hit tracking** with rolling report count per IP
- **Automatic promotion** — repeat offenders escalated from 24 h → 30 d based on configurable threshold within an N-day window
- **Pinned entries** — admin overrides that survive automatic re-evaluation
- **Rich filters** — search + group + source + pinned + count / AbuseIPDB score ranges on IP Blacklist; search + pinned on URL & Hash Blacklist. Search covers every tooltip-visible enrichment column (ISP, ASN, country, threat label, categories, tags, registrar…) with true case-insensitive matching across Turkish and other non-ASCII text.
- **Bulk actions** — activate / deactivate / delete / pin / unpin / score across every selection

</td>
<td width="50%" valign="top">

### 🧠 Threat Intelligence
- **AbuseIPDB** integration with per-score group assignment
- **VirusTotal** integration with malicious-engine threshold — for both file hashes AND URLs
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
- **E-mail alerts** for integration silence — notify when a regular firewall / XDR / SIEM caller stops pulling
- **Activity log** with old/new diff for every configuration change and every API request — REST *and* TAXII — recording method, path, query and user-agent
- **Activity log filter for API requests** so firewall/XDR pull events are one click away
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
- **Timelines** for blacklist activity and incoming API requests (REST + TAXII)
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

Two timeline widgets sit side by side, half the width each, both opening on **Last 24 hours · Hourly** (below ~1440px of browser width they stack instead, so each keeps its title and controls on one line):

| Widget | Series | Answers |
| --- | --- | --- |
| **Blacklist Timeline** | IP / Hash / URL | What happened to each list, and when? |
| **Request Timeline** | Feed pulls / Reports / Rejected / Other | What did clients ask of it? |

Each card has its own range (60 minutes … 12 months) and granularity (minutely / hourly / daily / monthly) control, so the two can be compared at different scales; picking a range selects a sensible granularity, which you can then override. Both cards are deliberately built to the same frame — one unwrappable header row, a fixed plot box, a fixed-height HTML legend and a pinned y-axis width — so the two plot areas stay aligned whatever numbers are in them. Clicking a legend entry hides that line and rescales the axis to what is left.

The Blacklist Timeline has a third control, the measure:

| Measure | Each point is | Use it to see |
| --- | --- | --- |
| **Activity** (default) | every change to the list in that bucket: entries added, activated, edited, plus repeat reports that bumped an existing entry's hit count | what the list has been doing |
| **New only** | entries added, and nothing else | real ingestion, separated from re-activating entries you already had |
| **Total** | how many entries the list held at the end of that bucket | the size of each list and how it got there |

An entry row carries only `added_at`, so activating or editing one leaves no per-row trace — **Activity** picks those up from the activity log, weighted by how many entries each action touched (`detail['count']` for a bulk action). Additions always come from `added_at` rather than from log rows, so they are exact and present even for entries imported before the log had any; a report that *created* an entry is therefore skipped when counting repeat reports, or it would be counted twice. Deactivations and deletions are left out on purpose: they are the opposite sign, and folding them in would make 100 additions plus 100 removals read as 200 changes.

**Activity** and **New only** report history, so they count every row regardless of whether it is active today — an entry added on Tuesday was added on Tuesday, and deactivating it on Friday must not rewrite Tuesday. **Total** reports present state instead, so it counts the live list from the very same querysets the stat cards use: a card and the chart beneath it cannot drift apart, and a wide-enough window sums to the number on the card. The Request Timeline reads the activity log, where every incoming API request is recorded under an `api.*` action:

| Series | Actions |
| --- | --- |
| Feed pulls | `api.blacklist`, `api.hashlist`, `api.urllist`, `api.taxii_objects`, `api.taxii_object`, `api.taxii_manifest` |
| Reports | `api.report`, `api.hash_report`, `api.url_report` |
| Rejected | `api.rate_limit` (throttled), `api.taxii_denied` (bad token, IP off the allowlist) |
| Other | the remainder — `api.status`, `api.report.skipped`, TAXII discovery and collection browsing |

*Other* is computed as the remainder rather than enumerated, so the four series always add up to the total API traffic in the window and a newly added `api.*` action can never silently vanish from the chart. Both the `/api/v1/` endpoints and the TAXII endpoints write these rows, so the same chart covers firewall pulls and TAXII subscriber polls; the Activity Log page shows the individual rows under its **API** type filter. The chart stays flat at zero until something actually calls the API.

At the foot of the page, the **API Endpoints** card (admin only) lists the callable surface: the `/api/v1/` endpoints, and below them the TAXII paths with a status chip reading *Disabled*, *Enabled · n collections* or *Enabled · no active collection* — the last of those is a server that answers but publishes nothing, which a list of paths alone would not reveal. TAXII sits on its own row rather than in the same grid because it shares neither the `/api/v1/` prefix nor the source-IP-only authentication of the endpoints above it.

![Dashboard](images/dashboard.png)

---

### IP Blacklist

Every active IP with its group (24 h / 30 d / no-group), AbuseIPDB score, source, reporter and rolling 30-day hit count. Sortable columns, inline search, bulk actions and per-row score refresh — all governed by role.

![IP Blacklist](images/ip_blacklist.png)

---

### URL Blacklist

Malicious / phishing URLs scored by VirusTotal. Any input form — bare domain, `http://…`, `https://…` — collapses to a single canonical row so the same target never lands three times, and the **Hostname column groups by registrable domain** (eTLD+1 via the Public Suffix List) so many subdomains under one phishing operation cluster together. Hovering a row surfaces every enriched field VT returns: threat label, categories, tags, community reputation & votes, page title, resolved serving IP, redirect chain, registrar, domain creation date, popularity rank. URLs VT has never indexed get a **"Not in VT"** badge and land in the Inactive tab instead of showing a misleading 0/0 score. Auto-scored on ingest, re-scored on the schedule you configure.

![URL Blacklist](images/url_blacklist.png)

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
│   ├── urllist/          # URL entries, VirusTotal service (URL + domain endpoints)
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

- **Python** 3.10+
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
git clone https://github.com/tolgaakkapulu/CYBERCavalry.git
cd CYBERCavalry
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows PowerShell
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env          # then fill in the secrets
python manage_server.py setup # migrate + seed default admin + collectstatic
python manage_server.py start # → https://127.0.0.1:8443
```

A default administrator is seeded automatically: **`admin` / `admin`** — log in
and change the password **immediately** under your profile. From there:

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
- Alerts → Silence: heartbeat watchdog for integrated products (firewall / XDR / SIEM). Fires when a caller with a 24 h baseline stops calling for N minutes. Threshold / baseline / cooldown are all configurable.
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
| `POST` | `/api/report/url/`     | Token + Source IP | Report a URL (http/https) |
| `GET`  | `/api/blacklist/`      | Source IP | Full active IP blacklist (both groups) |
| `GET`  | `/api/blacklist/24h/`  | Source IP | Only the 24 h group |
| `GET`  | `/api/blacklist/30d/`  | Source IP | Only the 30 d group |
| `GET`  | `/api/hashlist/`       | Source IP | Full active hash blacklist |
| `GET`  | `/api/urllist/`        | Source IP | Full active URL blacklist |

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

**Example — reporting a phishing URL:**

```bash
curl -X POST https://blacklist.example.com/api/report/url/ \
  -H "Authorization: Token 9c1e0f..." \
  -H "X-Username: xdr-connector" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://phishing.example/login", "reason": "Credential theft page"}'
```

**Example — pulling the current 24 h blacklist from your firewall (no token, IP allowlist enforced):**

```bash
curl https://blacklist.example.com/api/blacklist/24h/ \
  | jq -r '.entries[].cidr' > /etc/firewall/deny_24h.txt
```

Full endpoint schemas — including request bodies, response shapes and error codes — render live under **Accounts → API Documentation** once you're logged in, and can be exported to PDF from the same page. The TAXII surface described below has its own tab there (paths, filters, pagination, sample bundle), since it does not sit under `/api/v1/`.

---

## 📡 TAXII 2.0 Server (STIX 2.0)

Some enforcement points can't poll a plain JSON endpoint. **Centralised threat-intelligence managers** — the appliances that sit in front of a vendor's breach-detection, sandbox, secure e-mail and web-gateway estate — subscribe to intel over **TAXII** and then redistribute it to the products they manage; **XDR, NDR and SIEM** platforms consume the same way. So the URL Blacklist is published a **second way**, as STIX 2.0 indicators over TAXII 2.0, without disturbing the `GET /api/urllist/` feed the firewall already consumes.

Both channels read the same `URLEntry` rows with the same predicate, so they can never disagree about what is currently blocked:

| | Firewall | TAXII subscriber |
| --- | --- | --- |
| Prefix | `/api/urllist/` | `/taxii/…` |
| Format | JSON (or `?format=txt`) | STIX 2.0 bundle |
| Auth | Source-IP allowlist | API token over HTTP Basic (+ optional source-IP) |
| Access | read-only | read-only |

### Endpoints

Built against [OASIS TAXII 2.0 CS01](https://docs.oasis-open.org/cti/taxii/v2.0/cs01/taxii-v2.0-cs01.html). Discovery lives at `/taxii/` — note that's the 2.0 path; TAXII 2.1 moved it to `/taxii2/`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/taxii/` | Discovery — the single URL you paste into the subscriber |
| `GET` | `/taxii/<root>/` | API root (`versions: ["taxii-2.0"]`) |
| `GET` | `/taxii/<root>/collections/` | Collection list |
| `GET` | `/taxii/<root>/collections/<id>/` | Collection metadata |
| `GET` | `/taxii/<root>/collections/<id>/objects/` | The indicators, as a STIX bundle |
| `GET` | `/taxii/<root>/collections/<id>/objects/<obj-id>/` | A single indicator |
| `GET` | `/taxii/<root>/collections/<id>/manifest/` | Manifest, for incremental sync |

Pagination follows TAXII 2.0's `Range: items 0-49` → `206` + `Content-Range: items 0-49/500` contract (2.1's `more`/`next` fields don't apply here), and `added_after` drives incremental polling. Note the **space** after `items`: that is the spec's own form, and the RFC 7233-style `items=0-49` is treated as no range at all rather than rejected — a lenient reading that keeps a quirky client working, at the cost of silently serving it the default page instead of the slice it asked for. A request with no `Range` header is answered `206` as well, capped at the page size in Settings → TAXII 2.0 Server (default 500), so a 1 396-entry feed is three polls rather than one enormous response.

### Feeds

All three blacklists are publishable, one *feed* per collection. Each feed's queryset is **deliberately the same predicate** its firewall counterpart under `/api/v1/` uses, so the two consumers can never disagree about what is currently blocked:

| Feed | Source | Mirrors | Published rows |
| --- | --- | --- | --- |
| `url` | URL Blacklist | `/api/v1/urllist/` | active, blacklist, VT reachable |
| `ip` | IP Blacklist | `/api/v1/blacklist/` | active, published group, not expired, not whitelisted |
| `hash` | Hash Blacklist | `/api/v1/hashlist/` | active, blacklist, VT reachable, algorithm determinable |

### Indicator mapping

A blacklist row becomes one `indicator` SDO. For URLs the pattern depends on whether the row pins a path, which matches how that list is used in practice — mostly whole malicious domains and subdomains:

| Blacklist row | STIX pattern |
| --- | --- |
| `phishing.example` | `[domain-name:value = 'phishing.example']` |
| `sub.phishing.example` | `[domain-name:value = 'sub.phishing.example']` |
| `bad.example/login.php` | `[url:value = 'https://bad.example/login.php']` |
| `198.51.100.7/32` | `[ipv4-addr:value = '198.51.100.7']` |
| `203.0.113.0/24` | `[ipv4-addr:value = '203.0.113.0/24']` |
| `2001:db8::1/128` | `[ipv6-addr:value = '2001:db8::1']` |
| SHA-256 hash | `[file:hashes.'SHA-256' = '…']` |

A full-length IP prefix ships as a bare address because that is what consumers match most reliably; a real CIDR block keeps its prefix. Hash algorithm names come from STIX 2.0's `hash-algorithm-ov` (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`); a row whose algorithm cannot be determined from either its stored type or its hex length is **left out of the feed** rather than published under a guess, since a wrong algorithm name yields an indicator that silently matches nothing. Be aware that consumers differ in which algorithms they accept — suspicious-object lists on breach-detection appliances are commonly limited to SHA-1 and SHA-256. MD5 and SHA-512 indicators are valid STIX and are published regardless; a consumer that will not ingest them filters them on its own side, which is the right place for that decision.

Indicator IDs are `uuid5` of a per-feed identity (the URL feed's is its `url_hash`, the IP feed's its CIDR, the hash feed's its hash value), so they stay stable across polls and a subscriber updates in place instead of accumulating duplicates. Every indicator carries `labels: ["malicious-activity"]` — the one value that is both valid in STIX 2.0's required `labels` field and survives the label filtering consumers apply. Breach-detection appliances in particular tend to drop `anomalous-activity`, `anonymization`, `benign` and `compromised` outright, so an indicator labelled with any of those would be accepted by the transport and then silently discarded at the other end.

### Collections

A **collection** is one subscribable feed, managed from the **Collections** button in the **Settings → TAXII 2.0 Server** header — it is TAXII configuration, so it lives with the rest of it rather than in the sidebar. That header also shows how many collections are currently active, so a server that is enabled but publishing nothing is visible without opening the page. TAXII's own model is one API root holding many collections, so that's the axis to grow along — add a row per feed you want a subscriber to be able to pick. A second *API root* is only worth it if different subscribers must not even see each other's collection list.

Each collection's UUID is generated on creation and never typed by hand. It must stay stable, because a subscriber stores the id it discovered and re-polls that exact value — so collections can be **paused** (keeps the UUID, feed goes off the air, resumes without re-discovery) as well as deleted.

Normally all three feeds share **one** API root: the subscriber discovers it once and then picks from its collection list. The *Add Collection* form offers the roots already in use plus the conventional names (`default`, `urllist`, `blacklist`, `hashlist`) and lists only the feeds still free under the root you pick — `unique_together(api_root, feed)` forbids a second collection for the same feed in the same root.

Picking a root whose name matches one of the lists pre-selects that list's feed and its title: `urllist` → URL Blacklist, `blacklist` → IP Blacklist, `hashlist` → Hash Blacklist. It is a starting point, not a constraint — change the Feed dropdown and the title follows, or type your own title and it is left alone from then on. `default` implies nothing, so it just takes the first free feed. If the implied feed is already published under that root the form falls back to one that is still free, since offering a pair the server would reject is a dead end.

Adding a further feed type is a small adapter class in `apps/taxii/stix.py`, two registry entries, and a choice on `TaxiiCollection.FEED_CHOICES` with its `FEED_DEFAULTS` title.

### Authentication

Subscribers use HTTP Basic — the scheme TAXII 2.0 mandates — where the **username is an API User account and the password is that account's API token**, minted under *Accounts → User Management*. Deliberately not the account's login password:

- LDAP-backed accounts have no usable local password at all
- a token is one indexed lookup; a password is a slow PBKDF2 verification on every poll
- password-policy rotation would silently kill the feed 90 days in
- failed attempts would otherwise feed the login lockout counter and could lock a human out

Revoking access is revoking the token — no settings to edit. Giving each subscriber its own service account (e.g. `taxii-subscriber`) keeps the audit trail readable and lets you cut one off alone.

### Audit trail

Every TAXII request writes one activity-log row, exactly as the `/api/v1/` endpoints do — so a subscriber's polls are visible in the console without reading `cybercavalry.log`:

| Action | Written when |
| --- | --- |
| `api.taxii_discovery` | discovery was fetched |
| `api.taxii_api_root` | an API root was read |
| `api.taxii_collections` | the collection list was read |
| `api.taxii_collection` | collection metadata was read |
| `api.taxii_objects` | a poll — `detail` carries the feed, how many indicators were served, the total available and whether the answer was partial |
| `api.taxii_object` | a single indicator was fetched |
| `api.taxii_manifest` | a manifest poll, with the same detail as `objects` |
| `api.taxii_denied` | a caller was turned away — `detail` carries the endpoint, the status and the reason |

Each row also records the method, path, query string, user-agent and source IP, and is attributed to the service account that authenticated — which is the practical argument for giving each subscriber its own account. A denial has no account to attribute, by definition, so it is recorded against the source IP alone. Those rows are what the dashboard's **Request Timeline** draws: `objects` / `object` / `manifest` count as *Feed pulls*, `api.taxii_denied` as *Rejected*, and discovery and collection browsing fall into *Other*. On the **Activity Log** page they are one click away under the **API** type filter.

Writing the row can never break a poll: a logging failure is swallowed and the feed still answers. One consequence worth planning for: the activity log is **not** pruned automatically, and a subscriber polling every minute adds ~1 440 rows a day, so on a long-lived install the table is worth watching.

### Setup

1. **Accounts → User Management** — create a service account with the **API User** role and generate its API token (shown once).
2. **Settings → Source IPs** — add the subscriber's egress IP (or turn off *Also Require Source IP*).
3. **Settings → TAXII 2.0 Server** — enable it.
4. **Settings → TAXII 2.0 Server → Collections** — confirm the seeded URL Blacklist collection, or add your own. *Add Collection* offers the API roots already in use in a dropdown (plus *+ New API root…*), lists only the feeds still free under the root you pick, and pre-fills the title from that feed.
5. On the subscriber — usually a *Threat Intelligence → Feed Management → Add* screen, or whatever the platform calls its feed subscription list — set the server version to **TAXII 2.0** (not 1.x, and not 2.1), the **Discovery URL** to `https://<host>:8443/taxii/` (note `https` and the trailing slash), and tick the option to supply credentials: the service account's username with its API token as the password. Upload your server certificate if it is self-signed, let the subscriber discover and pick the collection, then set a polling frequency.

---

## 🏭 Production Deployment

Full walkthrough — prerequisites, offline wheel bundle, service
management, update flow, rollback — lives at
[`deploy/README.md`](deploy/README.md). At a glance:

| Platform | Runner | Service | Installer / Updater |
|---|---|---|---|
| RHEL 9.x · Debian 12+ · Ubuntu 22.04+ | gunicorn | systemd ([`cybercavalry.service`](deploy/linux/cybercavalry.service)) | [`deploy/linux/setup.sh install\|update`](deploy/linux/setup.sh) |
| Windows Server 2019 / 2022 · Windows 10 / 11 | hypercorn (ASGI, native TLS) | WinSW ([`cybercavalry-service.xml`](deploy/windows/cybercavalry-service.xml)) | [`deploy/windows/setup.ps1 -Action install\|update`](deploy/windows/setup.ps1) |

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
