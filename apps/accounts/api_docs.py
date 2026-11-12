"""
CYBERCavalry API Reference — central content source.
Edit this file; both the web page and the PDF report update automatically.
"""
from __future__ import annotations

import html as _html

# ── Authentication descriptions ───────────────────────────────────────────

_AUTH_TOKEN_HTML = (
    'Both headers are required. The token must belong to the user specified in '
    '<code style="font-family:var(--font-mono);color:var(--accent);">X-Username</code>, '
    'and that user must have the <strong>API User</strong> role. '
    'Source IP must also be in the allowed list (Settings → Source IPs). '
    'Tokens are managed by an admin via <strong>User Management</strong>.'
)
_AUTH_IP_HTML = (
    '<strong>Source IP only.</strong> No token or username header required. '
    'The requesting IP must be in the allowed list (Settings → Source IPs). '
    'This allows firewalls and SIEM systems to pull the list without managing API credentials.'
)

# ReportLab Paragraph markup (PDF)
_AUTH_TOKEN_PDF = (
    'Both <b>Authorization: Token &lt;token&gt;</b> and '
    '<b>X-Username: &lt;username&gt;</b> headers are required. '
    'The token must belong to the specified user, who must have the <b>API User</b> role. '
    'Source IP must also be in the allowed list (Settings → Source IPs). '
    'Tokens are managed by an admin via User Management.'
)
_AUTH_IP_PDF = (
    '<b>Source IP authentication only.</b> No token or username header required. '
    'The requesting IP must be in the allowed list (Settings → Source IPs). '
    'Allows firewalls and SIEM systems to pull data without managing API credentials.'
)
# TAXII 2.0 CS01 §1.4.6 makes HTTP Basic mandatory-to-implement, so Basic is
# what a subscriber speaks. What goes in the password field is our choice, and
# it is the account's API token — see apps/taxii/auth.py for why not its
# login password.
_AUTH_BASIC_HTML = (
    '<strong>HTTP Basic</strong> — the scheme TAXII 2.0 mandates. The username is an '
    '<strong>API User</strong> account and the password is that account\'s '
    '<strong>API token</strong>, <em>not</em> its login password. '
    'When <em>Also Require Source IP</em> is on (the default), the caller\'s IP must '
    'additionally be in the allowed list (Settings → Source IPs). '
    'The server must be enabled under <strong>Settings → TAXII 2.0 Server</strong>; '
    'while it is off every path below answers <code style="font-family:var(--font-mono);'
    'color:var(--accent);">404</code>.'
)
_AUTH_BASIC_PDF = (
    '<b>HTTP Basic</b> — the scheme TAXII 2.0 mandates. The username is an '
    '<b>API User</b> account and the password is that account\'s <b>API token</b>, '
    '<i>not</i> its login password. When <i>Also Require Source IP</i> is on (the '
    'default), the caller\'s IP must additionally be in the allowed list '
    '(Settings → Source IPs). The server must be enabled under Settings → '
    'TAXII 2.0 Server; while it is off every path below answers 404.'
)


# ── Section helpers ───────────────────────────────────────────────────────

def _code(label, *lines):
    """Code-block section. Lines starting with # are rendered in the comment colour."""
    html_parts = []
    for ln in lines:
        if not ln:
            html_parts.append('')
        elif ln.lstrip().startswith('#'):
            html_parts.append(f'<span class="api-comment">{_html.escape(ln)}</span>')
        else:
            html_parts.append(_html.escape(ln))
    return {
        'type':  'code',
        'label': label,
        'lines': list(lines),        # raw lines — for PDF
        'html':  '\n'.join(html_parts),  # ready HTML — for template
    }


def _params(label, col_name, rows, badge_col=False):
    """
    Parameter / endpoint table.
    rows: list of (label, description) or (label, description, badge_class).
    """
    processed = []
    for row in rows:
        processed.append({
            'label': row[0],
            'desc':  row[1],
            'badge': row[2] if len(row) > 2 else None,
        })
    return {
        'type':      'params',
        'label':     label,
        'col_name':  col_name,
        'rows':      processed,
        'badge_col': badge_col,
    }


# ── Base URLs ────────────────────────────────────────────────────
# Shown as badges on the page and as rows in the PDF's base-URL box. There
# are two, because the TAXII surface deliberately sits OUTSIDE /api/v1 --
# TAXII 2.0 fixes discovery at /taxii/ (see apps/taxii/urls.py), so a single
# "Base URL: /api/v1" badge would be wrong for the TAXII tab.

BASE_URLS = [
    ('REST API',  'https://<host>:8443/api/v1'),
    ('TAXII 2.0', 'https://<host>:8443/taxii/'),
]


# ── Endpoint definitions ──────────────────────────────────────────────────
# The order is used for both the tabs and the PDF export.

ENDPOINTS = [

    # ── 1. GET /status/ ───────────────────────────────────────────────────
    {
        'tab_id':      'status',
        'tab_label':   'GET /status/',
        'method':      'GET',
        'path':        '/api/v1/status/',
        'description': 'Platform health check',
        'auth':        'token',
        'auth_html':   _AUTH_TOKEN_HTML,
        'auth_pdf':    _AUTH_TOKEN_PDF,
        'sections': [
            _code('curl Example',
                '# Health check',
                'curl -k https://<host>:8443/api/v1/status/ \\',
                '  -H "Authorization: Token <api_user-token>" \\',
                '  -H "X-Username: <api_user-username>"',
            ),
            _code('Response',
                '# 200 OK',
                '{',
                '  "status": "ok",',
                '  "version": "1.0.0",',
                '  "platform": "__PLATFORM_NAME__",',
                '  "timestamp": "2024-01-01T13:00:00+03:00",  # system local time with tz offset',
                '  "entries": { "total": 500, "active": 142 }',
                '}',
                '',
                '# 401 — Missing/invalid credentials',
                '{"error": "Authentication failed. Provide both \'Authorization: Token <token>\' and \'X-Username: <username>\' headers."}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
            ),
            _code('Monitoring / Heartbeat',
                '# Simple Zabbix / Nagios health check',
                'STATUS=$(curl -sk https://<host>:8443/api/v1/status/ \\',
                '  -H "Authorization: Token <api_user-token>" \\',
                '  -H "X-Username: <api_user-username>" | grep -o \'"status":"ok"\')',
                '[ "$STATUS" = \'"status":"ok"\' ] && echo "OK" || echo "CRITICAL"',
            ),
        ],
    },

    # ── 2. POST /report/ip/ ───────────────────────────────────────────────
    {
        'tab_id':      'report',
        'tab_label':   'POST /report/ip',
        'method':      'POST',
        'path':        '/api/v1/report/ip/',
        'description': 'Report a single IP address to a blacklist group',
        'auth':        'token',
        'auth_html':   _AUTH_TOKEN_HTML,
        'auth_pdf':    _AUTH_TOKEN_PDF,
        'sections': [
            _code('Request Body (JSON)',
                '{',
                '  "ip": "192.168.1.100",',
                '  "reason": "Brute force"',
                '}',
                '# ip     — required, single IP (/32) only; CIDR blocks are rejected',
                '# reason — optional, default: "API report"',
                '#',
                '# Group assigned automatically via AbuseIPDB score (30s timeout):',
                '#   score 80-100   -> 30d',
                '#   score 10-79    -> 24h',
                '#   score < 10     -> deactivated (not malicious)',
                '#   timeout/no key -> no_group (held, not published)',
            ),
            _code('curl Example',
                '# Report an IP — group assigned automatically via AbuseIPDB score',
                'curl -k -X POST https://<host>:8443/api/v1/report/ip/ \\',
                '  -H "Authorization: Token <api_user-token>" \\',
                '  -H "X-Username: <api_user-username>" \\',
                '  -H "Content-Type: application/json" \\',
                '  -d \'{"ip": "192.168.1.100", "reason": "Brute force attempt"}\'',
            ),
            _code('Response',
                '# 201 Created — new IP, scored and assigned to group',
                '{',
                '  "status": "blacklisted",',
                '  "cidr": "192.168.1.100/32",',
                '  "group": "30d",',
                '  "group_label": "30 Days",',
                '  "abuse_confidence_score": 87,',
                '  "action": "blacklisted",',
                '  "message": "New blacklist entry created.",',
                '  "expires_at": "2024-02-01T10:00:00Z"',
                '}',
                '',
                '# 200 OK — IP already on the list (active or inactive); the existing row',
                '#          is re-queried against AbuseIPDB, refreshed in place, and moved',
                '#          between groups if the new score changes its bucket.',
                '{',
                '  "status": "blacklisted",',
                '  "cidr": "192.168.1.100/32",',
                '  "group": "24h",',
                '  "group_label": "24 Hours",',
                '  "abuse_confidence_score": 95,',
                '  "action": "updated",',
                '  "message": "Existing blacklist entry refreshed with the latest AbuseIPDB data.",',
                '  "expires_at": "2024-01-02T10:00:00Z"',
                '}',
                '',
                '# 201 Created — AbuseIPDB timeout or disabled; placed in no_group (not published)',
                '{',
                '  "status": "blacklisted",',
                '  "cidr": "192.168.1.100/32",',
                '  "group": "no_group",',
                '  "group_label": "No Group",',
                '  "abuse_confidence_score": null,',
                '  "action": "blacklisted",',
                '  "message": "New blacklist entry created.",',
                '  "expires_at": null',
                '}',
                '',
                '# 200 — IP is whitelisted, skipped',
                '{"status": "whitelisted", "cidr": "10.0.0.1/32", "action": "skipped"}',
                '',
                '# 400 — CIDR block submitted instead of single IP',
                '{"error": "Only single IP addresses (/32) are accepted. \'10.0.0.0/24\' is a CIDR block."}',
                '',
                '# 401 — Missing or invalid credentials',
                '{"error": "Authentication failed."}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
                '',
                '# 429 — Rate limit exceeded',
                '{"error": "Rate limit exceeded."}',
            ),
        ],
    },

    # ── 3. GET /blacklist/ ────────────────────────────────────────────────
    {
        'tab_id':      'blacklist',
        'tab_label':   'GET /blacklist/',
        'method':      'GET',
        'path':        '/api/v1/blacklist/',
        'description': 'Fetch active IP blacklist (whitelist-filtered)',
        'auth':        'ip',
        'auth_html':   _AUTH_IP_HTML,
        'auth_pdf':    _AUTH_IP_PDF,
        'sections': [
            _params('Endpoints', 'Path', [
                ('/api/v1/blacklist/',      'All groups combined'),
                ('/api/v1/blacklist/24h/', '24-hour blacklist only'),
                ('/api/v1/blacklist/30d/', '30-day blacklist only'),
            ]),
            _params('Query Parameters', 'Parameter', [
                ('format=txt',     'Plain text output, one IP per line (firewall-friendly)'),
                ('page=1',         'Page number (JSON only)'),
                ('page_size=1000', 'Results per page, max 5000 (JSON only)'),
            ]),
            _code('curl Examples',
                '# JSON — all entries',
                'curl -k https://<host>:8443/api/v1/blacklist/',
                '',
                '# Plain text — firewall / script integration',
                'curl -k "https://<host>:8443/api/v1/blacklist/?format=txt"',
                '',
                '# 24h list only (plain text)',
                'curl -k "https://<host>:8443/api/v1/blacklist/24h/?format=txt"',
                '',
                '# Bash — add each IP to iptables',
                'curl -sk "https://<host>:8443/api/v1/blacklist/?format=txt" \\',
                '  | grep -v "^#" | grep -v "^$" \\',
                '  | xargs -I{} iptables -A INPUT -s {} -j DROP',
            ),
            _code('JSON Response',
                '# 200 OK',
                '{',
                '  "count": 142,',
                '  "page": 1,',
                '  "page_size": 1000,',
                '  "generated_at": "2024-01-01T10:00:00Z",',
                '  "entries": [',
                '    {',
                '      "ip": "192.168.1.100",',
                '      "group": "24h",',
                '      "added_at": "2024-01-01T09:00:00Z",',
                '      "expires_at": "2024-01-02T09:00:00Z"',
                '    }',
                '  ]',
                '}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
            ),
        ],
    },

    # ── 4. GET /hashlist/ ─────────────────────────────────────────────────
    {
        'tab_id':      'hashlist',
        'tab_label':   'GET /hashlist/',
        'method':      'GET',
        'path':        '/api/v1/hashlist/',
        'description': 'Fetch active hash blacklist',
        'auth':        'ip',
        'auth_html':   _AUTH_IP_HTML,
        'auth_pdf':    _AUTH_IP_PDF,
        'sections': [
            _params('Query Parameters', 'Parameter', [
                ('format=txt',     'Plain text output, one hash per line (firewall-friendly)'),
                ('page=1',         'Page number (JSON only)'),
                ('page_size=1000', 'Results per page, max 5000 (JSON only)'),
            ]),
            _params('Hash Types', 'Type', [
                ('MD5',    '32 hex characters', 'badge-blue'),
                ('SHA1',   '40 hex characters', 'badge-yellow'),
                ('SHA256', '64 hex characters', 'badge-purple'),
                ('SHA512', '128 hex characters', 'badge-pink'),
            ], badge_col=True),
            _code('curl Examples',
                '# JSON — all active hashes',
                'curl -k https://<host>:8443/api/v1/hashlist/',
                '',
                '# Plain text — one hash per line',
                'curl -k "https://<host>:8443/api/v1/hashlist/?format=txt"',
                '',
                '# Bash — import hashes into a YARA / detection tool',
                'curl -sk "https://<host>:8443/api/v1/hashlist/?format=txt" \\',
                '  | grep -v "^#" | grep -v "^$"',
            ),
            _code('JSON Response',
                '# 200 OK',
                '{',
                '  "count": 38,',
                '  "page": 1,',
                '  "page_size": 1000,',
                '  "generated_at": "2024-01-01T10:00:00Z",',
                '  "entries": [',
                '    {"hash": "d41d8cd98f00b204e9800998ecf8427e", "hash_type": "md5", "added_at": "..."},',
                '    {"hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash_type": "sha1", "added_at": "..."}',
                '  ]',
                '}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
            ),
        ],
    },

    # ── 5. POST /report/hash/ ─────────────────────────────────────────────
    {
        'tab_id':      'hash_report',
        'tab_label':   'POST /report/hash/',
        'method':      'POST',
        'path':        '/api/v1/report/hash/',
        'description': 'Add a file hash to the blacklist',
        'auth':        'token',
        'auth_html':   _AUTH_TOKEN_HTML,
        'auth_pdf':    _AUTH_TOKEN_PDF,
        'sections': [
            _code('Request Body (JSON)',
                '{',
                '  "hash": "d41d8cd98f00b204e9800998ecf8427e",',
                '  "reason": "Malware sample"',
                '}',
                '# hash   — required; MD5 (32), SHA1 (40), SHA256 (64), or SHA512 (128) hex string',
                '# reason — optional, default: "API report"',
                '# Hash type detected automatically from length:',
                '#   32 -> MD5 | 40 -> SHA1 | 64 -> SHA256 | 128 -> SHA512',
            ),
            _code('curl Example',
                '# Add an MD5 hash to the blacklist',
                'curl -k -X POST https://<host>:8443/api/v1/report/hash/ \\',
                '  -H "Authorization: Token <api_user-token>" \\',
                '  -H "X-Username: <api_user-username>" \\',
                '  -H "Content-Type: application/json" \\',
                '  -d \'{"hash": "d41d8cd98f00b204e9800998ecf8427e", "reason": "Malware sample"}\'',
            ),
            _code('Response',
                '# 201 Created — new hash added to the blacklist',
                '{',
                '  "status": "blacklisted",',
                '  "hash": "d41d8cd98f00b204e9800998ecf8427e",',
                '  "hash_type": "md5",',
                '  "action": "added",',
                '  "message": "New hash blacklist entry created.",',
                '  "is_active": true',
                '}',
                '',
                '# 200 OK — hash already on the list (active or inactive); the existing row',
                '#          is reactivated and re-queried against VirusTotal so its threat',
                '#          metadata reflects the latest scan.',
                '{',
                '  "status": "blacklisted",',
                '  "hash": "d41d8cd98f00b204e9800998ecf8427e",',
                '  "hash_type": "md5",',
                '  "action": "updated",',
                '  "message": "Existing hash blacklist entry refreshed with the latest VirusTotal data.",',
                '  "is_active": true',
                '}',
                '',
                '# 400 — Invalid hash format',
                '{"error": "\'xyz\' is not a valid hash. Accepted: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128) hex chars."}',
                '',
                '# 401 — Missing or invalid credentials',
                '{"error": "Authentication failed."}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
                '',
                '# 429 — Rate limit exceeded',
                '{"error": "Rate limit exceeded."}',
            ),
        ],
    },

    # ── 6. GET /urllist/ ──────────────────────────────────────────────────
    {
        'tab_id':      'urllist',
        'tab_label':   'GET /urllist/',
        'method':      'GET',
        'path':        '/api/v1/urllist/',
        'description': 'Fetch active URL blacklist',
        'auth':        'ip',
        'auth_html':   _AUTH_IP_HTML,
        'auth_pdf':    _AUTH_IP_PDF,
        'sections': [
            _params('Query Parameters', 'Parameter', [
                ('format=txt',     'Plain text output, one URL per line (proxy/firewall-friendly)'),
                ('page=1',         'Page number (JSON only)'),
                ('page_size=1000', 'Results per page, max 5000 (JSON only)'),
            ]),
            _code('curl Examples',
                '# JSON — all active URLs',
                'curl -k https://<host>:8443/api/v1/urllist/',
                '',
                '# Plain text — one URL per line (proxy blocklist import)',
                'curl -k "https://<host>:8443/api/v1/urllist/?format=txt"',
                '',
                '# Bash — feed a Squid / secure-web-gateway deny list',
                'curl -sk "https://<host>:8443/api/v1/urllist/?format=txt" \\',
                '  | grep -v "^#" | grep -v "^$" > /etc/squid/deny_urls.txt',
            ),
            _code('JSON Response',
                '# 200 OK',
                '{',
                '  "count": 42,',
                '  "page": 1,',
                '  "page_size": 1000,',
                '  "generated_at": "2024-01-01T10:00:00Z",',
                '  "entries": [',
                '    {"url": "https://phishing.example/login", "hostname": "phishing.example", "added_at": "..."},',
                '    {"url": "http://malicious.example/download.exe", "hostname": "malicious.example", "added_at": "..."}',
                '  ]',
                '}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
            ),
        ],
    },

    # ── 7. POST /report/url/ ──────────────────────────────────────────────
    {
        'tab_id':      'url_report',
        'tab_label':   'POST /report/url/',
        'method':      'POST',
        'path':        '/api/v1/report/url/',
        'description': 'Add a URL to the blacklist',
        'auth':        'token',
        'auth_html':   _AUTH_TOKEN_HTML,
        'auth_pdf':    _AUTH_TOKEN_PDF,
        'sections': [
            _code('Request Body (JSON)',
                '{',
                '  "url": "https://phishing.example/login",',
                '  "reason": "Credential theft page"',
                '}',
                '# url    — required; must start with http:// or https:// and include a host',
                '#          Normalized on insert: scheme + host lowercased, default port',
                '#          stripped, fragment (#…) removed. Query string preserved as-is.',
                '# reason — optional, default: "API report"',
            ),
            _code('curl Example',
                '# Add a phishing URL to the blacklist',
                'curl -k -X POST https://<host>:8443/api/v1/report/url/ \\',
                '  -H "Authorization: Token <api_user-token>" \\',
                '  -H "X-Username: <api_user-username>" \\',
                '  -H "Content-Type: application/json" \\',
                '  -d \'{"url": "https://phishing.example/login", "reason": "Credential theft page"}\'',
            ),
            _code('Response',
                '# 201 Created — new URL added to the blacklist',
                '{',
                '  "status":   "blacklisted",',
                '  "url":      "https://phishing.example/login",',
                '  "hostname": "phishing.example",',
                '  "action":   "added",',
                '  "message":  "New URL blacklist entry created.",',
                '  "is_active": true,',
                '  "virustotal": {"malicious": 12, "total": 92, "threshold": 5}',
                '}',
                '',
                '# 200 OK — URL already tracked; existing state respected (no reactivation,',
                '#          no VT re-query). Existing decisions (admin-deactivated,',
                '#          below-threshold) are preserved.',
                '{',
                '  "status":   "inactive",',
                '  "url":      "https://phishing.example/login",',
                '  "hostname": "phishing.example",',
                '  "action":   "existing",',
                '  "message":  "URL already tracked (currently inactive, VT=12/92) -- no changes made.",',
                '  "is_active": false',
                '}',
                '',
                '# 201 Created + VT unavailable — created, but VirusTotal did not respond.',
                '#              Entry is is_active=True (visible in admin console) yet',
                '#              hidden from /api/v1/urllist/ until a real verdict arrives.',
                '{',
                '  "status":     "blacklisted",',
                '  "action":     "added",',
                '  "is_active":  true,',
                '  "virustotal": {"status": "unavailable"}',
                '}',
                '',
                '# 400 — Invalid URL',
                '{"error": "\'ftp://…\' is not a valid URL. Must start with http:// or https:// and include a host."}',
                '',
                '# 401 — Missing or invalid credentials',
                '{"error": "Authentication failed."}',
                '',
                '# 403 — Source IP not allowed',
                '{"error": "Source IP not authorized."}',
                '',
                '# 429 — Rate limit exceeded',
                '{"error": "Rate limit exceeded."}',
            ),
        ],
    },
    # ── 8. GET /taxii/ — the TAXII 2.0 surface ────────────────────────────
    # One tab for all seven paths rather than seven tabs: a subscriber is
    # handed the discovery URL and walks the rest itself, so the endpoints
    # are more use as a map than as separate pages. Unlike every tab above,
    # these paths are NOT under /api/v1 — see BASE_URLS.
    {
        'tab_id':      'taxii',
        'tab_label':   'GET /taxii/',
        'method':      'GET',
        'path':        '/taxii/',
        'description': 'TAXII 2.0 discovery — blacklists as STIX 2.0 indicators (read-only)',
        'auth':        'basic',
        'auth_html':   _AUTH_BASIC_HTML,
        'auth_pdf':    _AUTH_BASIC_PDF,
        'sections': [
            _code('Credentials',
                '# username = an API User account, password = that account\'s API token',
                'Authorization: Basic base64("<api_user-username>:<api_user-token>")',
                '',
                '# curl encodes it for you:',
                'curl -k -u "<api_user-username>:<api_user-token>" https://<host>:8443/taxii/',
            ),
            _params('Endpoints', 'Path', [
                ('/taxii/',
                 'Discovery — the single URL you paste into the subscriber'),
                ('/taxii/<root>/',
                 'API root; advertises versions: ["taxii-2.0"]'),
                ('/taxii/<root>/collections/',
                 'Collection list (one collection = one subscribable feed)'),
                ('/taxii/<root>/collections/<id>/',
                 'Collection metadata; can_read true, can_write false'),
                ('/taxii/<root>/collections/<id>/objects/',
                 'The indicators, as a STIX 2.0 bundle'),
                ('/taxii/<root>/collections/<id>/objects/<obj-id>/',
                 'A single indicator by its STIX id'),
                ('/taxii/<root>/collections/<id>/manifest/',
                 'Manifest — ids + date_added only, for incremental sync'),
            ]),
            _params('Feeds', 'Feed', [
                ('url',  'URL Blacklist — mirrors GET /api/v1/urllist/'),
                ('ip',   'IP Blacklist — mirrors GET /api/v1/blacklist/'),
                ('hash', 'Hash Blacklist — mirrors GET /api/v1/hashlist/'),
            ]),
            _code('curl Example — discover, then poll',
                '# 1. Discovery: returns the api_roots this account may see',
                'curl -k -u "<api_user-username>:<api_user-token>" \\',
                '  https://<host>:8443/taxii/',
                '',
                '# 2. Collections under an API root (the id is a UUID, generated on creation)',
                'curl -k -u "<api_user-username>:<api_user-token>" \\',
                '  https://<host>:8443/taxii/urllist/collections/',
                '',
                '# 3. The indicators',
                'curl -k -u "<api_user-username>:<api_user-token>" \\',
                '  https://<host>:8443/taxii/urllist/collections/<collection-id>/objects/',
            ),
            _params('Query Parameters', 'Parameter', [
                ('added_after=2026-11-09T00:00:00Z',
                 'Incremental poll — only entries added strictly after this RFC 3339 '
                 'timestamp. An unparseable value is a 400, never a silent full pull.'),
                ('match[type]=indicator',
                 'Only indicators are ever published, so any other type yields an '
                 'empty bundle rather than an error (§3.5.1).'),
                ('match[id]=indicator--<uuid>',
                 'Comma-separated STIX ids. Ids are uuid5-derived and stable across '
                 'polls, so a subscriber updates in place instead of duplicating.'),
            ]),
            _code('Pagination — Range / Content-Range (TAXII 2.0, not 2.1)',
                '# 2.0 paginates with HTTP range headers and the `items` unit;',
                '# 2.1\'s more/next envelope fields do not apply here.',
                '# Note the SPACE after `items` — that is the spec\'s own form, and',
                '# RFC 7233\'s `items=0-49` is ignored (served as if unset).',
                'curl -k -u "<api_user-username>:<api_user-token>" \\',
                '  -H "Range: items 0-49" \\',
                '  https://<host>:8443/taxii/urllist/collections/<collection-id>/objects/',
                '',
                '# 206 Partial Content',
                '# Accept-Ranges: items',
                '# Content-Range: items 0-49/1396          <- inclusive, zero-indexed, /total',
                '# X-TAXII-Date-Added-First: 2026-11-04T08:12:03.000Z',
                '# X-TAXII-Date-Added-Last:  2026-11-11T17:15:44.000Z',
                '',
                '# Sending no Range at all is also answered 206, capped at the page size',
                '# in Settings -> TAXII 2.0 Server (default 500) -- a 1396-entry feed is',
                '# three polls, not one enormous response. A start past the end gives 416.',
            ),
            _code('Response — objects (STIX 2.0 bundle)',
                '# 200 OK / 206 Partial Content',
                '# Content-Type: application/vnd.oasis.stix+json; version=2.0',
                '{',
                '  "type": "bundle",',
                '  "id": "bundle--<uuid>",',
                '  "spec_version": "2.0",',
                '  "objects": [',
                '    {',
                '      "type": "indicator",',
                '      "id": "indicator--<uuid5, stable per entry>",',
                '      "created": "2026-11-04T08:12:03.000Z",',
                '      "modified": "2026-11-04T08:12:03.000Z",',
                '      "valid_from": "2026-11-04T08:12:03.000Z",',
                '      "labels": ["malicious-activity"],',
                '      "pattern": "[domain-name:value = \'phishing.example\']",',
                '      "name": "phishing.example",',
                '      "description": "..."',
                '    }',
                '  ]',
                '}',
                '',
                '# An empty result is an empty bundle, not an error.',
            ),
            _code('Response — manifest, and errors',
                '# 200 OK — manifest: ids and dates only, so a subscriber can tell what',
                '#          changed without pulling the patterns',
                '{',
                '  "objects": [',
                '    {',
                '      "id": "indicator--<uuid5>",',
                '      "date_added": "2026-11-04T08:12:03.000Z",',
                '      "versions": ["2026-11-04T08:12:03.000Z"],',
                '      "media_types": ["application/vnd.oasis.stix+json; version=2.0"]',
                '    }',
                '  ]',
                '}',
                '',
                '# Errors are TAXII `error` objects (§3.6.1), not the REST API\'s',
                '# {"error": "..."} shape:',
                '# Content-Type: application/vnd.oasis.taxii+json; version=2.0',
                '',
                '# 401 — no / bad credentials (carries WWW-Authenticate: Basic)',
                '{"title": "Unauthorized", "http_status": "401", "description": "..."}',
                '',
                '# 403 — source IP not allowed   404 — server off, or no such root/collection',
                '# 400 — bad added_after         416 — Range starts past the end',
            ),
            _params('Audit trail', 'Action', [
                ('api.taxii_discovery',   'Discovery was fetched'),
                ('api.taxii_api_root',    'An API root was read'),
                ('api.taxii_collections', 'The collection list was read'),
                ('api.taxii_collection',  'Collection metadata was read'),
                ('api.taxii_objects',     'A poll; detail records feed, served, total, partial'),
                ('api.taxii_object',      'A single indicator was fetched'),
                ('api.taxii_manifest',    'A manifest poll; same detail as objects'),
                ('api.taxii_denied',      'A caller was turned away; detail records the reason'),
            ]),
            _code('Where those rows show up',
                '# Every request above writes one activity-log row, the same way the',
                '# /api/v1/ endpoints do, so a subscriber\'s polls are visible without',
                '# reading cybercavalry.log:',
                '#',
                '#   Activity Log  -> type filter "API"   — the individual requests',
                '#   Dashboard     -> Request Timeline     — polls over time',
                '#                    (objects/manifest count as Feed pulls,',
                '#                     api.taxii_denied as Rejected, the rest as Other)',
                '#',
                '# Logging can never break a poll: a failure to write the row is',
                '# swallowed and the feed still answers.',
            ),
        ],
    },
]


# Placeholder substituted into code-block lines at render time so example
# responses (e.g. the status endpoint) reflect the configured platform name
# from Settings → General. Keep ENDPOINTS structurally static — use
# get_endpoints() to consume it.
_PLATFORM_PLACEHOLDER = '__PLATFORM_NAME__'


def _current_brand_name():
    try:
        from apps.settings_app.branding import platform_name
        return platform_name()
    except Exception:
        return 'CYBERCavalry'


def get_endpoints():
    """ENDPOINTS with the brand-name placeholder substituted in code lines."""
    import copy
    name = _current_brand_name()
    eps = copy.deepcopy(ENDPOINTS)
    for ep in eps:
        for sec in ep.get('sections', []):
            if sec.get('type') == 'code' and sec.get('lines'):
                sec['lines'] = [ln.replace(_PLATFORM_PLACEHOLDER, name) for ln in sec['lines']]
                # ...and in the pre-rendered HTML the WEB page uses. Patching
                # only `lines` left the placeholder visible in the browser.
                if sec.get('html'):
                    sec['html'] = sec['html'].replace(_PLATFORM_PLACEHOLDER, name)
    return eps
