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
    return eps
