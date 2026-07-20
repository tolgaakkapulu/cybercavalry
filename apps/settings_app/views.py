import csv
import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.views.decorators.http import require_POST
from django.db.models import Q

from .models import Setting, AllowedSourceIP, ActivityLog
from .cache import SettingsCache
from .net_util import build_ssl_context
from apps.accounts.decorators import login_required_custom, role_required
from apps.blacklist.utils import normalize_cidr, is_valid_ip_or_cidr

logger = logging.getLogger(__name__)


SETTING_LABELS = {
    'general.platform_name':               ('Platform Name',          'Primary part of the platform brand name shown in the browser title (e.g. CYBER).'),
    'general.platform_name_suffix':        ('Platform Name Suffix',   'Accent-coloured suffix of the brand name displayed in the UI (e.g. Cavalry).'),
    'general.platform_email':              ('Platform Email',         'Contact e-mail address shown in the sidebar footer and on all PDF report covers and footers.'),
    'general.dashboard_refresh_seconds':   ('Dashboard Refresh Interval', 'How often (in seconds) the dashboard auto-refreshes its stats, tables and charts. Allowed range 5–3600; default 60.'),
    'general.blacklist_refresh_seconds':   ('Blacklist Refresh Interval', 'How often (in seconds) the IP / Hash Blacklist list pages stream new rows into the table. Allowed range 1–3600; default 5. The page is not reloaded — only the table body refreshes.'),
    'general.default_theme':               ('Default Theme',           'Theme applied when a user has not yet chosen one. Each user can still switch themes from the UI; their choice is remembered in the browser.'),
    'general.brand_color':                 ('Brand Color',             'Accent colour used for the suffix of the platform name (sidebar / topbar / login / PDF cover) and the active navigation highlight. Pick any hex value; the system recomputes the matching translucent glow automatically.'),
    'general.brand_logo':                  ('Logo & Favicon',         'Brand logo shown across the UI and used as the browser favicon. SVG/PNG/JPG/WEBP/GIF/ICO, max 3 MB. Leave empty to use the built-in default.'),
    'general.brand_login':                 ('Login & Sidebar Image',   'Optional logo. When set, it replaces the icon+platform-name in the sidebar header and is shown above the email row on the login screen. SVG/PNG/JPG/WEBP/GIF, max 3 MB. Leave empty to keep the default icon+name layout.'),
    'general.brand_background':            ('Background Image',        'Optional background image for the login page and the app. SVG/PNG/JPG/WEBP/GIF, max 3 MB. Leave empty to keep the default themed background.'),
    'api.rate_limit_rpm':                  ('API Rate Limit',         'Maximum API requests per minute per token.'),
    'security.session_timeout':            ('Session Timeout',        'How long a UI session stays active without interaction.'),
    'security.lockout_attempts':           ('Max Login Attempts',     'Number of consecutive failed logins before the account is temporarily locked.'),
    'security.lockout_duration':           ('Lockout Duration',       'How long (in minutes) a locked account cannot sign in.'),
    'security.password_min_length':        ('Minimum Length',         'Minimum number of characters required in a password.'),
    'security.password_require_uppercase': ('Require Uppercase',      'Password must contain at least one uppercase letter (A–Z).'),
    'security.password_require_lowercase': ('Require Lowercase',      'Password must contain at least one lowercase letter (a–z).'),
    'security.password_require_digits':    ('Require Digits',         'Password must contain at least one digit (0–9).'),
    'security.password_require_symbols':   ('Require Symbols',        'Password must contain at least one symbol (e.g. !@#$%^&*).'),
    'ldap.enabled':                         ('Enable LDAP',            'Allow users to authenticate via LDAP/Active Directory.'),
    'ldap.server_uri':                      ('Server URI',             'LDAP server address, e.g. ldap://192.168.1.10 or ldaps://dc.example.com.'),
    'ldap.enabled':                         ('Enable LDAP',            'Turn on LDAP authentication integration.'),
    'ldap.bind_dn':                         ('Bind DN',                'Service account distinguished name used to search the directory.'),
    'ldap.bind_password':                   ('Bind Password',          'Password for the service account.'),
    'ldap.user_search_base':                ('User Search Base',       'Base DN to search for user accounts. Separate multiple bases with `;` (semicolon) to probe several OUs — they are tried in order and the first hit wins. Example: OU=Staff,DC=corp,DC=local;OU=Contractors,DC=corp,DC=local'),
    'ldap.user_search_filter':              ('User Search Filter',     'LDAP filter to locate user objects, e.g. (sAMAccountName=%(user)s).'),
    'ldap.use_ssl':                         ('Use SSL/TLS',            'Force SSL/TLS for the LDAP connection.'),
    'ldap.user_attr_map':                   ('Attribute Map',          'JSON map of LDAP attributes to Django user fields.'),
    'ldap.group_map':                       ('Group Map',              'JSON map of LDAP group DNs to platform roles.'),
    # ── Actions (automated notifications) ─────────────────────────────────
    # E-mail (SMTP) — used by every alert type below
    'actions.email_smtp_host':                      ('SMTP Host',                 'Outgoing mail server hostname (e.g. smtp.gmail.com).'),
    'actions.email_smtp_port':                      ('SMTP Port',                 'Outgoing mail server port. 587 for STARTTLS, 465 for implicit TLS, 25 for plaintext.'),
    'actions.email_smtp_user':                      ('SMTP Username',             'Account used to authenticate against the SMTP server. Leave empty for anonymous relays.'),
    'actions.email_smtp_password':                  ('SMTP Password',             'Password (or app-specific token) for the SMTP account.'),
    'actions.email_smtp_use_tls':                   ('Use STARTTLS',              'Wrap the connection in TLS after the initial SMTP handshake. Recommended for port 587.'),
    'actions.email_from_address':                   ('From Address',              'Envelope sender address (e.g. no-reply@corp.local). Leave empty to reuse SMTP Username.'),
    # Quota Alert — AbuseIPDB / VirusTotal daily quota watchdog
    'actions.quota_alert_enabled':                  ('Enable Quota Alert',        'Send an e-mail when AbuseIPDB or VirusTotal daily quota usage crosses the configured percentage.'),
    'actions.quota_alert_email':                    ('Recipient E-mail',          'Address(es) that receive quota-alert e-mails. Separate multiple addresses with a semicolon `;` — e.g. `ops@corp.tr; soc@corp.tr`. Leave empty to disable e-mails without turning the checker off.'),
    'actions.quota_alert_threshold_pct':            ('Alert Threshold',           'Fire the alert when either provider crosses this percentage of its configured daily quota (1–100).'),
    'actions.quota_check_interval':                 ('Check Interval',            'How often the quota checker runs. The number is interpreted according to the "Check Interval Unit" setting.'),
    'actions.quota_check_interval_unit':            ('Check Interval Unit',       'Time unit for the check interval — minutes or hours.'),
    'actions.quota_alert_cooldown_hours':           ('Alert Cooldown',            'After an alert is sent for a provider, suppress further e-mails for this many hours (prevents spam). Default 24.'),
    # API Rate Limit Alert — platform's own /api/* endpoints
    'actions.rate_limit_alert_enabled':             ('Enable Rate Limit Alert',   'Send an e-mail when a platform API caller crosses their configured per-minute rate-limit for two consecutive check windows.'),
    'actions.rate_limit_alert_email':               ('Recipient E-mail',          'Address(es) that receive API rate-limit alerts. Separate multiple addresses with a semicolon `;` — e.g. `ops@corp.tr; soc@corp.tr`.'),
    'actions.rate_limit_alert_threshold_pct':       ('Alert Threshold',           'Fire the alert when a caller\'s usage reaches this percentage of their per-minute rate-limit.'),
    'actions.rate_limit_alert_cooldown_hours':      ('Alert Cooldown',            'After an alert is sent for a caller, suppress further e-mails for this many hours.'),
    # Syslog forwarding
    'actions.syslog_enabled':                       ('Enable Syslog',             'Forward selected log streams to an external syslog collector.'),
    'actions.syslog_host':                          ('Syslog Host',               'Hostname or IP address of the syslog collector.'),
    'actions.syslog_port':                          ('Syslog Port',               'Port on the collector (514 is the common default).'),
    'actions.syslog_protocol':                      ('Protocol',                  'Transport protocol — UDP for classic RFC 3164, TCP for reliable delivery.'),
    'actions.syslog_send_activity':                 ('Forward Activity Logs',     'Ship every entry written to the platform activity log.'),
    'actions.syslog_send_error':                    ('Forward Error Logs',        'Ship Python error/warning log records emitted by the application.'),
    'actions.syslog_send_access':                   ('Forward Access Logs',       'Ship HTTP access-log lines from the request handler.'),
    'threat_intel.abuseipdb_enabled':               ('Enable AbuseIPDB',          'Turn on AbuseIPDB threat intelligence lookups.'),
    'threat_intel.abuseipdb_api_key':               ('API Key',                   'Your AbuseIPDB v2 API key.'),
    'threat_intel.abuseipdb_max_age_days':          ('Max Report Age',            'Only consider abuse reports from this many days back (1–365).'),
    'threat_intel.abuseipdb_auto_check':            ('Auto-Check on Add',         'Automatically query AbuseIPDB when a new IP is blacklisted.'),
    'threat_intel.abuseipdb_threshold_30d':         ('30-Day Group Threshold',    'IPs with abuse score ≥ this value are assigned to the 30-day blacklist group. (0–100)'),
    'threat_intel.abuseipdb_threshold_24h':         ('24h / No-Group Threshold',  'IPs with score ≥ this value (but below the 30d threshold) go to the 24-hour group. IPs below this score are deactivated. (0–100)'),
    'threat_intel.abuseipdb_promotion_threshold':   ('24h → 30d Promotion Threshold', 'Auto-promote a 24h entry to the 30d group once its recent API report count (inside the rolling window on the right) reaches this value. Leave empty or 0 to disable.'),
    'threat_intel.abuseipdb_promotion_window_days': ('Window (days)', 'Length of the rolling window (in days) evaluated by the promotion threshold. Range 1–30.'),
    'threat_intel.abuseipdb_schedule_enabled':      ('Auto Schedule',             'Enable automatic periodic AbuseIPDB score refresh for all active entries.'),
    'threat_intel.abuseipdb_schedule_interval':     ('Schedule Interval',         'How often to run the automatic refresh: hourly or daily.'),
    'threat_intel.abuseipdb_schedule_time':         ('Daily Run Time',            'Time of day to run the daily refresh (HH:MM, 24-hour clock, server timezone).'),
    'threat_intel.abuseipdb_cleanup_enabled':       ('Auto-Cleanup',              'Permanently delete inactive AbuseIPDB-scored entries that match the rule below. A detailed log entry is written for every run.'),
    'threat_intel.abuseipdb_cleanup_score_min':     ('Cleanup Rule',              'Delete inactive entries whose AbuseIPDB confidence score is within the [Min – Max] range AND that were added more than the retention days ago.'),
    'threat_intel.virustotal_enabled':              ('Enable VirusTotal',         'Turn on VirusTotal hash reputation lookups for the hash blacklist.'),
    'threat_intel.virustotal_api_key':              ('API Key',                   'Your VirusTotal v3 API key.'),
    'threat_intel.virustotal_auto_check':           ('Auto-Check on Add',         'Automatically query VirusTotal when a new hash is added to the blacklist.'),
    'threat_intel.virustotal_detection_threshold':  ('Detection Threshold',       'Minimum number of engines that must flag a hash as malicious to keep it active. Hashes scoring below this are automatically deactivated. Set to 0 to disable auto-deactivation.'),
    'threat_intel.virustotal_schedule_enabled':     ('Auto Schedule',             'Enable automatic periodic VirusTotal score refresh for all active hash blacklist entries.'),
    'threat_intel.virustotal_schedule_interval':    ('Schedule Interval',         'How often to run the automatic refresh: hourly or daily.'),
    'threat_intel.virustotal_schedule_time':        ('Daily Run Time',            'Time of day to run the daily refresh (HH:MM, 24-hour clock, server timezone).'),
    'threat_intel.virustotal_cleanup_enabled':      ('Auto-Cleanup',              'Permanently delete inactive VirusTotal-scored hashes that match the rule below. A detailed log entry is written for every run.'),
    'threat_intel.virustotal_cleanup_score_min':    ('Cleanup Rule',              'Delete inactive hashes whose VirusTotal malicious-engine count is within the [Min – Max] range AND that were added more than the retention days ago.'),
    'backup.enabled':                               ('Enable Daily Backup',       'Automatically take a full database backup every day at the configured time.'),
    'backup.directory':                             ('Backup Directory',          'Absolute path where backup files are written. Leave blank to use <project>/backups. Must be writable by the service user.'),
    'backup.time':                                  ('Daily Run Time',            'Time of day to run the backup (HH:MM, 24-hour clock, server timezone).'),
    'backup.retention_days':                        ('Retention (days)',          'Delete backups older than this many days. Set to 0 to keep all backups (fully cumulative).'),
    'backup.max_count':                             ('Maximum Backup Count',      'Keep at most this many most-recent backups; older ones are pruned automatically after each new backup. Set to 0 for unlimited.'),
}

# Keys hidden from the UI (still exist in DB)
HIDDEN_KEYS = {
    'general.items_per_page',
    # Legacy keys — superseded; kept in DB to avoid migration churn
    'api.require_auth_for_publish',
    'api.trust_proxy',
    'security.session_timeout_hours',
    'security.session_timeout_minutes',
}

# Keys pulled from their original category and merged into another
MERGE_INTO = {
    'api.rate_limit_rpm': 'security',
}


@login_required_custom
@role_required('admin')
def settings_index(request):
    # Ensure auto-provisioned settings exist in DB before rendering
    _ENSURE = {
        'security.session_timeout':    ('15',       'int', 'security', 'UI session timeout in minutes', False),
        'security.lockout_attempts':   ('5',        'int', 'security', 'Failed logins before lockout', False),
        'security.lockout_duration':   ('5',        'int', 'security', 'Lockout duration in minutes', False),
        'general.platform_name_suffix':('Cavalry', 'str', 'general',  'Accent-coloured suffix of the brand name', False),
        'general.platform_email':      ('',         'str', 'general',  'Contact email shown in sidebar footer and PDF reports', False),
        'general.dashboard_refresh_seconds': ('60', 'int', 'general',  'Dashboard auto-refresh interval in seconds', False),
        'general.blacklist_refresh_seconds':('5',  'int', 'general',  'IP/Hash Blacklist list-page auto-refresh interval in seconds', False),
        'general.default_theme':       ('light',    'str', 'general',  'Default theme for users without a saved preference (light/dark)', False),
        'general.brand_color':         ('#ee5356',  'str', 'general',  'Accent colour applied across the UI (hex #RRGGBB)', False),
        'general.brand_logo':          ('',         'str', 'general',  'Brand logo / favicon (relative media path)', False),
        'general.brand_login':         ('',         'str', 'general',  'Login screen logo (relative media path)', False),
        'general.brand_background':    ('',         'str', 'general',  'Background image (relative media path)', False),
        # Actions — SMTP (used by every alert type)
        'actions.email_smtp_host':              ('',        'str',  'actions', 'Outgoing SMTP server hostname', False),
        'actions.email_smtp_port':              ('587',     'int',  'actions', 'Outgoing SMTP server port', False),
        'actions.email_smtp_user':              ('',        'str',  'actions', 'SMTP username', False),
        'actions.email_smtp_password':          ('',        'str',  'actions', 'SMTP password', True),
        'actions.email_smtp_use_tls':           ('true',    'bool', 'actions', 'Wrap the connection in STARTTLS', False),
        'actions.email_from_address':           ('',        'str',  'actions', 'Envelope sender address', False),
        # Actions — quota-alert automation
        'actions.quota_alert_enabled':          ('false',   'bool', 'actions', 'Send alert e-mails when API quota crosses the threshold', False),
        'actions.quota_alert_email':            ('',        'str',  'actions', 'Recipient e-mail address for quota alerts', False),
        'actions.quota_alert_threshold_pct':    ('80',      'int',  'actions', 'Percentage of daily quota that triggers the alert (1–100)', False),
        'actions.quota_check_interval':         ('1',       'int',  'actions', 'How often the checker runs (in the configured unit)', False),
        'actions.quota_check_interval_unit':    ('hours',   'str',  'actions', 'Time unit for the check interval: minutes or hours', False),
        'actions.quota_alert_cooldown_hours':   ('24',      'int',  'actions', 'Suppress repeat alerts for a provider for this many hours', False),
        # Actions — API rate-limit alert (recipient/threshold/cooldown; monitor logic ships later)
        'actions.rate_limit_alert_enabled':      ('false',  'bool', 'actions', 'Send alert e-mails when an API caller crosses their rate limit', False),
        'actions.rate_limit_alert_email':        ('',       'str',  'actions', 'Recipient e-mail address for rate-limit alerts', False),
        'actions.rate_limit_alert_threshold_pct':('80',     'int',  'actions', 'Percentage of the per-minute rate-limit that triggers the alert', False),
        'actions.rate_limit_alert_cooldown_hours':('24',    'int',  'actions', 'Suppress repeat rate-limit alerts per caller for this many hours', False),
        # Actions — syslog forwarding
        'actions.syslog_enabled':                ('false',  'bool', 'actions', 'Enable syslog forwarding', False),
        'actions.syslog_host':                   ('',       'str',  'actions', 'Syslog collector hostname or IP', False),
        'actions.syslog_port':                   ('514',    'int',  'actions', 'Syslog collector port', False),
        'actions.syslog_protocol':               ('udp',    'str',  'actions', 'Transport protocol — udp or tcp', False),
        'actions.syslog_send_activity':          ('false',  'bool', 'actions', 'Forward activity-log entries to syslog', False),
        'actions.syslog_send_error':             ('false',  'bool', 'actions', 'Forward Python error/warning logs to syslog', False),
        'actions.syslog_send_access':            ('false',  'bool', 'actions', 'Forward HTTP access logs to syslog', False),
        'backup.enabled':              ('false',    'bool','backup',   'Enable automatic daily database backups', False),
        'backup.directory':            ('',         'str', 'backup',   'Directory for backup files; blank uses <project>/backups', False),
        'backup.time':                 ('04:00',    'str', 'backup',   'Daily backup run time (HH:MM)', False),
        'backup.retention_days':       ('30',       'int', 'backup',   'Delete backups older than N days; 0 keeps all', False),
        'backup.max_count':            ('0',        'int', 'backup',   'Keep at most N most-recent backups; 0 = unlimited', False),
        # Cleanup settings — duplicated from migration 0015 so they self-heal
        # on instances where the migration hasn't run yet (otherwise the
        # absorbed sibling rows render with defaults but can't save back,
        # because the save handler silently skips unknown keys).
        'threat_intel.abuseipdb_cleanup_enabled':         ('false', 'bool', 'threat_intel', 'Enable automatic cleanup of inactive AbuseIPDB-scored entries', False),
        'threat_intel.abuseipdb_cleanup_score_min':       ('0',     'int',  'threat_intel', 'Lower bound (0-100) of the AbuseIPDB score range eligible for cleanup', False),
        'threat_intel.abuseipdb_cleanup_score_max':       ('100',   'int',  'threat_intel', 'Upper bound (0-100) of the AbuseIPDB score range eligible for cleanup', False),
        'threat_intel.abuseipdb_cleanup_retention_days':  ('30',    'int',  'threat_intel', 'Delete eligible AbuseIPDB entries older than this many days', False),
        'threat_intel.virustotal_cleanup_enabled':        ('false', 'bool', 'threat_intel', 'Enable automatic cleanup of inactive VirusTotal-scored hashes', False),
        'threat_intel.virustotal_cleanup_score_min':      ('0',     'int',  'threat_intel', 'Lower bound (0-100) of the VirusTotal malicious-engine count eligible for cleanup', False),
        'threat_intel.virustotal_cleanup_score_max':      ('100',   'int',  'threat_intel', 'Upper bound (0-100) of the VirusTotal malicious-engine count eligible for cleanup', False),
        'threat_intel.virustotal_cleanup_retention_days': ('30',    'int',  'threat_intel', 'Delete eligible VirusTotal hashes older than this many days', False),
        'threat_intel.abuseipdb_promotion_threshold':     ('',      'int',  'threat_intel', 'Auto-promote a 24h entry to 30d group once its recent API report count reaches this value; empty/0 disables', False),
        'threat_intel.abuseipdb_promotion_window_days':   ('7',     'int',  'threat_intel', 'Length of the rolling window (days) evaluated by the promotion threshold; range 1–30', False),
    }
    for key, (val, vtype, cat, desc, secret) in _ENSURE.items():
        Setting.objects.get_or_create(
            key=key,
            defaults={'value': val, 'value_type': vtype, 'category': cat,
                      'description': desc, 'is_secret': secret},
        )

    settings_by_category = {}
    for s in Setting.objects.all():
        if s.key in HIDDEN_KEYS:
            continue
        target_cat = MERGE_INTO.get(s.key, s.category)
        settings_by_category.setdefault(target_cat, []).append(s)

    # Keys rendered inline inside another setting's row — excluded from the list
    # so the count in the accordion header stays accurate.
    # Their values are attached as attributes on the parent setting object.
    _INLINE_ABSORBED = {
        'general.platform_name_suffix':           'general.platform_name',
        'threat_intel.abuseipdb_schedule_time':   'threat_intel.abuseipdb_schedule_interval',
        'threat_intel.virustotal_schedule_time':  'threat_intel.virustotal_schedule_interval',
        'security.lockout_duration':              'security.lockout_attempts',
        # Cleanup rule fits on one row: min/max range plus retention days are
        # all absorbed into the score_min setting so the template can render
        # the three number inputs side by side.
        'threat_intel.abuseipdb_cleanup_score_max':       'threat_intel.abuseipdb_cleanup_score_min',
        'threat_intel.abuseipdb_cleanup_retention_days':  'threat_intel.abuseipdb_cleanup_score_min',
        'threat_intel.virustotal_cleanup_score_max':      'threat_intel.virustotal_cleanup_score_min',
        'threat_intel.virustotal_cleanup_retention_days': 'threat_intel.virustotal_cleanup_score_min',
        # Promotion rule: threshold count + window (days) render side-by-side.
        'threat_intel.abuseipdb_promotion_window_days':   'threat_intel.abuseipdb_promotion_threshold',
    }

    # Remove empty categories; attach label/hint to each setting object
    result = {}
    for cat, items in settings_by_category.items():
        if not items:
            continue
        # Attach absorbed values to their parent settings
        absorbed_map = {}  # absorbed_key -> setting object
        for s in items:
            if s.key in _INLINE_ABSORBED:
                absorbed_map[s.key] = s
        for absorbed_key, parent_key in _INLINE_ABSORBED.items():
            if absorbed_key in absorbed_map:
                parent = next((s for s in items if s.key == parent_key), None)
                if parent:
                    parent.inline_suffix = absorbed_map[absorbed_key].value
                    # Also expose under a tail-named attr so a parent that
                    # absorbs more than one sibling (e.g. cleanup_score_min
                    # absorbs both _score_max and _retention_days) can read
                    # each absorbed value individually in the template.
                    tail = absorbed_key.rsplit('.', 1)[-1]
                    setattr(parent, 'inline_' + tail, absorbed_map[absorbed_key].value)
                items.remove(absorbed_map[absorbed_key])

        from apps.settings_app.branding import BRAND_KEYS, brand_value_to_url
        for s in items:
            label_data = SETTING_LABELS.get(s.key)
            s.ui_label = label_data[0] if label_data else None
            s.ui_hint  = label_data[1] if label_data else s.description
            # Image settings render a file-upload control with a live preview.
            s.is_brand_image = s.key in BRAND_KEYS
            if s.is_brand_image:
                s.brand_url = brand_value_to_url(s.value)
            # For the Actions category, tag each setting with the tab it
            # belongs to so the template can hide/show rows with Alpine.
            if s.category == 'actions':
                if s.key.startswith('actions.email_'):
                    s.tab_key = 'email'
                elif s.key.startswith('actions.quota_'):
                    s.tab_key = 'quota'
                elif s.key.startswith('actions.rate_limit_'):
                    s.tab_key = 'rate_limit'
                elif s.key.startswith('actions.syslog_'):
                    s.tab_key = 'syslog'
                else:
                    s.tab_key = 'email'  # sensible default for future keys
        # Explicit ordering overrides for specific keys
        _KEY_ORDER = {
            'general.platform_name':            0,
            'general.platform_email':           1,
            'general.dashboard_refresh_seconds': 2,
            'general.blacklist_refresh_seconds':3,
            'general.default_theme':            4,
            'general.brand_color':              5,
            'general.brand_logo':               6,
            'general.brand_login':              7,
            'general.brand_background':         8,
            # Actions category — E-mail tab first, then per-alert-type tabs.
            'actions.email_smtp_host':               0,
            'actions.email_smtp_port':               1,
            'actions.email_smtp_user':               2,
            'actions.email_smtp_password':           3,
            'actions.email_smtp_use_tls':            4,
            'actions.email_from_address':            5,
            'actions.quota_alert_enabled':          10,
            'actions.quota_alert_email':            11,
            'actions.quota_alert_threshold_pct':    12,
            'actions.quota_check_interval':         13,
            'actions.quota_check_interval_unit':    14,
            'actions.quota_alert_cooldown_hours':   15,
            'actions.rate_limit_alert_enabled':          20,
            'actions.rate_limit_alert_email':            21,
            'actions.rate_limit_alert_threshold_pct':    22,
            'actions.rate_limit_alert_cooldown_hours':   23,
            'actions.syslog_enabled':                    30,
            'actions.syslog_host':                       31,
            'actions.syslog_port':                       32,
            'actions.syslog_protocol':                   33,
            'actions.syslog_send_activity':              34,
            'actions.syslog_send_error':                 35,
            'actions.syslog_send_access':                36,
        }
        # Sort: explicit order first, then enabled toggles, then schedule group, then alphabetical
        items.sort(key=lambda s: (
            _KEY_ORDER[s.key] if s.key in _KEY_ORDER else (
                102 if 'schedule' in s.key else
                100 if s.key.endswith('enabled') else 101
            ),
            s.key
        ))
        result[cat] = items

    # Explicit category order for the Settings page. Anything not listed here
    # falls in at the end so a future category stays visible until someone
    # decides where it belongs.
    _CATEGORY_ORDER = ('general', 'ldap', 'threat_intel', 'actions', 'password_policy', 'security', 'backup' )
    ordered = {cat: result[cat] for cat in _CATEGORY_ORDER if cat in result}
    for cat, items in result.items():
        if cat not in ordered:
            ordered[cat] = items
    result = ordered

    try:
        from apps.blacklist.scheduler import get_status as _sched_status
        scheduler_status = _sched_status()
    except Exception:
        scheduler_status = {'running': False, 'next_run': None, 'job_exists': False}

    # Last scheduled run from ActivityLog
    last_scheduled_run = None
    try:
        from .models import ActivityLog as _AL
        from django.utils import timezone as _tz
        last_log = _AL.objects.filter(
            action='threat_intel.abuseipdb_scheduled_refresh'
        ).order_by('-timestamp').first()
        if last_log:
            last_scheduled_run = {
                'timestamp': _tz.localtime(last_log.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'detail': last_log.detail or {},
            }
    except Exception:
        pass

    last_vt_scheduled_run = None
    try:
        from .models import ActivityLog as _AL
        from django.utils import timezone as _tz
        last_vt_log = _AL.objects.filter(
            action='threat_intel.virustotal_scheduled_refresh'
        ).order_by('-timestamp').first()
        if last_vt_log:
            last_vt_scheduled_run = {
                'timestamp': _tz.localtime(last_vt_log.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                'detail': last_vt_log.detail or {},
            }
    except Exception:
        pass

    try:
        from apps.blacklist.scheduler import get_vt_status as _vt_sched_status
        vt_scheduler_status = _vt_sched_status()
    except Exception:
        vt_scheduler_status = {'running': False, 'next_run': None, 'job_exists': False}

    try:
        from apps.settings_app.cache import SettingsCache as _SC
        pw_policy = {
            'min_length':        int(_SC.get('security.password_min_length', 8) or 8),
            'require_uppercase': _SC.get('security.password_require_uppercase', True),
            'require_lowercase': _SC.get('security.password_require_lowercase', True),
            'require_digits':    _SC.get('security.password_require_digits', True),
            'require_symbols':   _SC.get('security.password_require_symbols', True),
        }
    except Exception:
        pw_policy = {'min_length': 8, 'require_uppercase': True,
                     'require_lowercase': True, 'require_digits': True, 'require_symbols': True}

    # Backup scheduler status + recent backups
    try:
        from apps.blacklist.scheduler import get_backup_status as _bk_status
        backup_status = _bk_status()
    except Exception:
        backup_status = {'running': False, 'next_run': None, 'job_exists': False}

    backup_dir = ''
    recent_backups = []
    last_backup = None
    try:
        from apps.settings_app.backup_service import list_backups, get_backup_dir
        backup_dir = str(get_backup_dir())
        for b in list_backups()[:5]:
            recent_backups.append({
                'name': b['name'],
                'size_kb': round(b['size_bytes'] / 1024, 1),
                'modified': b['modified'].strftime('%Y-%m-%d %H:%M'),
            })
        if recent_backups:
            last_backup = recent_backups[0]
    except Exception:
        pass

    return render(request, 'settings_app/index.html', {
        'settings_by_category': result,
        'scheduler_status': scheduler_status,
        'last_scheduled_run': last_scheduled_run,
        'vt_scheduler_status': vt_scheduler_status,
        'last_vt_scheduled_run': last_vt_scheduled_run,
        'pw_policy': pw_policy,
        'backup_status': backup_status,
        'backup_dir': backup_dir,
        'recent_backups': recent_backups,
        'last_backup': last_backup,
    })


_SCORE_THRESHOLD_KEYS = {
    'threat_intel.abuseipdb_threshold_24h',
    'threat_intel.abuseipdb_threshold_30d',
}
_PROMOTION_KEYS = {
    'threat_intel.abuseipdb_promotion_threshold',
    'threat_intel.abuseipdb_promotion_window_days',
}
# Union kept for save-change detection; downstream handling distinguishes
# score-threshold changes (full re-evaluation) from promotion-knob changes
# (group re-assignment only, no is_active toggles).
_THRESHOLD_KEYS = _SCORE_THRESHOLD_KEYS | _PROMOTION_KEYS

_VT_THRESHOLD_KEY = 'threat_intel.virustotal_detection_threshold'

_SCHEDULE_KEYS = {
    'threat_intel.abuseipdb_schedule_enabled',
    'threat_intel.abuseipdb_schedule_interval',
    'threat_intel.abuseipdb_schedule_time',
    'threat_intel.abuseipdb_cleanup_enabled',     # toggling cleanup must re-arm the job
    'threat_intel.virustotal_schedule_enabled',
    'threat_intel.virustotal_schedule_interval',
    'threat_intel.virustotal_schedule_time',
    'threat_intel.virustotal_cleanup_enabled',    # toggling cleanup must re-arm the job
}

_VT_SCHEDULE_KEYS = {
    'threat_intel.virustotal_schedule_enabled',
    'threat_intel.virustotal_schedule_interval',
    'threat_intel.virustotal_schedule_time',
    'threat_intel.virustotal_cleanup_enabled',
}

_BACKUP_KEYS = {
    'backup.enabled',
    'backup.directory',
    'backup.time',
    'backup.retention_days',
}


@login_required_custom
@role_required('admin')
def settings_save(request):
    # Wrap the entire body: an unhandled exception used to bubble up to
    # Django's 500 HTML page, which the AJAX client couldn't parse ("Unexpected
    # token '<'"). Now any surprise still returns valid JSON so the toast shows
    # the real reason and the server log carries the traceback.
    try:
        return _settings_save_impl(request)
    except Exception as exc:
        logger.error("settings_save crashed: %s", exc, exc_info=True)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return JsonResponse({
                'success': False,
                'messages': [{'level': 'error', 'text': f'Save failed: {exc}'}],
            }, status=500)
        messages.error(request, f'Save failed: {exc}')
        return redirect('settings_app:index')


def _settings_save_impl(request):
    if request.method == 'POST':
        category = request.POST.get('category', 'all')
        updated = 0
        threshold_changed = False
        score_threshold_changed = False
        promotion_threshold_changed = False
        vt_threshold_changed = False
        # AJAX-aware save: when the form is submitted via fetch with the
        # standard XHR header, we collect notifications into a JSON list
        # and skip the redirect so the page can stay put. Non-AJAX submits
        # (no JS) still get the redirect + Django messages framework.
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        ajax_msgs = []

        def add_msg(level, text):
            ajax_msgs.append({'level': level, 'text': text})
            if not is_ajax:
                getattr(messages, level)(request, text)

        for key, value in request.POST.items():
            if key.startswith('setting_'):
                setting_key = key[len('setting_'):]
                # Auto-provision settings that may not exist in older DBs
                _AUTO_CREATE = {
                    'general.platform_name_suffix': ('Cavalry', 'str', 'general', 'Accent-coloured suffix of the brand name', False),
                    'general.platform_email':       ('', 'str', 'general', 'Contact email shown in sidebar footer and PDF reports', False),
                    'general.dashboard_refresh_seconds': ('60', 'int', 'general', 'Dashboard auto-refresh interval in seconds', False),
                    'general.blacklist_refresh_seconds':('5',  'int', 'general', 'IP/Hash Blacklist list-page auto-refresh interval in seconds', False),
                    'general.default_theme':         ('light', 'str', 'general', 'Default theme for users without a saved preference (light/dark)', False),
                    'general.brand_color':           ('#ee5356', 'str', 'general', 'Accent colour applied across the UI (hex #RRGGBB)', False),
                    'security.session_timeout':     ('15', 'int', 'security', 'UI session timeout in minutes', False),
                    'security.lockout_attempts':    ('5',  'int', 'security', 'Failed logins before lockout', False),
                    'security.lockout_duration':    ('5',  'int', 'security', 'Lockout duration in minutes', False),
                    'backup.enabled':               ('false', 'bool', 'backup', 'Enable automatic daily database backups', False),
                    'backup.directory':             ('',   'str', 'backup', 'Directory for backup files; blank uses <project>/backups', False),
                    'backup.time':                  ('04:00', 'str', 'backup', 'Daily backup run time (HH:MM)', False),
                    'backup.retention_days':        ('30', 'int', 'backup', 'Delete backups older than N days; 0 keeps all', False),
                    'backup.max_count':             ('0',  'int', 'backup', 'Keep at most N most-recent backups; 0 = unlimited', False),
                    # Cleanup rule absorbed siblings — must be self-creatable
                    # here so the 3-input packed row in the AbuseIPDB / VT
                    # tabs can write back even on instances where migration
                    # 0015 hasn't run yet.
                    'threat_intel.abuseipdb_cleanup_enabled':         ('false', 'bool', 'threat_intel', 'Enable automatic cleanup of inactive AbuseIPDB-scored entries', False),
                    'threat_intel.abuseipdb_cleanup_score_min':       ('0',     'int',  'threat_intel', 'Lower bound (0-100) of the AbuseIPDB score range eligible for cleanup', False),
                    'threat_intel.abuseipdb_cleanup_score_max':       ('100',   'int',  'threat_intel', 'Upper bound (0-100) of the AbuseIPDB score range eligible for cleanup', False),
                    'threat_intel.abuseipdb_cleanup_retention_days':  ('30',    'int',  'threat_intel', 'Delete eligible AbuseIPDB entries older than this many days', False),
                    'threat_intel.virustotal_cleanup_enabled':        ('false', 'bool', 'threat_intel', 'Enable automatic cleanup of inactive VirusTotal-scored hashes', False),
                    'threat_intel.virustotal_cleanup_score_min':      ('0',     'int',  'threat_intel', 'Lower bound (0-100) of the VirusTotal malicious-engine count eligible for cleanup', False),
                    'threat_intel.virustotal_cleanup_score_max':      ('100',   'int',  'threat_intel', 'Upper bound (0-100) of the VirusTotal malicious-engine count eligible for cleanup', False),
                    'threat_intel.virustotal_cleanup_retention_days': ('30',    'int',  'threat_intel', 'Delete eligible VirusTotal hashes older than this many days', False),
                }
                try:
                    s = Setting.objects.get(key=setting_key)
                except Setting.DoesNotExist:
                    if setting_key in _AUTO_CREATE:
                        val, vtype, cat, desc, secret = _AUTO_CREATE[setting_key]
                        s = Setting.objects.create(
                            key=setting_key, value=val, value_type=vtype,
                            category=cat, description=desc, is_secret=secret,
                        )
                    else:
                        continue
                # Secret fields: skip if submitted value is blank (user left it unchanged)
                if s.is_secret and not value:
                    continue
                if s.plain_value != value:
                    if setting_key in _THRESHOLD_KEYS:
                        threshold_changed = True
                    if setting_key in _SCORE_THRESHOLD_KEYS:
                        score_threshold_changed = True
                    if setting_key in _PROMOTION_KEYS:
                        promotion_threshold_changed = True
                    if setting_key == _VT_THRESHOLD_KEY:
                        vt_threshold_changed = True
                    s.value = value
                    s.updated_by = request.user
                    s.save(update_fields=['value', 'updated_by', 'updated_at'])
                    SettingsCache.invalidate(setting_key)
                    updated += 1

        # ── Brand image uploads / removals (General tab) ─────────────────────
        from apps.settings_app.branding import (
            BRAND_KEYS, save_brand_image, clear_brand_image,
        )
        for bkey in BRAND_KEYS:
            uploaded = request.FILES.get('file_' + bkey)
            remove   = request.POST.get('remove_' + bkey)
            if not uploaded and not remove:
                continue
            s, _ = Setting.objects.get_or_create(
                key=bkey,
                defaults={'value': '', 'value_type': 'str', 'category': 'general',
                          'description': 'Brand image (relative media path)', 'is_secret': False},
            )
            if remove:
                if s.value:
                    clear_brand_image(s.value)
                    s.value = ''
                    s.updated_by = request.user
                    s.save(update_fields=['value', 'updated_by', 'updated_at'])
                    SettingsCache.invalidate(bkey)
                    updated += 1
            elif uploaded:
                rel, err = save_brand_image(bkey, uploaded)
                if err:
                    add_msg('error', f"{SETTING_LABELS.get(bkey, (bkey,))[0]}: {err}")
                else:
                    if s.value and s.value != rel:
                        clear_brand_image(s.value)
                    s.value = rel
                    s.updated_by = request.user
                    s.save(update_fields=['value', 'updated_by', 'updated_at'])
                    SettingsCache.invalidate(bkey)
                    updated += 1

        section = category.replace('_', ' ').title() if category != 'all' else 'All'
        add_msg('success', f"{section}: {updated} setting(s) saved.")
        ActivityLog.log(request.user, 'settings.save', 'Setting', category,
                     {'updated_count': updated, 'category': category},
                     getattr(request, 'client_ip', ''))

        if score_threshold_changed or promotion_threshold_changed:
            try:
                from apps.blacklist import abuseipdb_service
                # Score threshold change → full re-evaluation (may
                # activate/deactivate based on new score bands). Promotion-only
                # change → group re-assignment on active rows only, no
                # is_active toggles (avoids waking up dormant entries).
                if score_threshold_changed:
                    reactivated, deactivated, reassigned = abuseipdb_service.reapply_thresholds()
                    label = "Threshold change applied to scored entries"
                else:
                    reactivated, deactivated, reassigned = abuseipdb_service.reapply_thresholds(promotion_only=True)
                    label = "Promotion rule applied to active entries"
                parts = []
                if reactivated:
                    parts.append(f"{reactivated} re-activated")
                if deactivated:
                    parts.append(f"{deactivated} deactivated")
                if reassigned:
                    parts.append(f"{reassigned} reassigned to a different group")
                if parts:
                    add_msg('info', f"{label}: {', '.join(parts)}.")
                else:
                    add_msg('info', f"{label} — no entries required changes.")
            except Exception as e:
                logger.error(f"Failed to reapply AbuseIPDB thresholds: {e}")
                add_msg('warning', "Threshold saved, but automatic re-evaluation failed. Check server logs.")

        if vt_threshold_changed:
            try:
                from apps.hashlist.virustotal_service import reapply_vt_threshold
                activated, deactivated = reapply_vt_threshold()
                parts = []
                if activated:
                    parts.append(f"{activated} re-activated")
                if deactivated:
                    parts.append(f"{deactivated} deactivated")
                if parts:
                    add_msg('info', f"VirusTotal threshold applied to scored hashes: {', '.join(parts)}.")
                else:
                    add_msg('info', "VirusTotal threshold updated — no scored hashes required changes.")
            except Exception as e:
                logger.error(f"Failed to reapply VirusTotal threshold: {e}")
                add_msg('warning', "VirusTotal threshold saved, but automatic re-evaluation failed. Check server logs.")

        # Reschedule AbuseIPDB if schedule settings changed
        abuse_schedule_changed = any(
            key[len('setting_'):] in (_SCHEDULE_KEYS - _VT_SCHEDULE_KEYS)
            for key in request.POST
            if key.startswith('setting_')
        )
        if abuse_schedule_changed:
            try:
                from apps.blacklist.scheduler import reschedule
                reschedule()
            except Exception as e:
                logger.error(f"Failed to reschedule AbuseIPDB job: {e}")

        # Reschedule VirusTotal if VT schedule settings changed
        vt_schedule_changed = any(
            key[len('setting_'):] in _VT_SCHEDULE_KEYS
            for key in request.POST
            if key.startswith('setting_')
        )
        if vt_schedule_changed:
            try:
                from apps.blacklist.scheduler import reschedule_vt
                reschedule_vt()
            except Exception as e:
                logger.error(f"Failed to reschedule VirusTotal job: {e}")

        # Reschedule DB backup if backup settings changed
        backup_changed = any(
            key[len('setting_'):] in _BACKUP_KEYS
            for key in request.POST
            if key.startswith('setting_')
        )
        if backup_changed:
            try:
                from apps.blacklist.scheduler import reschedule_backup
                reschedule_backup()
            except Exception as e:
                logger.error(f"Failed to reschedule DB backup job: {e}")

        # Reschedule the quota alert job if any actions.* setting changed.
        actions_changed = any(
            key[len('setting_'):].startswith('actions.')
            for key in request.POST
            if key.startswith('setting_')
        )
        if actions_changed:
            try:
                from apps.blacklist.scheduler import (
                    reschedule_quota_alert, reschedule_rate_limit_alert,
                )
                reschedule_quota_alert()
                reschedule_rate_limit_alert()
            except Exception as e:
                logger.error(f"Failed to reschedule alert jobs: {e}")
            # Drop the syslog socket cache so the next emit picks up any
            # host/port/protocol change immediately.
            try:
                from apps.settings_app.syslog_service import invalidate as _syslog_invalidate
                _syslog_invalidate()
            except Exception as e:
                logger.error(f"Failed to invalidate syslog cache: {e}")

        if is_ajax:
            return JsonResponse({
                'success': True,
                'updated_count': updated,
                'messages': ajax_msgs,
            })

    return redirect('settings_app:index')


@login_required_custom
@role_required('admin')
@require_POST
def backup_now(request):
    """Manually trigger an immediate database backup. Returns JSON."""
    from apps.settings_app.backup_service import run_backup
    result = run_backup(user=request.user, trigger='manual',
                        ip_address=getattr(request, 'client_ip', ''))
    return JsonResponse({
        'success': result.get('success', False),
        'message': result.get('message', ''),
    })


@login_required_custom
@role_required('admin')
def ldap_test(request):
    """Test LDAP connection with current settings."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        import ldap3
    except ImportError:
        return JsonResponse({'success': False, 'message': 'ldap3 not installed. Run: pip install ldap3'})

    # Prefer values submitted in the request (unsaved form state); fall back to saved cache.
    server_uri    = request.POST.get('server_uri', '').strip()    or SettingsCache.get('ldap.server_uri', '')
    bind_dn       = request.POST.get('bind_dn', '').strip()       or SettingsCache.get('ldap.bind_dn', '')
    bind_password = request.POST.get('bind_password', '').strip() or SettingsCache.get('ldap.bind_password', '')

    if not server_uri:
        return JsonResponse({'success': False, 'message': 'LDAP server URI not configured.'})

    try:
        use_ssl = server_uri.startswith('ldaps://')
        host = server_uri.replace('ldaps://', '').replace('ldap://', '')
        port = 636 if use_ssl else 389
        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            port = int(port_str)

        server = ldap3.Server(host, port=port, use_ssl=use_ssl, connect_timeout=5)
        conn = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        conn.unbind()
        return JsonResponse({'success': True, 'message': f'Connected to {server_uri} successfully.'})
    except Exception as e:
        logger.warning(f"LDAP test connection failed: {e}")
        return JsonResponse({'success': False, 'message': f'Connection failed: {e}'})


@login_required_custom
@role_required('admin')
def source_ip_list(request):
    status = request.GET.get('status', 'active')
    qs = AllowedSourceIP.objects.select_related('added_by').all()

    count_active   = qs.filter(is_active=True).count()
    count_inactive = qs.filter(is_active=False).count()
    count_all      = qs.count()

    if status == 'inactive':
        entries = qs.filter(is_active=False)
    elif status == 'all':
        entries = qs
    else:
        status = 'active'
        entries = qs.filter(is_active=True)

    return render(request, 'settings_app/source_ip_list.html', {
        'entries': entries,
        'status': status,
        'count_active': count_active,
        'count_inactive': count_inactive,
        'count_all': count_all,
    })


@login_required_custom
@role_required('admin')
def source_ip_add(request):
    if request.method == 'POST':
        cidr_input = request.POST.get('cidr', '').strip()
        label = request.POST.get('label', '').strip()

        if not is_valid_ip_or_cidr(cidr_input):
            messages.error(request, f"'{cidr_input}' is not a valid IP address or CIDR.")
        else:
            cidr, ip, prefix = normalize_cidr(cidr_input)
            if AllowedSourceIP.objects.filter(cidr=cidr).exists():
                messages.warning(request, f"{cidr} is already in the allowed source IP list.")
            else:
                AllowedSourceIP.objects.create(cidr=cidr, label=label, added_by=request.user)
                messages.success(request, f"{cidr} added to allowed sources.")
                ActivityLog.log(request.user, 'source_ip.add', 'AllowedSourceIP', cidr,
                             {'label': label}, getattr(request, 'client_ip', ''))
    return redirect('settings_app:source_ip_list')


@login_required_custom
@role_required('admin')
@require_POST
def source_ip_activate(request, entry_id):
    from django.urls import reverse
    entry = get_object_or_404(AllowedSourceIP, pk=entry_id)
    entry.is_active = True
    entry.save(update_fields=['is_active'])
    messages.success(request, f"{entry.cidr} activated.")
    ActivityLog.log(request.user, 'source_ip.activate', 'AllowedSourceIP', str(entry_id),
                 {'cidr': entry.cidr}, getattr(request, 'client_ip', ''))
    return redirect(reverse('settings_app:source_ip_list') + '?status=inactive')


@login_required_custom
@role_required('admin')
@require_POST
def source_ip_deactivate(request, entry_id):
    from django.urls import reverse
    entry = get_object_or_404(AllowedSourceIP, pk=entry_id)
    entry.is_active = False
    entry.save(update_fields=['is_active'])
    messages.success(request, f"{entry.cidr} deactivated.")
    ActivityLog.log(request.user, 'source_ip.deactivate', 'AllowedSourceIP', str(entry_id),
                 {'cidr': entry.cidr}, getattr(request, 'client_ip', ''))
    return redirect(reverse('settings_app:source_ip_list') + '?status=active')


@login_required_custom
@role_required('admin')
def source_ip_delete(request, entry_id):
    entry = get_object_or_404(AllowedSourceIP, pk=entry_id)
    if request.method == 'POST':
        cidr = entry.cidr
        entry.delete()
        messages.success(request, f"{cidr} removed from allowed sources.")
        ActivityLog.log(request.user, 'source_ip.delete', 'AllowedSourceIP', str(entry_id),
                     {'cidr': cidr}, getattr(request, 'client_ip', ''))
    return redirect('settings_app:source_ip_list')


@login_required_custom
@role_required('admin')
@require_POST
def source_ip_edit(request, entry_id):
    entry = get_object_or_404(AllowedSourceIP, pk=entry_id)
    cidr_input = request.POST.get('cidr', '').strip()
    label = request.POST.get('label', '').strip()

    if not is_valid_ip_or_cidr(cidr_input):
        messages.error(request, f"'{cidr_input}' is not a valid IP address or CIDR.")
        return redirect('settings_app:source_ip_list')

    cidr, ip, prefix = normalize_cidr(cidr_input)
    old_cidr  = entry.cidr
    old_label = entry.label or ''

    if cidr != old_cidr and AllowedSourceIP.objects.filter(cidr=cidr).exclude(pk=entry_id).exists():
        messages.warning(request, f"{cidr} is already in the allowed source IP list.")
        return redirect('settings_app:source_ip_list')

    entry.cidr = cidr
    entry.label = label
    entry.save(update_fields=['cidr', 'label'])
    messages.success(request, f"Source IP updated.")
    ActivityLog.log(request.user, 'source_ip.edit', 'AllowedSourceIP', str(entry_id),
                 {
                     'old_cidr':  old_cidr,  'new_cidr':  cidr,
                     'old_label': old_label, 'new_label': label,
                     'label':     label,   # backwards-compat with existing readers
                 },
                 getattr(request, 'client_ip', ''))
    return redirect('settings_app:source_ip_list')


@login_required_custom
@role_required('admin')
@require_POST
def source_ip_bulk_activate(request):
    ids = request.POST.getlist('entry_ids')
    if not ids:
        messages.warning(request, "No entries selected.")
        return redirect('settings_app:source_ip_list')
    entries = AllowedSourceIP.objects.filter(pk__in=ids, is_active=False)
    cidrs = list(entries.values_list('cidr', flat=True))
    count = entries.update(is_active=True)
    messages.success(request, f"{count} source IP{'s' if count != 1 else ''} activated.")
    ActivityLog.log(request.user, 'source_ip.bulk_activate', 'AllowedSourceIP', None,
                 {'count': count, 'cidrs': cidrs}, getattr(request, 'client_ip', ''))
    status = request.POST.get('status', 'inactive')
    from django.urls import reverse
    return redirect(reverse('settings_app:source_ip_list') + f'?status={status}')


@login_required_custom
@role_required('admin')
@require_POST
def source_ip_bulk_deactivate(request):
    ids = request.POST.getlist('entry_ids')
    if not ids:
        messages.warning(request, "No entries selected.")
        return redirect('settings_app:source_ip_list')
    entries = AllowedSourceIP.objects.filter(pk__in=ids, is_active=True)
    cidrs = list(entries.values_list('cidr', flat=True))
    count = entries.update(is_active=False)
    messages.success(request, f"{count} source IP{'s' if count != 1 else ''} deactivated.")
    ActivityLog.log(request.user, 'source_ip.bulk_deactivate', 'AllowedSourceIP', None,
                 {'count': count, 'cidrs': cidrs}, getattr(request, 'client_ip', ''))
    status = request.POST.get('status', 'active')
    from django.urls import reverse
    return redirect(reverse('settings_app:source_ip_list') + f'?status={status}')


@login_required_custom
@role_required('admin')
@require_POST
def source_ip_bulk_delete(request):
    ids = request.POST.getlist('entry_ids')
    if not ids:
        messages.warning(request, "No entries selected.")
        return redirect('settings_app:source_ip_list')
    entries = AllowedSourceIP.objects.filter(pk__in=ids)
    cidrs = list(entries.values_list('cidr', flat=True))
    count = entries.count()
    entries.delete()
    messages.success(request, f"{count} source IP{'s' if count != 1 else ''} removed.")
    ActivityLog.log(request.user, 'source_ip.bulk_delete', 'AllowedSourceIP', None,
                 {'count': count, 'cidrs': cidrs}, getattr(request, 'client_ip', ''))
    status = request.POST.get('status', 'active')
    from django.urls import reverse
    return redirect(reverse('settings_app:source_ip_list') + f'?status={status}')


def _apply_activity_filters(logs, request):
    """Shared filter logic for activity_log and activity_log_export."""
    from django.utils import timezone as tz
    from datetime import timedelta, datetime

    action_filter = request.GET.get('action', '').strip()
    user_filter   = request.GET.get('user', '').strip()
    detail_filter = request.GET.get('detail', '').strip()
    type_filter   = request.GET.get('type', '').strip()
    date_range    = request.GET.get('date_range', '24h').strip()
    date_from_raw = request.GET.get('date_from', '').strip()
    date_to_raw   = request.GET.get('date_to', '').strip()

    # ── Type filter ──────────────────────────────────────────────────
    if action_filter:
        logs = logs.filter(action__icontains=action_filter)
    if user_filter:
        logs = logs.filter(user__username__icontains=user_filter)
    if detail_filter:
        # JSONField stored as text on SQLite (and serialisable on Postgres). Cast
        # to text and run a case-insensitive substring match — works on both.
        from django.db.models import TextField
        from django.db.models.functions import Cast
        logs = logs.annotate(_detail_text=Cast('detail', output_field=TextField())) \
                   .filter(_detail_text__icontains=detail_filter)
    if type_filter == 'page':
        logs = logs.filter(action__startswith='page.')
    elif type_filter == 'auth':
        logs = logs.filter(action__startswith='auth.')
    elif type_filter == 'user':
        logs = logs.filter(action__startswith='user.')
    elif type_filter == 'threat_intel':
        logs = logs.filter(
            Q(action__startswith='threat_intel.') |
            Q(action__startswith='blacklist.') |
            Q(action__in=['api.report', 'api.blacklist'])
        )
    elif type_filter == 'ip_blacklist':
        logs = logs.filter(
            Q(action__startswith='threat_intel.abuseipdb') |
            Q(action__startswith='blacklist.') |
            Q(action__in=['api.report', 'api.blacklist'])
        )
    elif type_filter == 'whitelist':
        logs = logs.filter(action__startswith='whitelist.')
    elif type_filter == 'hashlist':
        logs = logs.filter(
            Q(action__startswith='hashlist.') |
            Q(action__in=['api.hashlist', 'api.hash_report'])
        )
    elif type_filter == 'hash_blacklist':
        logs = logs.filter(
            Q(action__startswith='hashlist.') |
            Q(action__startswith='threat_intel.virustotal') |
            Q(action__in=['api.hashlist', 'api.hash_report'])
        )
    elif type_filter == 'rate_limit':
        logs = logs.filter(action='api.rate_limit')
    elif type_filter == 'report':
        logs = logs.filter(action='report.download')
    elif type_filter == 'action':
        logs = logs.exclude(action__startswith='page.') \
                   .exclude(action__startswith='auth.') \
                   .exclude(action__startswith='user.')

    # ── Date filter ──────────────────────────────────────────────────
    now = tz.now()
    if date_range == 'custom':
        try:
            if date_from_raw:
                dt_from = tz.make_aware(datetime.strptime(date_from_raw, '%Y-%m-%d'))
                logs = logs.filter(timestamp__gte=dt_from)
            if date_to_raw:
                dt_to = tz.make_aware(datetime.strptime(date_to_raw, '%Y-%m-%d'))
                # include the whole end day
                dt_to = dt_to.replace(hour=23, minute=59, second=59)
                logs = logs.filter(timestamp__lte=dt_to)
        except ValueError:
            pass
    elif date_range == '7d':
        logs = logs.filter(timestamp__gte=now - timedelta(days=7))
    elif date_range == '30d':
        logs = logs.filter(timestamp__gte=now - timedelta(days=30))
    elif date_range == 'all':
        pass  # no date filter
    else:  # default: 24h
        date_range = '24h'
        logs = logs.filter(timestamp__gte=now - timedelta(hours=24))

    return logs, action_filter, user_filter, detail_filter, type_filter, date_range, date_from_raw, date_to_raw


@login_required_custom
@role_required('admin')
def activity_log(request):
    from django.contrib.auth.models import User
    logs = ActivityLog.objects.select_related('user').all()

    logs, action_filter, user_filter, detail_filter, type_filter, date_range, date_from_raw, date_to_raw = \
        _apply_activity_filters(logs, request)

    from apps.settings_app.pagination import get_page_size, PAGE_SIZE_OPTIONS
    page_size = get_page_size(request)
    paginator = Paginator(logs, page_size)
    page = request.GET.get('page', 1)
    logs_page = paginator.get_page(page)

    users = User.objects.filter(
        id__in=ActivityLog.objects.values_list('user_id', flat=True).distinct()
    ).order_by('username')

    return render(request, 'settings_app/activity_log.html', {
        'logs': logs_page,
        'action_filter': action_filter,
        'user_filter': user_filter,
        'detail_filter': detail_filter,
        'type_filter': type_filter,
        'date_range': date_range,
        'date_from': date_from_raw,
        'date_to': date_to_raw,
        'users': users,
        'page_size': page_size,
        'page_size_options': PAGE_SIZE_OPTIONS,
    })


@login_required_custom
@role_required('admin')
def activity_log_export(request):
    logs = ActivityLog.objects.select_related('user').all()
    logs, *_ = _apply_activity_filters(logs, request)

    from django.utils import timezone as tz

    def _log_type(action):
        if action == 'auth.login.failed':   return 'fail'
        if action == 'auth.login.success':  return 'login'
        if action == 'auth.logout':         return 'logout'
        if action.startswith('page.'):      return 'visit'
        if action == 'user.create':         return 'create'
        if action == 'user.activate':       return 'activate'
        if action == 'user.deactivate':     return 'deactivate'
        if action in ('user.role.assign', 'user.role.remove'): return 'role'
        if action == 'report.download':     return 'download'
        if 'delete' in action or 'remove' in action: return 'delete'
        if 'add' in action or 'create' in action or 'import' in action: return 'add'
        if 'edit' in action or 'update' in action:  return 'edit'
        return 'action'

    ts = tz.localtime(tz.now()).strftime('%Y%m%d_%H%M%S')
    response = HttpResponse(content_type='text/csv')
    from apps.settings_app.branding import brand_filename_prefix
    response['Content-Disposition'] = f'attachment; filename="{brand_filename_prefix()}_activity_log_{ts}.csv"'
    from .csv_util import safe_row
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Type', 'Action', 'Target Model', 'Target ID', 'IP Address', 'Detail'])
    for log in logs:
        writer.writerow(safe_row([
            tz.localtime(log.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'system',
            _log_type(log.action),
            log.action,
            log.target_model or '',
            log.target_id or '',
            log.ip_address or '',
            json.dumps(log.detail, ensure_ascii=False) if log.detail else '',
        ]))
    return response


@login_required_custom
@role_required('admin')
def role_matrix(request):
    from apps.accounts.models import Role
    roles = Role.objects.all()
    return render(request, 'settings_app/role_matrix.html', {'roles': roles})


@login_required_custom
@role_required('admin')
def abuseipdb_check_key(request):
    """Check AbuseIPDB API key validity and return today's usage / remaining quota."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    raw = request.POST.get('api_key', '').strip() or SettingsCache.get('threat_intel.abuseipdb_api_key', '').strip()
    from apps.blacklist.abuseipdb_service import _parse_keys, _key_id
    keys = _parse_keys(raw)
    if not keys:
        return JsonResponse({'success': False, 'message': 'API key is not configured. Enter it in the field above.'})

    import urllib.request as _urllib
    import urllib.error  as _urlerr
    import urllib.parse  as _parse
    import json as _json

    def _probe(api_key):
        """Probe one key against the AbuseIPDB /check endpoint using the
        loopback IP — keys are validated and quota headers are read without
        consuming meaningful quota (AbuseIPDB does not count private IPs)."""
        url = ('https://api.abuseipdb.com/api/v2/check?'
               + _parse.urlencode({'ipAddress': '127.0.0.1', 'maxAgeInDays': '1'}))
        req = _urllib.Request(url, headers={'Key': api_key, 'Accept': 'application/json'})
        try:
            with _urllib.urlopen(req, timeout=10, context=build_ssl_context()) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                _json.loads(resp.read().decode())
            daily_limit = int(hdrs.get('x-ratelimit-limit', 0) or 0)
            remaining   = int(hdrs.get('x-ratelimit-remaining', 0) or 0)
            used = max(daily_limit - remaining, 0) if daily_limit else 0
            return {'id': _key_id(api_key), 'status': 'valid',
                    'requests_today': used, 'daily_limit': daily_limit, 'remaining': remaining}
        except _urlerr.HTTPError as exc:
            if exc.code == 401:
                return {'id': _key_id(api_key), 'status': 'invalid', 'message': 'Authentication failed'}
            if exc.code == 429:
                return {'id': _key_id(api_key), 'status': 'exhausted', 'message': 'Daily quota exceeded'}
            return {'id': _key_id(api_key), 'status': 'error', 'message': f'HTTP {exc.code}'}
        except Exception as exc:
            return {'id': _key_id(api_key), 'status': 'error', 'message': str(exc)[:120]}

    results = [_probe(k) for k in keys]
    valid_results = [r for r in results if r['status'] == 'valid']
    any_valid = bool(valid_results)

    # Exhausted keys can't tell us their daily_limit themselves (the 429 is
    # all we get back), but admins clearly want to see the FULL daily
    # capacity across every configured key — so we assume an exhausted key
    # has the same per-day cap as any valid key on the account (or fall
    # back to the free-tier default of 1000 when no valid sample exists).
    per_key_limit = next(
        (r.get('daily_limit', 0) for r in valid_results if r.get('daily_limit', 0)),
        1000,
    )
    total_limit = 0
    total_remaining = 0
    total_used = 0
    for r in results:
        if r['status'] == 'valid':
            total_limit     += r.get('daily_limit', 0)
            total_remaining += r.get('remaining', 0)
            total_used      += r.get('requests_today', 0)
        elif r['status'] == 'exhausted':
            total_limit += per_key_limit
            total_used  += per_key_limit   # fully consumed

    exhausted_count = sum(1 for r in results if r['status'] == 'exhausted')
    invalid_count   = sum(1 for r in results if r['status'] == 'invalid')
    valid_count     = len(valid_results)
    total_keys      = len(keys)
    # "Used" from the admin's perspective = how many *whole keys' worth* of
    # quota has been consumed today across the pool. Counting keys with
    # requests_today > 0 doesn't work: scheduled bulk checks spread across
    # every key, so all of them show minor usage even though the total spend
    # equals only a handful of full-key quotas. Floor(total_used / per_key)
    # matches the admin's mental model — "2358 requests spent, per-key cap
    # 1000 → 2 keys' worth used".
    used_count = min(total_used // per_key_limit, total_keys) if per_key_limit else exhausted_count

    if total_keys == 1:
        only = results[0]
        if only['status'] == 'valid':
            msg = (f'Valid  ·  {total_used} / {total_limit} requests used today'
                   f'  ·  {total_remaining} remaining'
                   if total_limit else 'Valid  ·  Quota information not available for this plan')
        elif only['status'] == 'invalid':
            msg = 'Invalid API key — authentication failed.'
        elif only['status'] == 'exhausted':
            msg = 'Key reached daily quota. Add another key to keep querying.'
        else:
            msg = f"Connection to AbuseIPDB failed: {only.get('message','')}"
    else:
        parts = [f'{valid_count} / {total_keys} key(s) valid']
        if total_limit:
            parts.append(f'{total_used} / {total_limit} used today')
            parts.append(f'{total_remaining} remaining')
        if exhausted_count:
            parts.append(f'{exhausted_count} exhausted')
        if invalid_count:
            parts.append(f'{invalid_count} invalid')
        msg = '  ·  '.join(parts)

    return JsonResponse({
        'success':           any_valid,
        'requests_today':    total_used,
        'daily_limit':       total_limit,
        'remaining':         total_remaining,
        'valid_keys_count':      valid_count,
        'exhausted_keys_count':  exhausted_count,
        'used_keys_count':       used_count,
        'total_keys_count':      total_keys,
        'keys':                  results,
        'message':               msg,
    })


@login_required_custom
@role_required('admin')
def abuseipdb_refresh(request):
    """Trigger a bulk AbuseIPDB score refresh for all active blacklist entries."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    from apps.settings_app.cache import SettingsCache
    from apps.blacklist.abuseipdb_service import bulk_refresh

    enabled = SettingsCache.get('threat_intel.abuseipdb_enabled', False)
    if not enabled:
        return JsonResponse({'success': False, 'message': 'AbuseIPDB integration is disabled. Enable it in settings first.'})

    from apps.blacklist.abuseipdb_service import _parse_keys as _abuse_parse
    if not _abuse_parse(SettingsCache.get('threat_intel.abuseipdb_api_key', '')):
        return JsonResponse({'success': False, 'message': 'AbuseIPDB API key is not configured.'})

    only_unchecked = request.POST.get('only_unchecked', 'false').lower() == 'true'

    try:
        checked, skipped, failed = bulk_refresh(only_unchecked=only_unchecked)
        msg = f"Refresh complete: {checked} scored, {skipped} no data, {failed} failed."
        ActivityLog.log(request.user, 'threat_intel.abuseipdb_refresh', 'BlacklistEntry', 'bulk',
                     {'checked': checked, 'skipped': skipped, 'failed': failed},
                     getattr(request, 'client_ip', ''))
        return JsonResponse({'success': True, 'message': msg, 'checked': checked, 'skipped': skipped, 'failed': failed})
    except Exception as e:
        logger.error(f"AbuseIPDB bulk refresh error: {e}")
        return JsonResponse({'success': False, 'message': 'Refresh failed. Check server logs for details.'})


@login_required_custom
@role_required('admin')
def actions_syslog_test(request):
    """Send one probe datagram to the configured syslog collector.
    Returns success + a human-readable status for the toast."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required.'}, status=405)
    from apps.settings_app.syslog_service import test_connection
    ok, msg = test_connection()
    from apps.settings_app.models import ActivityLog
    ActivityLog.log(request.user, 'actions.syslog_test', 'Setting',
                 'actions.syslog_host',
                 {'delivered': ok, 'message': msg[:120]},
                 getattr(request, 'client_ip', ''))
    return JsonResponse({'success': ok, 'message': msg})


@login_required_custom
@role_required('admin')
def actions_smtp_test(request):
    """Verify the SMTP settings without sending any e-mail. Opens the
    connection, runs the handshake, closes — pure config validation."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required.'}, status=405)
    from apps.settings_app.alert_service import test_smtp_connection
    ok, msg = test_smtp_connection()
    from apps.settings_app.models import ActivityLog
    ActivityLog.log(request.user, 'actions.smtp_test', 'Setting',
                 'actions.email_smtp_host',
                 {'delivered': ok, 'message': msg[:120]},
                 getattr(request, 'client_ip', ''))
    return JsonResponse({'success': ok, 'message': msg})


@login_required_custom
@role_required('admin')
def actions_rate_limit_test_mail(request):
    """Send a preview of the rate-limit alert to the recipient configured
    in Settings → Actions → API Rate Limit Alert. Ignores threshold /
    cooldown gates so admins can verify the template + SMTP path even
    when the platform is idle."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required.'}, status=405)
    recipient = (request.POST.get('email', '').strip()
                 or (SettingsCache.get('actions.rate_limit_alert_email', '') or '').strip())
    if not recipient:
        return JsonResponse({'success': False, 'message': 'Recipient e-mail is empty. Save an address first, or enter one in the form.'})
    from apps.settings_app.alert_service import send_rate_limit_test_mail
    ok, msg = send_rate_limit_test_mail(recipient)
    from apps.settings_app.models import ActivityLog
    ActivityLog.log(request.user, 'actions.rate_limit_alert_test', 'Setting',
                 'actions.rate_limit_alert_email',
                 {'recipient': recipient, 'delivered': ok},
                 getattr(request, 'client_ip', ''))
    return JsonResponse({'success': ok, 'message': msg})


@login_required_custom
@role_required('admin')
def actions_quota_test_mail(request):
    """Send the "quota alert" e-mail to the address configured in
    Settings → Actions with live quota numbers. Distinct from the scheduler
    entry: no cooldown, no threshold gating — the admin explicitly asked for
    a preview."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required.'}, status=405)
    recipient = (request.POST.get('email', '').strip()
                 or (SettingsCache.get('actions.quota_alert_email', '') or '').strip())
    if not recipient:
        return JsonResponse({'success': False, 'message': 'Recipient e-mail is empty. Save an address first, or enter one in the form.'})
    from apps.settings_app.alert_service import send_test_mail
    ok, msg = send_test_mail(recipient)
    from apps.settings_app.models import ActivityLog
    ActivityLog.log(request.user, 'actions.quota_alert_test', 'Setting',
                 'actions.quota_alert_email',
                 {'recipient': recipient, 'delivered': ok},
                 getattr(request, 'client_ip', ''))
    return JsonResponse({'success': ok, 'message': msg})


@login_required_custom
@role_required('admin')
def virustotal_check_key(request):
    """Check VirusTotal API key validity and quota via EICAR hash lookup."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    raw = request.POST.get('api_key', '').strip() or SettingsCache.get('threat_intel.virustotal_api_key', '').strip()
    from apps.hashlist.virustotal_service import (
        _vt_parse_keys, _vt_key_id, _vt_is_exhausted, _vt_mark_exhausted,
    )
    keys = _vt_parse_keys(raw)
    if not keys:
        return JsonResponse({'success': False, 'message': 'API key is not configured. Enter it in the field above.'})

    import urllib.request as _urllib
    import urllib.error  as _urlerr
    import json as _json

    def _safe_int(v):
        try:
            return int(v) if v is not None else 0
        except (ValueError, TypeError):
            return 0

    _ctx = build_ssl_context()

    def _classify_429(http_error):
        """VT returns `error.code = "QuotaExceededError"` for BOTH the
        per-minute throttle and the real daily quota — the code alone is
        ambiguous. Signals evaluated in order:
          1. `x-ratelimit-remaining: 0` header → daily quota gone
          2. `QuotaExceededError` code in the JSON body → daily quota gone
          3. `Retry-After > 3600` → daily quota gone (fallback)
        Free-tier daily-exhaustion 429s often ship WITHOUT a distinctive
        Retry-After, which is why the Retry-After-only rule this function
        used before mis-classified real exhaustion as a transient throttle
        — the UI then showed keys as green while lookups were failing."""
        hdrs_l = {k.lower(): v for k, v in (http_error.headers or {}).items()}
        h_remaining_raw = (hdrs_l.get('x-ratelimit-remaining')
                           or hdrs_l.get('x-apirate-remaining'))
        if h_remaining_raw is not None and str(h_remaining_raw).strip() == '0':
            return 'quota_exhausted'
        try:
            body = http_error.read().decode('utf-8', errors='replace')
            parsed = _json.loads(body) if body else {}
            code = (parsed.get('error', {}) or {}).get('code', '')
            if code == 'QuotaExceededError':
                return 'quota_exhausted'
        except Exception:
            pass
        try:
            retry_after = int(hdrs_l.get('retry-after', '') or 0)
        except (TypeError, ValueError):
            retry_after = 0
        return 'quota_exhausted' if retry_after > 3600 else 'rate_limited'

    def _probe(api_key):
        """Probe one VT key with the EICAR hash and read quota headers /
        users/me quota."""
        # Fast path — if the runtime has already marked this key as
        # daily-exhausted (via bulk_refresh or an earlier probe), don't
        # burn another API call on it. Also keeps the UI honest: without
        # this the Check Key button would clear the exhausted verdict on
        # a per-minute throttle response and mis-report the key as valid.
        if _vt_is_exhausted(api_key):
            return {'id': _vt_key_id(api_key), 'status': 'exhausted',
                    'message': 'Daily quota exceeded (in-memory cache)'}
        try:
            eicar_md5 = '44d88612fea8a8f36de82e1278abb02f'
            url = f'https://www.virustotal.com/api/v3/files/{eicar_md5}'
            req = _urllib.Request(url, headers={'x-apikey': api_key, 'Accept': 'application/json'})
            with _urllib.urlopen(req, timeout=10, context=_ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                _json.loads(resp.read().decode())
            daily_limit     = (_safe_int(hdrs.get('x-apirate-limit'))    or
                               _safe_int(hdrs.get('x-ratelimit-limit'))   or 0)
            daily_remaining = (_safe_int(hdrs.get('x-apirate-remaining')) or
                               _safe_int(hdrs.get('x-ratelimit-remaining')) or 0)
            daily_used      = max(0, daily_limit - daily_remaining) if daily_limit else 0
            # Fall back to /users/me when headers don't carry quota info.
            if daily_limit == 0:
                try:
                    me_url = 'https://www.virustotal.com/api/v3/users/me'
                    mreq = _urllib.Request(me_url, headers={'x-apikey': api_key, 'Accept': 'application/json'})
                    with _urllib.urlopen(mreq, timeout=8, context=_ctx) as mresp:
                        mdata = _json.loads(mresp.read().decode())
                    quotas = mdata.get('data', {}).get('attributes', {}).get('quotas', {})
                    daily_quota = quotas.get('api_requests_daily', {})
                    if isinstance(daily_quota, dict) and daily_quota.get('allowed'):
                        daily_limit     = _safe_int(daily_quota.get('allowed'))
                        daily_used      = _safe_int(daily_quota.get('used'))
                        daily_remaining = max(0, daily_limit - daily_used)
                    else:
                        attrs = mdata.get('data', {}).get('attributes', {})
                        daily_limit     = _safe_int(attrs.get('api_requests_daily_limit'))
                        daily_used      = _safe_int(attrs.get('api_requests_daily'))
                        daily_remaining = max(0, daily_limit - daily_used)
                except _urlerr.HTTPError as me_exc:
                    # If the secondary /users/me call hits the per-minute
                    # throttle on a key whose EICAR check already succeeded,
                    # the KEY is fine — we just couldn't read the quota.
                    # Surface as valid with zero quota info rather than
                    # demoting the whole key to throttled.
                    if me_exc.code != 429:
                        pass
                except Exception:
                    pass
            # Successful response but the header says the daily bucket is
            # empty. That means this very request drained the last unit and
            # any subsequent lookup will get a 429. Treat the key as
            # exhausted so the UI badge and the quota monitor agree with
            # what the hashlist path is actually seeing.
            if daily_limit > 0 and daily_remaining == 0:
                _vt_mark_exhausted(api_key)
                return {'id': _vt_key_id(api_key), 'status': 'exhausted',
                        'daily_limit': daily_limit, 'daily_used': daily_limit, 'daily_remaining': 0,
                        'message': 'Daily quota exceeded (remaining=0)'}
            return {'id': _vt_key_id(api_key), 'status': 'valid',
                    'daily_limit': daily_limit, 'daily_used': daily_used, 'daily_remaining': daily_remaining}
        except _urlerr.HTTPError as exc:
            if exc.code == 401:
                return {'id': _vt_key_id(api_key), 'status': 'invalid', 'message': 'Authentication failed'}
            if exc.code == 429:
                kind = _classify_429(exc)
                if kind == 'quota_exhausted':
                    # Persist the verdict in the runtime cache so hashlist
                    # lookups and the quota monitor also see this key as
                    # exhausted until the next UTC reset — otherwise Check
                    # Key would only catch it while the UI probe is live.
                    _vt_mark_exhausted(api_key)
                    return {'id': _vt_key_id(api_key), 'status': 'exhausted', 'message': 'Daily quota exceeded'}
                # Per-minute throttle is transient — the key is valid, just
                # currently resting. Distinct status so the UI counts it as
                # configured-but-busy rather than dead-for-the-day.
                return {'id': _vt_key_id(api_key), 'status': 'throttled', 'message': 'Per-minute rate limit — try again in ~1 min'}
            return {'id': _vt_key_id(api_key), 'status': 'error', 'message': f'HTTP {exc.code}'}
        except Exception as exc:
            return {'id': _vt_key_id(api_key), 'status': 'error', 'message': str(exc)[:120]}

    # Stagger the probes so we don't burn through any single key's per-minute
    # bucket (4 req/min) when /users/me also fires. 250ms between starts
    # keeps the burst rate at most 4/sec across the whole probe phase.
    import time as _time
    results = []
    for idx, k in enumerate(keys):
        if idx > 0:
            _time.sleep(0.25)
        results.append(_probe(k))
    valid_results = [r for r in results if r['status'] == 'valid']
    # Rate-limited (throttled) keys are still correctly configured — the
    # response is "success" overall as long as at least one key is either
    # currently usable OR temporarily cooling down.
    any_valid = any(r['status'] in ('valid', 'throttled') for r in results)

    # Same reasoning as AbuseIPDB: exhausted keys can't expose their own
    # daily_limit via 429 so we assume per-key parity with the valid keys
    # (or the free-tier default of 500) — that way the total reflects the
    # admin's full configured daily capacity, not just the currently-live
    # subset.
    per_key_limit = next(
        (r.get('daily_limit', 0) for r in valid_results if r.get('daily_limit', 0)),
        500,
    )
    total_limit     = 0
    total_remaining = 0
    total_used      = 0
    for r in results:
        if r['status'] == 'valid':
            total_limit     += r.get('daily_limit', 0)
            total_remaining += r.get('daily_remaining', 0)
            total_used      += r.get('daily_used', 0)
        elif r['status'] == 'exhausted':
            total_limit += per_key_limit
            total_used  += per_key_limit
        elif r['status'] == 'throttled':
            # Briefly rate-limited but still valid — count its capacity in
            # the daily total so the UI reflects the full configured pool.
            total_limit += per_key_limit

    exhausted_count = sum(1 for r in results if r['status'] == 'exhausted')
    throttled_count = sum(1 for r in results if r['status'] == 'throttled')
    invalid_count   = sum(1 for r in results if r['status'] == 'invalid')
    # 'throttled' keys are configured correctly — they count as "valid" for
    # the X/Y key counter the user sees, just with a separate note that
    # some are currently in cooldown.
    valid_count     = len(valid_results) + throttled_count
    total_keys      = len(keys)

    if total_keys == 1:
        only = results[0]
        if only['status'] == 'valid':
            msg = (f'Valid  ·  {total_used} / {total_limit} daily requests used'
                   f'  ·  {total_remaining} remaining'
                   if total_limit else 'Valid  ·  Quota information not available for this plan')
        elif only['status'] == 'invalid':
            msg = 'Invalid API key — authentication failed.'
        elif only['status'] == 'exhausted':
            msg = 'Key reached daily quota. Add another key to keep querying.'
        elif only['status'] == 'throttled':
            msg = 'Valid  ·  Key is briefly rate-limited (4 req/min) — retry in ~1 minute.'
        else:
            msg = f"Connection to VirusTotal failed: {only.get('message','')}"
    else:
        parts = [f'{valid_count} / {total_keys} key(s) valid']
        if total_limit:
            parts.append(f'{total_used} / {total_limit} used today')
            parts.append(f'{total_remaining} remaining')
        if throttled_count:
            parts.append(f'{throttled_count} cooling down')
        if exhausted_count:
            parts.append(f'{exhausted_count} exhausted')
        if invalid_count:
            parts.append(f'{invalid_count} invalid')
        msg = '  ·  '.join(parts)

    return JsonResponse({
        'success':              any_valid,
        'message':              msg,
        'daily_limit':          total_limit,
        'daily_used':           total_used,
        'daily_remaining':      total_remaining,
        'valid_keys_count':     valid_count,
        'total_keys_count':     total_keys,
        # Exposed for the UI's per-key saturation bar — VT free tier doesn't
        # let us read the real used/limit numbers reliably, so the bar in
        # the topbar gauges progress in key-count terms instead (how many
        # keys are out of quota out of the total configured).
        'exhausted_keys_count': exhausted_count,
        'throttled_keys_count': throttled_count,
        'keys':                 results,
    })


@login_required_custom
@role_required('admin')
def virustotal_refresh(request):
    """Trigger a bulk VirusTotal score refresh for all active hash blacklist entries."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    enabled = SettingsCache.get('threat_intel.virustotal_enabled', False)
    if not enabled:
        return JsonResponse({'success': False, 'message': 'VirusTotal integration is disabled. Enable it in settings first.'})

    from apps.hashlist.virustotal_service import _vt_parse_keys
    if not _vt_parse_keys(SettingsCache.get('threat_intel.virustotal_api_key', '')):
        return JsonResponse({'success': False, 'message': 'VirusTotal API key is not configured.'})

    only_unchecked = request.POST.get('only_unchecked', 'false').lower() == 'true'

    try:
        from apps.hashlist.virustotal_service import bulk_refresh as vt_bulk_refresh
        checked, skipped, failed = vt_bulk_refresh(only_unchecked=only_unchecked)
        msg = f"Refresh complete: {checked} scored, {skipped} skipped, {failed} failed."
        ActivityLog.log(request.user, 'threat_intel.virustotal_refresh', 'HashEntry', 'bulk',
                     {'checked': checked, 'skipped': skipped, 'failed': failed},
                     getattr(request, 'client_ip', ''))
        return JsonResponse({'success': True, 'message': msg, 'checked': checked, 'skipped': skipped, 'failed': failed})
    except Exception as e:
        logger.error(f"VirusTotal bulk refresh error: {e}")
        return JsonResponse({'success': False, 'message': 'Refresh failed. Check server logs for details.'})


@login_required_custom
@role_required('admin')
def abuseipdb_run_cleanup(request):
    """Trigger an immediate AbuseIPDB cleanup pass. Returns the run summary
    (rule, deleted_count) and writes a detailed ActivityLog entry the admin
    can inspect under Settings → Activity Log."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    if not SettingsCache.get('threat_intel.abuseipdb_cleanup_enabled', False):
        return JsonResponse({
            'success': False,
            'message': 'Cleanup is disabled — enable it in settings first.',
        })
    try:
        from apps.blacklist.cleanup_service import run_cleanup
        summary = run_cleanup(actor=request.user, client_ip=getattr(request, 'client_ip', ''))
    except Exception as e:
        logger.error(f"AbuseIPDB cleanup error: {e}")
        return JsonResponse({'success': False, 'message': 'Cleanup failed. Check server logs.'})
    rule = summary['rule']
    msg = (
        f"Cleanup complete: deleted {summary['deleted_count']} inactive entries "
        f"(score {rule['score_min']}-{rule['score_max']}, "
        f"older than {rule['retention_days']}d)."
    )
    return JsonResponse({
        'success': True,
        'message': msg,
        'deleted_count': summary['deleted_count'],
        'rule': rule,
    })


@login_required_custom
@role_required('admin')
def virustotal_run_cleanup(request):
    """Trigger an immediate VirusTotal cleanup pass — same shape as the
    AbuseIPDB endpoint above but operates on inactive hash entries."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    if not SettingsCache.get('threat_intel.virustotal_cleanup_enabled', False):
        return JsonResponse({
            'success': False,
            'message': 'Cleanup is disabled — enable it in settings first.',
        })
    try:
        from apps.hashlist.cleanup_service import run_cleanup
        summary = run_cleanup(actor=request.user, client_ip=getattr(request, 'client_ip', ''))
    except Exception as e:
        logger.error(f"VirusTotal cleanup error: {e}")
        return JsonResponse({'success': False, 'message': 'Cleanup failed. Check server logs.'})
    rule = summary['rule']
    msg = (
        f"Cleanup complete: deleted {summary['deleted_count']} inactive hashes "
        f"(malicious {rule['score_min']}-{rule['score_max']}, "
        f"older than {rule['retention_days']}d)."
    )
    return JsonResponse({
        'success': True,
        'message': msg,
        'deleted_count': summary['deleted_count'],
        'rule': rule,
    })
