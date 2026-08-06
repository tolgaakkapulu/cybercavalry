"""Threshold-driven e-mail alerts for API quota exhaustion.

Wired into the APScheduler (`_run_quota_alert_check`) and also callable from
a synchronous view for the test-mail button. Uses Django's configured
EMAIL_BACKEND, so an operator's `.env` / `settings.py` decides how the mail
actually leaves the box.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.core.mail import EmailMultiAlternatives, get_connection
from django.template.loader import render_to_string
from django.utils import timezone

from apps.settings_app.cache import SettingsCache
from apps.settings_app.models import Setting
from apps.settings_app.quota_monitor import collect_quota_status

logger = logging.getLogger(__name__)


def _get_smtp_password() -> str:
    """SMTP password is stored encrypted in the Setting row — read via the
    model's `plain_value` property so it's decrypted with the field key."""
    row = Setting.objects.filter(key='actions.email_smtp_password').first()
    return (row.plain_value if row else '') or ''


def _smtp_connection():
    """Build a Django EmailBackend connection from the Settings → E-mail tab.

    Falls back to Django's default backend (typically console in dev) when
    no SMTP host is configured, so a fresh install still shows something.
    """
    host = (SettingsCache.get('actions.email_smtp_host', '') or '').strip()
    if not host:
        return get_connection()  # honour whatever settings.py defines
    try:
        port = int(SettingsCache.get('actions.email_smtp_port', 587) or 587)
    except (TypeError, ValueError):
        port = 587
    user     = (SettingsCache.get('actions.email_smtp_user', '') or '').strip()
    password = _get_smtp_password()
    use_tls  = bool(SettingsCache.get('actions.email_smtp_use_tls', True))
    return get_connection(
        backend='django.core.mail.backends.smtp.EmailBackend',
        host=host,
        port=port,
        username=user or None,
        password=password or None,
        use_tls=use_tls,
        # `use_ssl` is mutually exclusive with `use_tls`; port 465 style is
        # not exposed here — most installs use STARTTLS on 587. If someone
        # needs implicit TLS they can toggle STARTTLS off and change the port.
    )


def _from_address() -> str:
    """Configured envelope sender, falling back to SMTP user, then to
    Django's `DEFAULT_FROM_EMAIL`."""
    addr = (SettingsCache.get('actions.email_from_address', '') or '').strip()
    if addr:
        return addr
    user = (SettingsCache.get('actions.email_smtp_user', '') or '').strip()
    if user:
        return user
    from django.conf import settings as dj_settings
    return getattr(dj_settings, 'DEFAULT_FROM_EMAIL', 'webmaster@localhost')


# Cache key used to remember the last time a specific provider's alert went
# out — kept in the same SettingsCache table so it survives restarts without
# adding a new column.
_LAST_SENT_KEY            = 'actions.quota_alert_last_sent'          # JSON blob: {"AbuseIPDB": iso, ...}
_RATE_LIMIT_LAST_SENT_KEY = 'actions.rate_limit_alert_last_sent'      # JSON blob: {"user:42": iso, "ip:1.2.3.4": iso, ...}
_SILENCE_LAST_SENT_KEY    = 'actions.silence_alert_last_sent'         # JSON blob: {"ip:10.34.36.254": iso, ...}


def _get_last_sent(key: str = _LAST_SENT_KEY) -> dict:
    from apps.settings_app.models import Setting
    row = Setting.objects.filter(key=key).first()
    if not row or not row.value:
        return {}
    try:
        import json
        return json.loads(row.value)
    except Exception:
        return {}


def _set_last_sent(payload: dict, key: str = _LAST_SENT_KEY, desc: str = '') -> None:
    from apps.settings_app.models import Setting
    import json
    Setting.objects.update_or_create(
        key=key,
        defaults={
            'value':       json.dumps(payload),
            'value_type':  'json',
            'category':    'actions',
            'description': desc or 'Timestamps of the most recent alert e-mails (managed internally).',
            'is_secret':   False,
        },
    )
    SettingsCache.invalidate(key)


def _build_context(providers: list[dict], threshold_pct: int, is_test: bool = False) -> dict:
    """Feed the mail templates with brand + status data."""
    primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
    suffix  = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
    email   = SettingsCache.get('general.platform_email', '') or ''
    brand   = (SettingsCache.get('general.brand_color', '#ee5356') or '#ee5356').strip()
    interval      = SettingsCache.get('actions.quota_check_interval', 1) or 1
    interval_unit = SettingsCache.get('actions.quota_check_interval_unit', 'hours') or 'hours'
    cooldown      = SettingsCache.get('actions.quota_alert_cooldown_hours', 24) or 24

    # Flag which rows crossed the threshold — the template uses this for
    # the badge colour so the reader sees the outlier at a glance.
    for row in providers:
        row['triggered'] = row.get('configured') and row.get('usage_pct', 0) >= threshold_pct

    return {
        'platform_name':         f'{primary}{suffix}',
        'platform_name_primary': primary,
        'platform_name_suffix':  suffix,
        'platform_email':        email,
        'brand_color':           brand,
        'providers':             providers,
        'threshold_pct':         threshold_pct,
        'checked_at':            timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M %Z'),
        'check_interval':        interval,
        'check_interval_unit':   interval_unit,
        'cooldown_hours':        cooldown,
        'is_test':               is_test,
    }


def parse_recipients(raw: str) -> list[str]:
    """Split the `;`-separated recipient string into a de-duplicated list.

    Admins configure alert recipients as one line — e.g.
    "ops@corp.tr; soc@corp.tr". Blank slots (extra `;`) and whitespace are
    tolerated. Comparison is case-insensitive when de-duping.
    """
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.split(';'):
        addr = part.strip()
        if not addr:
            continue
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(addr)
    return out


def _send(recipients, subject: str, ctx: dict) -> bool:
    """Render + deliver via a connection driven by Settings → E-mail.

    `recipients` may be a single address string or an already-parsed list —
    both are normalised through `parse_recipients()` so callers can stay
    lazy without breaking when the setting holds "a@x; b@y".
    """
    to_list = parse_recipients(recipients) if isinstance(recipients, str) else [
        r for r in (recipients or []) if r
    ]
    if not to_list:
        return False
    try:
        html_body = render_to_string('settings_app/emails/quota_alert.html', ctx)
        text_body = render_to_string('settings_app/emails/quota_alert.txt',  ctx)
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=_from_address(),
            to=to_list,
            connection=_smtp_connection(),
        )
        msg.attach_alternative(html_body, 'text/html')
        msg.send(fail_silently=False)
        return True
    except Exception as exc:
        logger.error("Quota-alert e-mail failed: %s", exc)
        return False


def test_smtp_connection() -> tuple[bool, str]:
    """Open a connection using the current Settings → E-mail values, do the
    SMTP handshake, and close — no e-mail is delivered. Used by the
    "Test SMTP" button so an admin can verify credentials without spamming
    the recipient inbox."""
    host = (SettingsCache.get('actions.email_smtp_host', '') or '').strip()
    if not host:
        return False, 'SMTP host is empty. Fill in the E-mail tab first.'
    try:
        conn = _smtp_connection()
        conn.open()
        conn.close()
        return True, 'SMTP handshake succeeded.'
    except Exception as exc:
        logger.error("SMTP handshake failed: %s", exc)
        # Trim exception noise so the UI banner stays short.
        return False, f'SMTP handshake failed: {exc}'[:200]


def _build_rate_limit_context(callers: list[dict], threshold_pct: int,
                              limit_rpm: int, is_test: bool = False) -> dict:
    """Feed the rate-limit alert templates with brand + traffic data."""
    primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
    suffix  = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
    email   = SettingsCache.get('general.platform_email', '') or ''
    brand   = (SettingsCache.get('general.brand_color', '#ee5356') or '#ee5356').strip()
    cooldown = SettingsCache.get('actions.rate_limit_alert_cooldown_hours', 24) or 24
    return {
        'platform_name':         f'{primary}{suffix}',
        'platform_name_primary': primary,
        'platform_name_suffix':  suffix,
        'platform_email':        email,
        'brand_color':           brand,
        'callers':               callers,
        'threshold_pct':         threshold_pct,
        'limit_rpm':             limit_rpm,
        'checked_at':            timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M %Z'),
        'cooldown_hours':        cooldown,
        'is_test':               is_test,
    }


def _send_rate_limit_mail(recipients, subject: str, ctx: dict) -> bool:
    """Render + deliver the rate-limit alert via the Settings-driven SMTP.
    Accepts a single string or a list — the recipient setting stores a
    `;`-separated list so we normalise before handing to Django."""
    to_list = parse_recipients(recipients) if isinstance(recipients, str) else [
        r for r in (recipients or []) if r
    ]
    if not to_list:
        return False
    try:
        html_body = render_to_string('settings_app/emails/rate_limit_alert.html', ctx)
        text_body = render_to_string('settings_app/emails/rate_limit_alert.txt',  ctx)
        msg = EmailMultiAlternatives(
            subject=subject, body=text_body,
            from_email=_from_address(), to=to_list,
            connection=_smtp_connection(),
        )
        msg.attach_alternative(html_body, 'text/html')
        msg.send(fail_silently=False)
        return True
    except Exception as exc:
        logger.error("Rate-limit alert e-mail failed: %s", exc)
        return False


def send_rate_limit_test_mail(recipient: str) -> tuple[bool, str]:
    """Deliver the rate-limit alert preview with live traffic. Used by the
    Settings → Actions → API Rate Limit Alert "Send Test Mail" button."""
    if not recipient:
        return False, 'Recipient e-mail is empty.'
    from apps.settings_app.rate_limit_monitor import sample_rate_limit_usage
    sample = sample_rate_limit_usage(window_seconds=60)
    threshold_pct = int(SettingsCache.get('actions.rate_limit_alert_threshold_pct', 80) or 80)
    limit_rpm     = int(SettingsCache.get('api.rate_limit_rpm', 60) or 60)
    ctx = _build_rate_limit_context(sample, threshold_pct, limit_rpm, is_test=True)
    subject = f'[{ctx["platform_name"]}] Rate-limit alert test'
    ok = _send_rate_limit_mail(recipient, subject, ctx)
    return ok, ('Test e-mail sent.' if ok else 'Sending failed — check the server log for details.')


def run_rate_limit_alert_check(actor=None, ip: str = '') -> dict:
    """Scheduler entry point. Samples the last 60 s of API traffic, filters
    callers whose usage is at/above the configured threshold, respects the
    per-caller cooldown, and mails the recipient if there's anything to say."""
    from apps.settings_app.models import ActivityLog
    from apps.settings_app.rate_limit_monitor import find_callers_over_threshold

    if not SettingsCache.get('actions.rate_limit_alert_enabled', False):
        return {'skipped': 'disabled'}
    recipient = (SettingsCache.get('actions.rate_limit_alert_email', '') or '').strip()
    if not recipient:
        return {'skipped': 'no_recipient'}

    offenders, threshold_pct = find_callers_over_threshold()
    if not offenders:
        return {'skipped': 'below_threshold'}

    cooldown_h = int(SettingsCache.get('actions.rate_limit_alert_cooldown_hours', 24) or 24)
    now = timezone.now()
    last_sent_map = _get_last_sent(_RATE_LIMIT_LAST_SENT_KEY)

    to_notify = []
    for c in offenders:
        caller_key = f'user:{c["user_id"]}' if c.get('user_id') else f'ip:{c["caller"]}'
        last_iso = last_sent_map.get(caller_key)
        if last_iso:
            try:
                last_dt = timezone.datetime.fromisoformat(last_iso)
                if now - last_dt < timedelta(hours=cooldown_h):
                    continue
            except Exception:
                pass
        c['_caller_key'] = caller_key
        to_notify.append(c)

    if not to_notify:
        return {'skipped': 'cooldown_active',
                'over':    [c['caller'] for c in offenders]}

    limit_rpm = to_notify[0]['limit_rpm']
    ctx = _build_rate_limit_context(to_notify, threshold_pct, limit_rpm, is_test=False)
    ctx['callers'] = to_notify  # only the notified subset in the mail
    subject = (f'[{ctx["platform_name"]}] Rate-limit alert — {len(to_notify)} caller(s)'
               f' ≥ {threshold_pct}%')
    ok = _send_rate_limit_mail(recipient, subject, ctx)

    if ok:
        for c in to_notify:
            last_sent_map[c['_caller_key']] = now.isoformat()
        _set_last_sent(
            last_sent_map, key=_RATE_LIMIT_LAST_SENT_KEY,
            desc='Timestamps of the most recent rate-limit alert e-mails per caller (managed internally).',
        )

    ActivityLog.log(
        user=actor, action='actions.rate_limit_alert_sent',
        target_model='Setting', target_id='actions.rate_limit_alert_email',
        detail={
            'recipient':     recipient,
            'threshold_pct': threshold_pct,
            'limit_rpm':     limit_rpm,
            'triggered':     [
                {'caller': c['caller'], 'requests': c['requests'], 'usage_pct': c['usage_pct']}
                for c in to_notify
            ],
            'delivered':     ok,
        },
        ip_address=ip,
    )
    return {'sent': ok, 'recipient': recipient,
            'callers': [c['caller'] for c in to_notify]}


def send_test_mail(recipient: str) -> tuple[bool, str]:
    """Deliver a preview of the alert e-mail with live quota numbers. Used
    by the Settings → Actions "Send Test Mail" button."""
    if not recipient:
        return False, 'Recipient e-mail is empty.'
    threshold_pct = int(SettingsCache.get('actions.quota_alert_threshold_pct', 80) or 80)
    providers = collect_quota_status()
    ctx = _build_context(providers, threshold_pct, is_test=True)
    subject = f'[{ctx["platform_name"]}] Quota alert test'
    ok = _send(recipient, subject, ctx)
    return ok, ('Test e-mail sent.' if ok else 'Sending failed — check the server log for details.')


def run_quota_alert_check(actor=None, ip: str = '') -> dict:
    """Scheduler entry point. Probes both providers, compares against the
    admin-configured threshold, and only sends when a provider has crossed
    the line AND the per-provider cooldown has elapsed. Returns a dict for
    the activity-log payload."""
    from apps.settings_app.models import ActivityLog

    if not SettingsCache.get('actions.quota_alert_enabled', False):
        return {'skipped': 'disabled'}

    recipient = (SettingsCache.get('actions.quota_alert_email', '') or '').strip()
    if not recipient:
        return {'skipped': 'no_recipient'}

    threshold_pct = int(SettingsCache.get('actions.quota_alert_threshold_pct', 80) or 80)
    cooldown_h    = int(SettingsCache.get('actions.quota_alert_cooldown_hours', 24) or 24)

    providers = collect_quota_status()
    over = [p for p in providers if p['configured'] and p['usage_pct'] >= threshold_pct]
    if not over:
        return {
            'skipped':  'below_threshold',
            'summary':  {p['provider']: p['usage_pct'] for p in providers},
        }

    now = timezone.now()
    last_sent_map = _get_last_sent()
    to_notify = []
    for p in over:
        last_iso = last_sent_map.get(p['provider'])
        if last_iso:
            try:
                last_dt = timezone.datetime.fromisoformat(last_iso)
                if now - last_dt < timedelta(hours=cooldown_h):
                    continue  # still cooling down
            except Exception:
                pass
        to_notify.append(p)

    if not to_notify:
        return {'skipped': 'cooldown_active',
                'over':    [p['provider'] for p in over]}

    ctx = _build_context(providers, threshold_pct, is_test=False)
    subject_names = ', '.join(p['provider'] for p in to_notify)
    subject = f'[{ctx["platform_name"]}] Quota alert — {subject_names} ≥ {threshold_pct}%'
    ok = _send(recipient, subject, ctx)

    if ok:
        for p in to_notify:
            last_sent_map[p['provider']] = now.isoformat()
        _set_last_sent(last_sent_map)

    ActivityLog.log(
        user=actor, action='actions.quota_alert_sent',
        target_model='Setting', target_id='actions.quota_alert_email',
        detail={
            'recipient':      recipient,
            'threshold_pct':  threshold_pct,
            'triggered':      [
                {'provider': p['provider'], 'usage_pct': p['usage_pct'],
                 'used': p['used'], 'limit': p['limit']}
                for p in to_notify
            ],
            'delivered':      ok,
        },
        ip_address=ip,
    )
    return {
        'sent':      ok,
        'recipient': recipient,
        'providers': [p['provider'] for p in to_notify],
    }


# ── API Silence Alert ────────────────────────────────────────────────────────

def _build_silence_context(callers: list[dict], silent_only: list[dict],
                           threshold_minutes: int, baseline_min_hits: int,
                           is_test: bool = False) -> dict:
    """Feed the silence-alert templates with brand + traffic snapshot."""
    primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
    suffix  = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
    email   = SettingsCache.get('general.platform_email', '') or ''
    brand   = (SettingsCache.get('general.brand_color', '#ee5356') or '#ee5356').strip()
    cooldown = SettingsCache.get('actions.silence_alert_cooldown_hours', 6) or 6

    # Local timestamps for display
    for row in callers:
        if row.get('last_seen'):
            row['last_seen_local'] = timezone.localtime(row['last_seen']).strftime('%Y-%m-%d %H:%M:%S')
        else:
            row['last_seen_local'] = 'never'
        row['is_silent'] = row['silent_minutes'] >= threshold_minutes

    return {
        'platform_name':          f'{primary}{suffix}',
        'platform_name_primary':  primary,
        'platform_name_suffix':   suffix,
        'platform_email':         email,
        'brand_color':            brand,
        'callers':                callers,
        'silent_callers':         silent_only,
        'threshold_minutes':      threshold_minutes,
        'baseline_min_hits':      baseline_min_hits,
        'checked_at':             timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M %Z'),
        'cooldown_hours':         cooldown,
        'is_test':                is_test,
    }


def _send_silence_mail(recipients, subject: str, ctx: dict) -> bool:
    to_list = parse_recipients(recipients) if isinstance(recipients, str) else [
        r for r in (recipients or []) if r
    ]
    if not to_list:
        return False
    try:
        html_body = render_to_string('settings_app/emails/silence_alert.html', ctx)
        text_body = render_to_string('settings_app/emails/silence_alert.txt',  ctx)
        msg = EmailMultiAlternatives(
            subject=subject, body=text_body,
            from_email=_from_address(), to=to_list,
            connection=_smtp_connection(),
        )
        msg.attach_alternative(html_body, 'text/html')
        msg.send(fail_silently=False)
        return True
    except Exception as exc:
        logger.error("Silence-alert e-mail failed: %s", exc)
        return False


def send_silence_test_mail(recipient: str) -> tuple[bool, str]:
    """Deliver the silence-alert preview with the live monitored-caller list.
    Used by the Settings → Actions → API Silence Alert "Send Test Mail" button."""
    if not recipient:
        return False, 'Recipient e-mail is empty.'
    from apps.settings_app.silence_monitor import sample_recent_callers, find_silent_callers

    callers = sample_recent_callers()
    silent_only, threshold_minutes, baseline_min_hits = find_silent_callers()
    ctx = _build_silence_context(
        callers, silent_only, threshold_minutes, baseline_min_hits, is_test=True,
    )
    subject = f'[{ctx["platform_name"]}] API silence alert test'
    ok = _send_silence_mail(recipient, subject, ctx)
    return ok, ('Test e-mail sent.' if ok else 'Sending failed — check the server log for details.')


def run_silence_alert_check(actor=None, ip: str = '') -> dict:
    """Scheduler entry point. Finds monitored callers whose last API request
    is older than the configured threshold, honours per-caller cooldown, and
    mails the recipient if there's anything to say."""
    from apps.settings_app.models import ActivityLog
    from apps.settings_app.silence_monitor import find_silent_callers

    if not SettingsCache.get('actions.silence_alert_enabled', False):
        return {'skipped': 'disabled'}
    recipient = (SettingsCache.get('actions.silence_alert_email', '') or '').strip()
    if not recipient:
        return {'skipped': 'no_recipient'}

    silent, threshold_minutes, baseline_min_hits = find_silent_callers()
    if not silent:
        return {'skipped': 'no_silent_callers'}

    cooldown_h = int(SettingsCache.get('actions.silence_alert_cooldown_hours', 6) or 6)
    now = timezone.now()
    last_sent_map = _get_last_sent(_SILENCE_LAST_SENT_KEY)

    to_notify = []
    for c in silent:
        last_iso = last_sent_map.get(c['caller_key'])
        if last_iso:
            try:
                last_dt = timezone.datetime.fromisoformat(last_iso)
                if now - last_dt < timedelta(hours=cooldown_h):
                    continue
            except Exception:
                pass
        to_notify.append(c)

    if not to_notify:
        return {'skipped': 'cooldown_active',
                'silent':  [c['caller'] for c in silent]}

    ctx = _build_silence_context(
        to_notify, to_notify, threshold_minutes, baseline_min_hits, is_test=False,
    )
    subject = (f'[{ctx["platform_name"]}] API silence alert — '
               f'{len(to_notify)} integration(s) silent ≥ {threshold_minutes}m')
    ok = _send_silence_mail(recipient, subject, ctx)

    if ok:
        for c in to_notify:
            last_sent_map[c['caller_key']] = now.isoformat()
        _set_last_sent(
            last_sent_map, key=_SILENCE_LAST_SENT_KEY,
            desc='Timestamps of the most recent silence alert e-mails per caller (managed internally).',
        )

    ActivityLog.log(
        user=actor, action='actions.silence_alert_sent',
        target_model='Setting', target_id='actions.silence_alert_email',
        detail={
            'recipient':          recipient,
            'threshold_minutes':  threshold_minutes,
            'baseline_min_hits':  baseline_min_hits,
            'triggered':          [
                {'caller': c['caller'],
                 'silent_minutes':  c['silent_minutes'],
                 'baseline_hits':   c['baseline_hits']}
                for c in to_notify
            ],
            'delivered':          ok,
        },
        ip_address=ip,
    )
    return {'sent': ok, 'recipient': recipient,
            'callers': [c['caller'] for c in to_notify]}
