"""Per-endpoint API-silence detector.

Watches each configurable API endpoint independently and answers "did THIS
endpoint receive any traffic in the last N minutes?". Each endpoint has its
own on/off checkbox in Settings → Actions → API Silence Alert. The alarm
fires whenever a TRACKED endpoint's window is empty — even if other
endpoints are noisy.

Motivation: the earlier "GET vs POST group" design used union semantics
(any hit from any tracked endpoint reset the timer). In production that
hid a legitimate incident — POST /api/v1/report/url/ was silent for two
days while POST /api/v1/report/ip/ stayed busy, so the union never went
quiet and no alarm fired. Per-endpoint tracking surfaces exactly that
case.

Uses the same ActivityLog rows the rate-limit monitor reads, so no extra
storage or middleware is needed.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.db.models import Max
from django.utils import timezone

from apps.settings_app.cache import SettingsCache

logger = logging.getLogger(__name__)


# Ordered by user-facing category (IP → Hash → URL → misc) so the settings
# tab, the alert e-mail table and the test-mail preview all present the
# endpoints in the same intuitive grouping.
#
# Each row: (settings_key, activitylog_action, http_method, url_path, label)
ENDPOINT_MAP = [
    ('actions.silence_ep_report_ip',   'api.report',      'POST', '/report/ip/',   'Report IP'),
    ('actions.silence_ep_blacklist',   'api.blacklist',   'GET',  '/blacklist/',   'IP Blacklist'),
    ('actions.silence_ep_report_hash', 'api.hash_report', 'POST', '/report/hash/', 'Report Hash'),
    ('actions.silence_ep_hashlist',    'api.hashlist',    'GET',  '/hashlist/',    'Hash Blacklist'),
    ('actions.silence_ep_report_url',  'api.url_report',  'POST', '/report/url/',  'Report URL'),
    ('actions.silence_ep_urllist',     'api.urllist',     'GET',  '/urllist/',     'URL Blacklist'),
    ('actions.silence_ep_status',      'api.status',      'GET',  '/status/',      'Status'),
]


def _read_int(key: str, default: int) -> int:
    try:
        return int(SettingsCache.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def _read_bool(key: str, default: bool) -> bool:
    val = SettingsCache.get(key, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(val)


def find_silent_endpoints() -> dict:
    """Evaluate every configured endpoint against the silence window.

    Returns a dict the alert service + test-mail preview both consume:
      threshold_minutes  int   — length of the silence window
      window_start       dt    — `now - threshold_minutes`
      endpoints          list  — one entry per row in ENDPOINT_MAP with
                                 `tracked`, `window_hits`, `last_activity_at`,
                                 `silent` and `silent_minutes` populated.
                                 Untracked endpoints appear too so the
                                 preview can show what's off; only tracked
                                 ones drive the alarm.
      tracked_count      int
      silent_endpoints   list  — subset of `endpoints` where silent=True
      has_silent         bool  — True → the alarm should fire (subject to
                                 recipient config and cooldown)
    """
    from apps.settings_app.models import ActivityLog

    threshold_minutes = max(1, _read_int('actions.silence_threshold_minutes', 5))
    now = timezone.now()
    window_start = now - timedelta(minutes=threshold_minutes)

    endpoints, silent_list = [], []
    tracked_count = 0
    for key, action, method, path, label in ENDPOINT_MAP:
        tracked = _read_bool(key, True)
        window_hits = 0
        last_activity = None
        if tracked:
            tracked_count += 1
            agg = ActivityLog.objects.filter(action=action).aggregate(
                last_seen=Max('timestamp'),
            )
            last_activity = agg.get('last_seen')
            window_hits = ActivityLog.objects.filter(
                action=action, timestamp__gte=window_start,
            ).count()
        silent = bool(tracked and window_hits == 0)
        silent_minutes = None
        if last_activity is not None:
            silent_minutes = int((now - last_activity).total_seconds() // 60)
        row = {
            'settings_key':     key,
            'action':           action,
            'method':           method,
            'path':             path,
            'label':            label,
            'tracked':          tracked,
            'window_hits':      window_hits,
            'last_activity_at': last_activity,
            'silent':           silent,
            'silent_minutes':   silent_minutes,
        }
        endpoints.append(row)
        if silent:
            silent_list.append(row)

    return {
        'threshold_minutes': threshold_minutes,
        'window_start':      window_start,
        'endpoints':         endpoints,
        'tracked_count':     tracked_count,
        'silent_endpoints':  silent_list,
        'has_silent':        bool(silent_list),
    }


def sample_endpoint_activity(lookback_hours: int = 24) -> list[dict]:
    """Per-endpoint 24-hour snapshot for the test-mail preview.

    Emits one row per configured endpoint (tracked and untracked) so the
    operator can sanity-check which endpoints are being watched and what
    their last-24h traffic looks like. Uses one query per endpoint — the
    row count is fixed at len(ENDPOINT_MAP) so the fan-out is bounded."""
    from apps.settings_app.models import ActivityLog

    since = timezone.now() - timedelta(hours=lookback_hours)
    out = []
    for key, action, method, path, label in ENDPOINT_MAP:
        tracked = _read_bool(key, True)
        agg = ActivityLog.objects.filter(action=action).aggregate(
            last_seen=Max('timestamp'),
        )
        hits = ActivityLog.objects.filter(
            action=action, timestamp__gte=since,
        ).count()
        out.append({
            'settings_key': key,
            'action':       action,
            'method':       method,
            'path':         path,
            'label':        label,
            'tracked':      tracked,
            'hits':         hits,
            'last_seen':    agg.get('last_seen'),
        })
    return out
