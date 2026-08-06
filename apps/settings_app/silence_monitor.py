"""API silence detector for integrated products (firewall, XDR, SIEM).

The idea: any partner that talks to the platform on a schedule (typically
GET /api/v1/blacklist/ every minute or every hour) should keep talking. If
a well-established caller suddenly falls silent, something is wrong on their
side — dead cron, revoked token, network split, wrong URL after DNS change.
Better an e-mail than finding out days later.

`find_silent_callers()` returns the list of monitored callers whose most
recent API request is older than `silence_threshold_minutes`. A caller is
"monitored" once they have produced at least `silence_baseline_min_hits`
API requests during the last 24h — this filters one-off scripts, port
scans and admins poking the endpoint from a browser, while still catching
new integrations after their first stable day.

Returned entries:
    {
      'caller':         'ip:10.34.36.254 (anonymous)' | 'firewall.svc',
      'user_id':        None | 42,
      'last_seen':      datetime,
      'silent_minutes': 12,
      'baseline_hits':  1440,   # how many hits in last 24h
    }

Uses the same ActivityLog rows the rate-limit monitor reads, so no extra
storage or middleware is needed.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.db.models import Max, Count
from django.utils import timezone

from apps.settings_app.cache import SettingsCache

logger = logging.getLogger(__name__)


# Same action set as the rate-limit monitor -- both watch the same request
# stream, they just answer different questions about it.
_API_ACTIONS = (
    'api.report', 'api.report.skipped',
    'api.hash_report',
    'api.blacklist', 'api.hashlist',
    'api.status',
    'api.rate_limit',
)

_BASELINE_HOURS = 24  # hard-coded window for "regular caller" detection


def _read_int(key: str, default: int) -> int:
    try:
        return int(SettingsCache.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def find_silent_callers() -> tuple[list[dict], int, int]:
    """Return `(silent, threshold_minutes, baseline_min_hits)`.

    A caller shows up in `silent` when:
      1. Baseline: they generated >= baseline_min_hits API requests in the
         last 24h (so we know they're a regular integration, not a one-off).
      2. Silence: they have made zero API requests in the last
         `threshold_minutes`.
    """
    from apps.settings_app.models import ActivityLog

    threshold_minutes = max(1, _read_int('actions.silence_threshold_minutes', 5))
    baseline_min_hits = max(1, _read_int('actions.silence_baseline_min_hits', 30))

    now      = timezone.now()
    baseline = now - timedelta(hours=_BASELINE_HOURS)
    silence  = now - timedelta(minutes=threshold_minutes)

    # Baseline: for each caller, count 24h hits and record the most-recent one.
    # `values(...).annotate(...)` gives us GROUP BY (user_id, ip_address) with
    # both the hit count and the last-seen timestamp in a single query.
    rows = (
        ActivityLog.objects
        .filter(timestamp__gte=baseline, action__in=_API_ACTIONS)
        .values('user_id', 'user__username', 'ip_address')
        .annotate(hits=Count('id'), last_seen=Max('timestamp'))
        .filter(hits__gte=baseline_min_hits)
    )

    silent: list[dict] = []
    for r in rows:
        if r['last_seen'] and r['last_seen'] > silence:
            continue  # still active within the silence window
        uid = r.get('user_id')
        if uid:
            caller  = r.get('user__username') or f'user #{uid}'
            key     = f'user:{uid}'
        else:
            ip      = (r.get('ip_address') or '').strip() or 'unknown'
            caller  = f'{ip} (anonymous)'
            key     = f'ip:{ip}'
        silent_delta = now - r['last_seen'] if r['last_seen'] else timedelta(hours=999)
        silent.append({
            'caller':          caller,
            'caller_key':      key,
            'user_id':         uid,
            'last_seen':       r['last_seen'],
            'silent_minutes':  int(silent_delta.total_seconds() // 60),
            'baseline_hits':   r['hits'],
        })

    # Longest-silent first so downstream truncation keeps the worst offender.
    silent.sort(key=lambda r: r['silent_minutes'], reverse=True)
    return silent, threshold_minutes, baseline_min_hits


def sample_recent_callers() -> list[dict]:
    """Same shape as `find_silent_callers()` but returns every monitored caller
    with their current silence duration -- used by the "Send Test Mail" preview
    so the operator sees the live picture (silent + still-talking together)."""
    from apps.settings_app.models import ActivityLog

    baseline_min_hits = max(1, _read_int('actions.silence_baseline_min_hits', 30))
    now      = timezone.now()
    baseline = now - timedelta(hours=_BASELINE_HOURS)

    rows = (
        ActivityLog.objects
        .filter(timestamp__gte=baseline, action__in=_API_ACTIONS)
        .values('user_id', 'user__username', 'ip_address')
        .annotate(hits=Count('id'), last_seen=Max('timestamp'))
        .filter(hits__gte=baseline_min_hits)
    )

    out: list[dict] = []
    for r in rows:
        uid = r.get('user_id')
        if uid:
            caller = r.get('user__username') or f'user #{uid}'
            key    = f'user:{uid}'
        else:
            ip = (r.get('ip_address') or '').strip() or 'unknown'
            caller = f'{ip} (anonymous)'
            key    = f'ip:{ip}'
        silent_delta = now - r['last_seen'] if r['last_seen'] else timedelta(hours=999)
        out.append({
            'caller':          caller,
            'caller_key':      key,
            'user_id':         uid,
            'last_seen':       r['last_seen'],
            'silent_minutes':  int(silent_delta.total_seconds() // 60),
            'baseline_hits':   r['hits'],
        })
    out.sort(key=lambda r: r['silent_minutes'], reverse=True)
    return out
