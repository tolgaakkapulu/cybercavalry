"""Per-caller API rate-limit usage sampler.

The API layer already logs every `/api/*` request as an `api.*` action in
ActivityLog. Rather than reaching into the rate-limit cache (backend-agnostic
key iteration isn't guaranteed on LocMem / file caches), we replay the last
60 seconds of those log rows and group by caller.

Returned by `sample_rate_limit_usage()`:
    [
      {
        'caller':      'jdoe' | 'ip:203.0.113.7',
        'user_id':     42 | None,
        'requests':    47,           # last-60s API calls (incl. 429s)
        'limit_rpm':   60,           # from api.rate_limit_rpm setting
        'usage_pct':   78,           # rounded
        'threshold_pct': 80,         # from actions.rate_limit_alert_threshold_pct
        'over_threshold': False,
      },
      ...
    ]

Only callers meeting `usage_pct >= threshold_pct` are candidates for an
alert e-mail; the scheduler filters and applies cooldown on top of this.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from apps.settings_app.cache import SettingsCache

logger = logging.getLogger(__name__)


# Which action names count as a "real" API request the caller made against
# the platform. `api.rate_limit` (the 429 rejection) is included on purpose —
# a rejected call is still a caller-initiated request that saturated the
# limit, so it belongs in the usage tally.
_API_ACTIONS = (
    'api.report', 'api.report.skipped',
    'api.hash_report',
    'api.blacklist', 'api.hashlist',
    'api.status',
    'api.rate_limit',
)


def sample_rate_limit_usage(window_seconds: int = 60) -> list[dict]:
    """Snapshot the last `window_seconds` of API activity per caller.

    Buckets are keyed by user when the log row has one (authenticated
    callers) and by client IP otherwise (anonymous callers via API token
    can still be identified by their reporter IP).
    """
    from apps.settings_app.models import ActivityLog

    try:
        limit_rpm = int(SettingsCache.get('api.rate_limit_rpm', 60) or 60)
    except (TypeError, ValueError):
        limit_rpm = 60
    try:
        threshold_pct = int(SettingsCache.get('actions.rate_limit_alert_threshold_pct', 80) or 80)
    except (TypeError, ValueError):
        threshold_pct = 80
    threshold_pct = max(1, min(threshold_pct, 100))

    since = timezone.now() - timedelta(seconds=max(10, window_seconds))
    rows = (
        ActivityLog.objects
        .filter(timestamp__gte=since, action__in=_API_ACTIONS)
        .select_related('user')
        .values('user_id', 'user__username', 'ip_address')
    )

    buckets: dict[str, dict] = {}
    for r in rows:
        uid = r.get('user_id')
        if uid:
            caller_key = f'user:{uid}'
            display    = r.get('user__username') or f'user #{uid}'
        else:
            ip = (r.get('ip_address') or '').strip() or 'unknown'
            caller_key = f'ip:{ip}'
            display    = f'{ip} (anonymous)'
        b = buckets.setdefault(caller_key, {
            'caller':   display,
            'user_id':  uid,
            'requests': 0,
        })
        b['requests'] += 1

    out: list[dict] = []
    for _, b in buckets.items():
        # `limit_rpm` describes the per-token cap. Anonymous IP callers get
        # 3× headroom in the actual limiter, but the alert threshold is
        # keyed off the per-token number so admins have one intuitive value
        # to reason about.
        usage_pct = int(round(b['requests'] / limit_rpm * 100)) if limit_rpm else 0
        out.append({
            'caller':         b['caller'],
            'user_id':        b['user_id'],
            'requests':       b['requests'],
            'limit_rpm':      limit_rpm,
            'usage_pct':      usage_pct,
            'threshold_pct':  threshold_pct,
            'over_threshold': usage_pct >= threshold_pct,
        })
    # Highest-usage caller first so any downstream truncation keeps the
    # noisiest talker.
    out.sort(key=lambda r: r['usage_pct'], reverse=True)
    return out


def find_callers_over_threshold() -> tuple[list[dict], int]:
    """Convenience helper for the scheduler and the test-mail preview.

    Returns `(offenders, threshold_pct)` — offenders is the subset of the
    sample where `over_threshold=True`.
    """
    sample = sample_rate_limit_usage(window_seconds=60)
    if not sample:
        try:
            threshold_pct = int(SettingsCache.get('actions.rate_limit_alert_threshold_pct', 80) or 80)
        except (TypeError, ValueError):
            threshold_pct = 80
        return [], max(1, min(threshold_pct, 100))
    threshold_pct = sample[0]['threshold_pct']
    return [r for r in sample if r['over_threshold']], threshold_pct
