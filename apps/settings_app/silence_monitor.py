"""Global API-silence detector.

Watches the whole API request stream (not any single caller) and answers
"was there any traffic in the last N minutes?" — with the definition of
"any traffic" driven by two settings-tab checkboxes:

  * `actions.silence_track_get`  → count GET-shaped endpoints
    (`api.blacklist`, `api.hashlist`, `api.urllist`, `api.status`)
  * `actions.silence_track_post` → count POST-shaped endpoints
    (`api.report`, `api.report.skipped`, `api.hash_report`, `api.url_report`)

Either can be enabled independently. If BOTH are enabled, a request from
either group resets the silence timer — the platform stays "not silent"
as long as any tracked kind of request keeps arriving. If ONLY GET is
enabled, POST activity is ignored (and vice versa). If neither is
enabled, the alert is effectively disabled.

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


# Endpoint families that count as "the platform is being talked to". Grouped
# by HTTP verb because that's how the UI exposes them to the operator.
#
# `api.rate_limit` / `api.rate_limit_rpm` are deliberately excluded — they're
# internal signals emitted when the platform blocks a caller for exceeding
# quota, not client-verb requests we want to treat as evidence of life.
GET_ACTIONS = (
    'api.blacklist',
    'api.hashlist',
    'api.urllist',
    'api.status',
)
POST_ACTIONS = (
    'api.report',
    'api.report.skipped',
    'api.hash_report',
    'api.url_report',
)


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


def _tracked_actions() -> tuple[list[str], list[str]]:
    """Return `(tracked_actions, tracked_labels)` based on the two checkbox
    settings. Empty list on both sides means "nothing to watch" — the caller
    should treat that as feature-disabled rather than "always silent"."""
    track_get  = _read_bool('actions.silence_track_get',  True)
    track_post = _read_bool('actions.silence_track_post', True)
    actions, labels = [], []
    if track_get:
        actions.extend(GET_ACTIONS)
        labels.append('GET')
    if track_post:
        actions.extend(POST_ACTIONS)
        labels.append('POST')
    return actions, labels


def check_global_silence() -> dict:
    """Evaluate the platform's API traffic against the silence threshold.

    Returns a dict the alert service + test-mail preview both consume:
      enabled            bool  — at least one method group is being tracked
      tracked_actions    list  — ActivityLog action names in scope
      tracked_labels     list  — human labels for the tracked groups ('GET', 'POST')
      threshold_minutes  int   — silence window length
      window_start       dt    — `now - threshold_minutes`
      last_activity_at   dt|None — most recent qualifying request across all callers
      window_hits        int   — count of qualifying requests inside the window
      silent             bool  — True when `window_hits == 0` and monitoring is on
      silent_reason      str   — one-line diagnostic for logs / e-mail body
    """
    from apps.settings_app.models import ActivityLog

    threshold_minutes = max(1, _read_int('actions.silence_threshold_minutes', 5))
    tracked_actions, tracked_labels = _tracked_actions()
    now = timezone.now()
    window_start = now - timedelta(minutes=threshold_minutes)

    if not tracked_actions:
        return {
            'enabled':           False,
            'tracked_actions':   [],
            'tracked_labels':    [],
            'threshold_minutes': threshold_minutes,
            'window_start':      window_start,
            'last_activity_at':  None,
            'window_hits':       0,
            'silent':            False,
            'silent_reason':     'no method groups selected — monitoring is disabled',
        }

    # A single aggregate query is cheaper than two round-trips; grab both the
    # last-seen timestamp (across all time) and the in-window hit count.
    agg = ActivityLog.objects.filter(action__in=tracked_actions).aggregate(
        last_seen=Max('timestamp'),
    )
    last_activity = agg.get('last_seen')
    window_hits = ActivityLog.objects.filter(
        action__in=tracked_actions, timestamp__gte=window_start,
    ).count()

    silent = (window_hits == 0)
    if silent:
        if last_activity is None:
            reason = f'no {"/".join(tracked_labels)} API activity has ever been recorded'
        else:
            silent_min = int((now - last_activity).total_seconds() // 60)
            reason = (
                f'no {"/".join(tracked_labels)} API activity in the last '
                f'{threshold_minutes} minute(s) (last seen {silent_min} min ago)'
            )
    else:
        reason = f'{window_hits} {"/".join(tracked_labels)} request(s) in the last {threshold_minutes} minute(s)'

    return {
        'enabled':           True,
        'tracked_actions':   list(tracked_actions),
        'tracked_labels':    tracked_labels,
        'threshold_minutes': threshold_minutes,
        'window_start':      window_start,
        'last_activity_at':  last_activity,
        'window_hits':       window_hits,
        'silent':            silent,
        'silent_reason':     reason,
    }


def sample_recent_activity(lookback_hours: int = 24) -> list[dict]:
    """Per-action snapshot for the test-mail preview — one row per tracked
    action name with the count of hits in the last `lookback_hours` and the
    most recent timestamp. Groups that aren't currently tracked don't appear
    (mirrors what the alert would evaluate on)."""
    from apps.settings_app.models import ActivityLog

    tracked_actions, _labels = _tracked_actions()
    if not tracked_actions:
        return []

    since = timezone.now() - timedelta(hours=lookback_hours)
    rows = (
        ActivityLog.objects
        .filter(action__in=tracked_actions, timestamp__gte=since)
        .values('action')
        .annotate(hits=Count('id'), last_seen=Max('timestamp'))
    )
    seen_map = {r['action']: r for r in rows}

    # Emit one row per tracked action, so an action with zero recent hits
    # still shows up in the preview as "0 hits — never".
    out = []
    for action in tracked_actions:
        row = seen_map.get(action)
        label = 'GET' if action in GET_ACTIONS else 'POST'
        out.append({
            'action':    action,
            'label':     label,
            'hits':      row['hits'] if row else 0,
            'last_seen': row['last_seen'] if row else None,
        })
    out.sort(key=lambda r: (-r['hits'], r['action']))
    return out
