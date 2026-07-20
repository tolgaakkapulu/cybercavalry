"""Auto-cleanup of old, inactive, AbuseIPDB-scored blacklist entries.

A run deletes every BlacklistEntry that matches ALL of:
  - is_active = False
  - abuse_confidence_score IS NOT NULL (i.e. has been scored)
  - score_min <= abuse_confidence_score <= score_max
  - added_at < now - retention_days

Every run emits a single ActivityLog entry (action
`threat_intel.abuseipdb_cleanup`) carrying the rule that fired, the
deleted-row count, and a snapshot of each deleted record (cidr, score,
group, added_at, ip enrichment) so admins can see *what* was removed and
*why* without trawling diff'd DB dumps.
"""
import logging
from datetime import timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)


def _read_rule():
    """Pull the current cleanup rule from SettingsCache, with safe clamps.

    Returns (enabled, score_min, score_max, retention_days). Even when the
    integration is disabled we still return validated values so callers can
    log the rule that would have been used if needed.
    """
    from apps.settings_app.cache import SettingsCache

    def _int(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(SettingsCache.get(key, default))))
        except (TypeError, ValueError):
            return default

    enabled = bool(SettingsCache.get('threat_intel.abuseipdb_cleanup_enabled', False))
    smin = _int('threat_intel.abuseipdb_cleanup_score_min', 0, 0, 100)
    smax = _int('threat_intel.abuseipdb_cleanup_score_max', 100, 0, 100)
    if smin > smax:
        smin, smax = smax, smin
    days = _int('threat_intel.abuseipdb_cleanup_retention_days', 30, 1, 3650)
    return enabled, smin, smax, days


def _snapshot(entry):
    """Compact serialisable snapshot of one entry — used as the deleted-row
    record in the ActivityLog detail. Stores all enrichment fields so the
    admin doesn't lose them when the row is gone."""
    return {
        'cidr': entry.cidr,
        'ip_address': entry.ip_address,
        'group': entry.group.name if entry.group_id else None,
        'score': entry.abuse_confidence_score,
        'added_at': entry.added_at.isoformat() if entry.added_at else None,
        'expires_at': entry.expires_at.isoformat() if entry.expires_at else None,
        'last_seen_at': entry.last_seen_at.isoformat() if entry.last_seen_at else None,
        'reason': entry.reason,
        'source': entry.source,
        'abuse_isp': entry.abuse_isp,
        'abuse_country_code': entry.abuse_country_code,
        'abuse_country_name': entry.abuse_country_name,
        'abuse_total_reports': entry.abuse_total_reports,
        'abuse_checked_at': entry.abuse_checked_at.isoformat() if entry.abuse_checked_at else None,
    }


def run_cleanup(actor=None, client_ip=''):
    """Execute one cleanup pass and return a summary dict.

    actor / client_ip are forwarded to the ActivityLog entry so a manual
    'Run cleanup now' click is attributed to the admin who triggered it.
    For scheduled runs both are left blank (the action itself flags the
    automated context).

    Returns {ran, deleted_count, rule, deleted}. `ran=False` means the
    integration is disabled — no DB writes happen and no log is emitted.
    """
    from apps.blacklist.models import BlacklistEntry
    from apps.settings_app.models import ActivityLog

    enabled, smin, smax, days = _read_rule()
    rule = {'score_min': smin, 'score_max': smax, 'retention_days': days}
    if not enabled:
        return {'ran': False, 'deleted_count': 0, 'rule': rule, 'deleted': []}

    cutoff = timezone.now() - timedelta(days=days)
    qs = (
        BlacklistEntry.objects
        .filter(
            is_active=False,
            abuse_confidence_score__isnull=False,
            abuse_confidence_score__gte=smin,
            abuse_confidence_score__lte=smax,
            added_at__lt=cutoff,
        )
        .select_related('group')
    )

    # Snapshot before deletion so the activity log entry carries the full
    # context of every removed row.
    snapshots = [_snapshot(e) for e in qs]
    deleted_count = qs.count()
    if deleted_count == 0:
        # Still log a no-op summary so admins can see the schedule ran and
        # found nothing to do — useful for trust-building on rare deletions.
        ActivityLog.log(
            actor, 'threat_intel.abuseipdb_cleanup', 'BlacklistEntry', 'bulk',
            {
                'rule': rule,
                'reason': (f'Inactive AbuseIPDB-scored entries older than '
                           f'{days}d with score {smin}-{smax} (no matches)'),
                'deleted_count': 0,
                'deleted': [],
                'automated': actor is None,
            },
            client_ip or '',
        )
        return {'ran': True, 'deleted_count': 0, 'rule': rule, 'deleted': []}

    qs.delete()

    ActivityLog.log(
        actor, 'threat_intel.abuseipdb_cleanup', 'BlacklistEntry', 'bulk',
        {
            'rule': rule,
            'reason': (f'Inactive AbuseIPDB-scored entries older than '
                       f'{days}d with score {smin}-{smax}'),
            'deleted_count': deleted_count,
            'deleted': snapshots,
            'automated': actor is None,
        },
        client_ip or '',
    )
    logger.info(
        'AbuseIPDB cleanup: deleted %d entries (score %d-%d, retention %dd)',
        deleted_count, smin, smax, days,
    )
    return {'ran': True, 'deleted_count': deleted_count, 'rule': rule, 'deleted': snapshots}
