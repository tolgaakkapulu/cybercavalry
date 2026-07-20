"""Auto-cleanup of old, inactive, VirusTotal-scored hash blacklist entries.

A run deletes every HashEntry that matches ALL of:
  - is_active = False
  - list_type = 'black'
  - vt_malicious IS NOT NULL (i.e. has been scored)
  - score_min <= vt_malicious <= score_max
  - added_at < now - retention_days

Every run emits a single ActivityLog entry (action
`threat_intel.virustotal_cleanup`) carrying the rule that fired, the
deleted-row count, and a snapshot of each deleted record so admins can
see *what* was removed and *why* without trawling diff'd DB dumps.
"""
import logging
from datetime import timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)


def _read_rule():
    """Pull the current cleanup rule from SettingsCache, with safe clamps.

    Returns (enabled, score_min, score_max, retention_days)."""
    from apps.settings_app.cache import SettingsCache

    def _int(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(SettingsCache.get(key, default))))
        except (TypeError, ValueError):
            return default

    enabled = bool(SettingsCache.get('threat_intel.virustotal_cleanup_enabled', False))
    smin = _int('threat_intel.virustotal_cleanup_score_min', 0, 0, 100)
    smax = _int('threat_intel.virustotal_cleanup_score_max', 100, 0, 100)
    if smin > smax:
        smin, smax = smax, smin
    days = _int('threat_intel.virustotal_cleanup_retention_days', 30, 1, 3650)
    return enabled, smin, smax, days


def _snapshot(entry):
    """Serialisable snapshot of one hash entry — stored on the ActivityLog
    detail so the admin can reconstruct what was removed."""
    return {
        'hash_value': entry.hash_value,
        'hash_type': entry.hash_type,
        'list_type': entry.list_type,
        'vt_malicious': entry.vt_malicious,
        'vt_total': entry.vt_total,
        'added_at': entry.added_at.isoformat() if entry.added_at else None,
        'reason': entry.reason,
        'source': entry.source,
        'vt_threat_label': entry.vt_threat_label,
        'vt_type_description': entry.vt_type_description,
        'vt_meaningful_name': entry.vt_meaningful_name,
        'vt_first_seen': entry.vt_first_seen.isoformat() if entry.vt_first_seen else None,
        'vt_last_analysis': entry.vt_last_analysis.isoformat() if entry.vt_last_analysis else None,
        'vt_checked_at': entry.vt_checked_at.isoformat() if entry.vt_checked_at else None,
    }


def run_cleanup(actor=None, client_ip=''):
    """Execute one cleanup pass and return a summary dict.

    Returns {ran, deleted_count, rule, deleted}. `ran=False` means the
    integration is disabled — no DB writes happen and no log is emitted.
    """
    from apps.hashlist.models import HashEntry
    from apps.settings_app.models import ActivityLog

    enabled, smin, smax, days = _read_rule()
    rule = {'score_min': smin, 'score_max': smax, 'retention_days': days}
    if not enabled:
        return {'ran': False, 'deleted_count': 0, 'rule': rule, 'deleted': []}

    cutoff = timezone.now() - timedelta(days=days)
    qs = HashEntry.objects.filter(
        is_active=False,
        list_type=HashEntry.LIST_BLACK,
        vt_malicious__isnull=False,
        vt_malicious__gte=smin,
        vt_malicious__lte=smax,
        added_at__lt=cutoff,
    )

    snapshots = [_snapshot(e) for e in qs]
    deleted_count = qs.count()
    if deleted_count == 0:
        ActivityLog.log(
            actor, 'threat_intel.virustotal_cleanup', 'HashEntry', 'bulk',
            {
                'rule': rule,
                'reason': (f'Inactive VirusTotal-scored hashes older than '
                           f'{days}d with malicious count {smin}-{smax} (no matches)'),
                'deleted_count': 0,
                'deleted': [],
                'automated': actor is None,
            },
            client_ip or '',
        )
        return {'ran': True, 'deleted_count': 0, 'rule': rule, 'deleted': []}

    qs.delete()

    ActivityLog.log(
        actor, 'threat_intel.virustotal_cleanup', 'HashEntry', 'bulk',
        {
            'rule': rule,
            'reason': (f'Inactive VirusTotal-scored hashes older than '
                       f'{days}d with malicious count {smin}-{smax}'),
            'deleted_count': deleted_count,
            'deleted': snapshots,
            'automated': actor is None,
        },
        client_ip or '',
    )
    logger.info(
        'VirusTotal cleanup: deleted %d hash entries (score %d-%d, retention %dd)',
        deleted_count, smin, smax, days,
    )
    return {'ran': True, 'deleted_count': deleted_count, 'rule': rule, 'deleted': snapshots}
