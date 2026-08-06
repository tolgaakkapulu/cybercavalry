"""Auto-cleanup of old, inactive, VirusTotal-scored hash blacklist entries.

A run deletes every URLEntry that matches ALL of:
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
    """Serialisable snapshot of one URL entry — stored on the ActivityLog
    detail so the admin can reconstruct what was removed."""
    return {
        'url_value': entry.url_value,
        'url_hash': entry.url_hash,
        'hostname': entry.hostname,
        'list_type': entry.list_type,
        'vt_malicious': entry.vt_malicious,
        'vt_total': entry.vt_total,
        'added_at': entry.added_at.isoformat() if entry.added_at else None,
        'reason': entry.reason,
        'source': entry.source,
        'vt_threat_label': entry.vt_threat_label,
        'vt_categories': entry.vt_categories,
        'vt_final_url': entry.vt_final_url,
        'vt_title': entry.vt_title,
        'vt_first_seen': entry.vt_first_seen.isoformat() if entry.vt_first_seen else None,
        'vt_last_analysis': entry.vt_last_analysis.isoformat() if entry.vt_last_analysis else None,
        'vt_checked_at': entry.vt_checked_at.isoformat() if entry.vt_checked_at else None,
        # Extended VT enrichment (0003 migration)
        'vt_reputation': entry.vt_reputation,
        'vt_votes_harmless': entry.vt_votes_harmless,
        'vt_votes_malicious': entry.vt_votes_malicious,
        'vt_http_code': entry.vt_http_code,
        'vt_content_length': entry.vt_content_length,
        'vt_redirect_count': entry.vt_redirect_count,
        'vt_serving_ip': entry.vt_serving_ip,
        'vt_tags': entry.vt_tags,
        'vt_languages': entry.vt_languages,
        'vt_harmless': entry.vt_harmless,
        'vt_suspicious': entry.vt_suspicious,
        'vt_undetected': entry.vt_undetected,
        'vt_registrar': entry.vt_registrar,
        'vt_creation_date': entry.vt_creation_date.isoformat() if entry.vt_creation_date else None,
        'vt_popularity_rank': entry.vt_popularity_rank,
    }


def run_cleanup(actor=None, client_ip=''):
    """Execute one cleanup pass and return a summary dict.

    Returns {ran, deleted_count, rule, deleted}. `ran=False` means the
    integration is disabled — no DB writes happen and no log is emitted.
    """
    from apps.urllist.models import URLEntry
    from apps.settings_app.models import ActivityLog

    enabled, smin, smax, days = _read_rule()
    rule = {'score_min': smin, 'score_max': smax, 'retention_days': days}
    if not enabled:
        return {'ran': False, 'deleted_count': 0, 'rule': rule, 'deleted': []}

    cutoff = timezone.now() - timedelta(days=days)
    qs = URLEntry.objects.filter(
        is_active=False,
        list_type=URLEntry.LIST_BLACK,
        vt_malicious__isnull=False,
        vt_malicious__gte=smin,
        vt_malicious__lte=smax,
        added_at__lt=cutoff,
    )

    snapshots = [_snapshot(e) for e in qs]
    deleted_count = qs.count()
    if deleted_count == 0:
        ActivityLog.log(
            actor, 'threat_intel.virustotal_cleanup', 'URLEntry', 'bulk',
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
        actor, 'threat_intel.virustotal_cleanup', 'URLEntry', 'bulk',
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
