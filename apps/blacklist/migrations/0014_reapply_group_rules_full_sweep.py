"""Full-sweep re-application of the current group assignment rules.

Prior data-migration cleanups landed piecewise:
  * 0010: entries stuck at 30d whose score would resolve to 24h under the
          new rolling-window promotion semantic (a specific legacy pattern
          from the lifetime → rolling promotion switch).
  * 0013: entries stuck at 30d because they never got a score (CSV import
          default was '30d'), or their score dropped below the 24h band.

Both handled slices of the "stuck-at-30d" surface but neither covered the
middle case now surfacing in production:

    score IN [t24h, t30d) AND group = 30d AND recent_hits < promo_threshold

i.e. a row whose score alone would land it in 24h and whose recent-hit
count is not high enough to trigger the promotion rule — so it should be
in 24h, not 30d. This slipped through 0010 (that migration only ran once
at a specific point in time; rows scored high back then and re-scored
lower later were not revisited) and through 0013 (whose filters excluded
scores >= t24h).

This migration is a full sweep: it re-runs the current group-assignment
rules over every active non-pinned entry with a stored score, and moves
rows that don't match the current rules. Idempotent — running it twice
produces no additional changes because after pass 1 every row already
sits where the rules would place it.
"""
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db import migrations
from django.utils import timezone


def _get_int_setting(Setting, key, default):
    try:
        raw = Setting.objects.get(key=key).value
        return int(raw) if raw not in ('', None) else default
    except (Setting.DoesNotExist, ValueError, TypeError):
        return default


def _count_recent(raw_list, cutoff):
    count = 0
    for raw in (raw_list or []):
        try:
            t = datetime.fromisoformat(raw)
            if t.tzinfo is None:
                t = t.replace(tzinfo=dt_timezone.utc)
            if t >= cutoff:
                count += 1
        except (ValueError, TypeError):
            continue
    return count


def _forwards(apps, schema_editor):
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    Setting = apps.get_model('settings_app', 'Setting')

    try:
        group_24h = BlacklistGroup.objects.get(name='24h')
        group_30d = BlacklistGroup.objects.get(name='30d')
    except BlacklistGroup.DoesNotExist:
        return

    t24h = _get_int_setting(Setting, 'threat_intel.abuseipdb_threshold_24h', 10)
    t30d = _get_int_setting(Setting, 'threat_intel.abuseipdb_threshold_30d', 80)
    promo_threshold = _get_int_setting(Setting, 'threat_intel.abuseipdb_promotion_threshold', 0)
    promo_window = _get_int_setting(Setting, 'threat_intel.abuseipdb_promotion_window_days', 7)
    promo_window = max(1, min(30, promo_window))
    cutoff = timezone.now() - timedelta(days=promo_window)

    stats = {'demoted_30d_to_24h': 0, 'promoted_24h_to_30d': 0, 'skipped_duplicate': 0}

    # Consider every scored, non-pinned entry — an admin adjusting scores or
    # thresholds after this sweep will still land the row in the right group
    # via the runtime _apply_score_to_entry / reapply_thresholds paths.
    entries = BlacklistEntry.objects.filter(
        is_pinned=False,
        abuse_confidence_score__isnull=False,
    ).select_related('group')

    for entry in entries:
        score = entry.abuse_confidence_score

        # Rule (mirrors runtime _apply_score_to_entry):
        #   score >= t30d           → 30d
        #   score in [t24h, t30d)   → 24h  (promotion override applies)
        #   score < t24h            → covered by migration 0013; skip here.
        if score < t24h:
            continue

        if score >= t30d:
            target = group_30d
        else:
            target = group_24h
            # Promotion override — only applies to the 24h band.
            if promo_threshold > 0:
                recent = _count_recent(entry.recent_hit_timestamps, cutoff)
                if recent >= promo_threshold:
                    target = group_30d

        if entry.group_id == target.pk:
            continue

        # Avoid unique_together(cidr, group) conflicts — leave the row alone
        # if the target slot is already occupied by another row of this CIDR.
        conflict = BlacklistEntry.objects.filter(
            cidr=entry.cidr, group=target,
        ).exclude(pk=entry.pk).exists()
        if conflict:
            stats['skipped_duplicate'] += 1
            continue

        old_group_name = entry.group.name if entry.group_id else '?'
        entry.group = target

        # Refresh expires_at so the row's TTL matches its new bucket.
        hours = target.default_duration_hours
        if hours is not None:
            entry.expires_at = timezone.now() + timedelta(hours=hours)

        entry.save(update_fields=['group', 'expires_at'])

        if old_group_name == '30d' and target.pk == group_24h.pk:
            stats['demoted_30d_to_24h'] += 1
        elif old_group_name == '24h' and target.pk == group_30d.pk:
            stats['promoted_24h_to_30d'] += 1

    changed = stats['demoted_30d_to_24h'] + stats['promoted_24h_to_30d']
    if changed or stats['skipped_duplicate']:
        print(
            f"blacklist 0014: demoted {stats['demoted_30d_to_24h']} 30d → 24h "
            f"(score/promotion no longer justifies 30d), promoted "
            f"{stats['promoted_24h_to_30d']} 24h → 30d (score/promotion now "
            f"warrants 30d), skipped {stats['skipped_duplicate']} rows due to "
            f"unique-key conflict."
        )


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0013_demote_unscored_and_low_score_30d'),
        ('settings_app', '0026_silence_method_toggles'),
    ]

    operations = [
        migrations.RunPython(_forwards, migrations.RunPython.noop),
    ]
