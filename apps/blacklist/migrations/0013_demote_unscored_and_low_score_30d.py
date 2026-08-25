"""One-shot cleanup for entries that landed in the 30d group without a
score high enough to justify it.

Two paths could have historically produced such rows:

  1. CSV import without an explicit `group` column — the old default was
     `30d`, so any row that skipped AbuseIPDB scoring (auto-check off, or
     score call timed out) sat in 30d forever with `abuse_confidence_score
     IS NULL` and `hit_count = 0`.
  2. A row was scored high once → landed in 30d, later rescored below the
     24h threshold → deactivated by `_apply_score_to_entry` but the group
     stayed at 30d (the deactivate path didn't change the FK). Even though
     the row was excluded from the API feed, filtering by group=30d in the
     admin UI still surfaced it as a "stale 30d".

Migration 0010 already sweeps a related legacy pattern (entries scored
into the 24h band but stuck at 30d under the old lifetime-promotion
rule). This migration extends that cleanup to the two cases above:

  * `score IS NULL` and `group = 30d` and not pinned
    → demote to `no_group` and deactivate (never scored, unpublished)
  * `score < threshold_24h` and `group = 30d` and not pinned
    → demote to `24h` and deactivate (matches the new runtime behaviour
      in `_apply_score_to_entry`)

Pinned entries are left alone in every case — they're admin overrides
and should survive automatic sweeps.
"""
from datetime import timedelta

from django.db import migrations
from django.utils import timezone


def _get_int_setting(Setting, key, default):
    try:
        raw = Setting.objects.get(key=key).value
        return int(raw) if raw not in ('', None) else default
    except (Setting.DoesNotExist, ValueError, TypeError):
        return default


def _forwards(apps, schema_editor):
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    Setting = apps.get_model('settings_app', 'Setting')

    try:
        group_30d      = BlacklistGroup.objects.get(name='30d')
        group_24h      = BlacklistGroup.objects.get(name='24h')
        group_no_group = BlacklistGroup.objects.filter(name='no_group').first()
    except BlacklistGroup.DoesNotExist:
        # Fresh install — nothing to sweep.
        return

    t24h = _get_int_setting(Setting, 'threat_intel.abuseipdb_threshold_24h', 10)

    demoted_unscored = 0
    demoted_low_score = 0

    # ── (1) unscored 30d rows → no_group (or 24h if no_group is absent) ──
    fallback_for_unscored = group_no_group or group_24h
    unscored = BlacklistEntry.objects.filter(
        group=group_30d,
        is_pinned=False,
        abuse_confidence_score__isnull=True,
    )
    for entry in unscored:
        # Skip if a row already exists at the target group for this CIDR —
        # unique_together(cidr, group) would raise. Duplicate is safe to
        # leave; the survivor keeps the row we care about.
        if BlacklistEntry.objects.filter(
            cidr=entry.cidr, group=fallback_for_unscored,
        ).exclude(pk=entry.pk).exists():
            continue
        entry.group = fallback_for_unscored
        entry.is_active = False
        # Refresh expires_at for the new group so lifetime matches.
        hours = fallback_for_unscored.default_duration_hours
        entry.expires_at = timezone.now() + timedelta(hours=hours) if hours else None
        entry.save(update_fields=['group', 'is_active', 'expires_at'])
        demoted_unscored += 1

    # ── (2) low-score 30d rows → 24h + deactivate ──
    low_score = BlacklistEntry.objects.filter(
        group=group_30d,
        is_pinned=False,
        abuse_confidence_score__isnull=False,
        abuse_confidence_score__lt=t24h,
    )
    for entry in low_score:
        if BlacklistEntry.objects.filter(
            cidr=entry.cidr, group=group_24h,
        ).exclude(pk=entry.pk).exists():
            continue
        entry.group = group_24h
        entry.is_active = False
        hours = group_24h.default_duration_hours
        entry.expires_at = timezone.now() + timedelta(hours=hours) if hours else None
        entry.save(update_fields=['group', 'is_active', 'expires_at'])
        demoted_low_score += 1

    if demoted_unscored or demoted_low_score:
        print(
            f'blacklist 0013: demoted {demoted_unscored} unscored 30d rows '
            f'to {fallback_for_unscored.name}; demoted {demoted_low_score} '
            f'low-score (<{t24h}) 30d rows to 24h; all deactivated.'
        )


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0012_clear_backfilled_hits'),
        ('settings_app', '0026_silence_method_toggles'),
    ]

    operations = [
        migrations.RunPython(_forwards, migrations.RunPython.noop),
    ]
