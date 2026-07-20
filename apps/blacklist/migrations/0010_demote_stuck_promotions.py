"""One-shot cleanup for the promotion semantic change.

Migration 0009 switched the promotion threshold check from lifetime
`hit_count` to a rolling 7-day count of API report timestamps. Existing
30d entries that had been promoted under the old (lifetime) rule keep
sitting in 30d until either a score refresh or a threshold save
triggers re-evaluation. This migration performs that sweep once so the
UI matches the new semantic the moment `migrate` finishes, without
requiring the admin to touch anything.
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


def demote_stuck_promotions(apps, schema_editor):
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    Setting = apps.get_model('settings_app', 'Setting')

    try:
        group_24h = BlacklistGroup.objects.get(name='24h')
        group_30d = BlacklistGroup.objects.get(name='30d')
    except BlacklistGroup.DoesNotExist:
        # Fresh install without seeded groups yet — nothing to sweep.
        return

    t24h = _get_int_setting(Setting, 'threat_intel.abuseipdb_threshold_24h', 10)
    t30d = _get_int_setting(Setting, 'threat_intel.abuseipdb_threshold_30d', 80)
    threshold = _get_int_setting(Setting, 'threat_intel.abuseipdb_promotion_threshold', 0)

    cutoff = timezone.now() - timedelta(days=7)
    # Refresh entries currently at 30d whose score would resolve to 24h — the
    # candidate pool for a legacy promotion that no longer qualifies.
    candidates = BlacklistEntry.objects.filter(
        group=group_30d,
        is_pinned=False,
        abuse_confidence_score__isnull=False,
        abuse_confidence_score__gte=t24h,
        abuse_confidence_score__lt=t30d,
    )

    for entry in candidates:
        recent = _count_recent(entry.recent_hit_timestamps, cutoff)
        if threshold > 0 and recent >= threshold:
            # Still qualifies for promotion under the new rule — keep at 30d.
            continue
        # Would-be duplicate at 24h? Skip so we don't collide with an existing row.
        if BlacklistEntry.objects.filter(cidr=entry.cidr, group=group_24h).exclude(pk=entry.pk).exists():
            continue
        entry.group = group_24h
        # Refresh expires_at from the 24h group's default_duration_hours so the
        # demoted row picks up the shorter TTL immediately.
        hours = group_24h.default_duration_hours
        if hours is not None:
            entry.expires_at = timezone.now() + timedelta(hours=hours)
        entry.save(update_fields=['group', 'expires_at'])


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0009_recent_hit_timestamps'),
        ('settings_app', '0023_blacklist_promotion_threshold'),
    ]

    operations = [
        migrations.RunPython(demote_stuck_promotions, migrations.RunPython.noop),
    ]
