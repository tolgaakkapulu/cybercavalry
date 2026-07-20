"""Backfill `recent_hit_timestamps` for entries that carried a lifetime
`hit_count` but had no per-report timestamps to migrate.

We can't reconstruct the actual report times — those weren't recorded. What
we DO know is that at least one report landed on `last_seen_at`. For any
entry whose `last_seen_at` falls inside the storage window (30 days), we
seed `min(hit_count, MAX_SEED)` timestamps at that time so the 7-day
promotion window shows something meaningful right away rather than
sitting at 0. Entries whose last activity is older than the storage
window get an empty list — they truly had no recent hits.
"""
from datetime import timedelta

from django.db import migrations
from django.utils import timezone


_MAX_STORED_DAYS = 30
_MAX_SEED = 50  # cap the per-entry list so a huge legacy hit_count doesn't bloat the JSON


def seed_from_hit_count(apps, schema_editor):
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')
    cutoff = timezone.now() - timedelta(days=_MAX_STORED_DAYS)

    qs = BlacklistEntry.objects.filter(
        hit_count__gt=0,
        last_seen_at__isnull=False,
        last_seen_at__gte=cutoff,
    )
    for entry in qs:
        # Skip if we've already got timestamps (idempotent — safe to re-run).
        if entry.recent_hit_timestamps:
            continue
        stamp = entry.last_seen_at.isoformat()
        n = min(entry.hit_count, _MAX_SEED)
        entry.recent_hit_timestamps = [stamp] * n
        entry.save(update_fields=['recent_hit_timestamps'])


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0010_demote_stuck_promotions'),
    ]

    operations = [
        migrations.RunPython(seed_from_hit_count, migrations.RunPython.noop),
    ]
