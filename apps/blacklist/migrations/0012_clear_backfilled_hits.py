"""Revert the 0011 backfill.

Migration 0011 seeded `recent_hit_timestamps` from `hit_count` at
`last_seen_at`, aiming to give legacy entries a non-zero recent count.
The unintended effect: the fake timestamps sit at the same moment, so
they either all land inside the configured window (inflating the recent
count to lifetime hit_count) or all fall out (dropping it to 0), never
tracking real activity. That made the promotion threshold and the Count
column both read like lifetime figures.

This migration clears every non-empty list so the rolling window starts
fresh. Real API reports arriving after this migration will populate
timestamps one-per-hit as intended, and both the display and the
promotion decision will reflect actual recent activity.
"""
from django.db import migrations


def clear_recent_hits(apps, schema_editor):
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')
    BlacklistEntry.objects.exclude(recent_hit_timestamps=[]).update(recent_hit_timestamps=[])


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0011_backfill_recent_hits'),
    ]

    operations = [
        migrations.RunPython(clear_recent_hits, migrations.RunPython.noop),
    ]
