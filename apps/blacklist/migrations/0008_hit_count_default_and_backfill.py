from django.db import migrations, models


def backfill_hit_count(apps, schema_editor):
    """Every blacklist entry represents at least one report, so a row with
    hit_count=0 (legacy rows written before hit tracking was meaningful) is
    normalised to 1. Rows already at 1 or higher are untouched — we only
    lift the floor, never overwrite real counts."""
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')
    BlacklistEntry.objects.filter(hit_count=0).update(hit_count=1)


def reverse_noop(apps, schema_editor):
    # Backfill is intentionally one-way — rolling back to hit_count=0 for
    # the affected rows would erase the "seen at least once" signal.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0007_blacklistentry_abuse_reports'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blacklistentry',
            name='hit_count',
            field=models.IntegerField(default=1),
        ),
        migrations.RunPython(backfill_hit_count, reverse_noop),
    ]
