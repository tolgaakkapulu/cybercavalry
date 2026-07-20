from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0008_hit_count_default_and_backfill'),
    ]

    operations = [
        migrations.AddField(
            model_name='blacklistentry',
            name='recent_hit_timestamps',
            field=models.JSONField(blank=True, default=list),
        ),
    ]
