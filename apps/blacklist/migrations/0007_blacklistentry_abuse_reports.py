from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0006_blacklistentry_abuse_metadata'),
    ]

    operations = [
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_total_reports',
            field=models.IntegerField(blank=True, help_text='AbuseIPDB total report count', null=True),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_last_reported_at',
            field=models.DateTimeField(blank=True, help_text='AbuseIPDB last report time', null=True),
        ),
    ]
