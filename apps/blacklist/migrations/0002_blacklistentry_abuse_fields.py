from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_confidence_score',
            field=models.IntegerField(blank=True, help_text='AbuseIPDB confidence score (0-100)', null=True),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_checked_at',
            field=models.DateTimeField(blank=True, help_text='Last AbuseIPDB query time', null=True),
        ),
    ]
