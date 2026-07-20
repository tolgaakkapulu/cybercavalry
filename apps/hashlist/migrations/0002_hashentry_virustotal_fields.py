from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hashlist', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='hashentry',
            name='vt_malicious',
            field=models.IntegerField(
                null=True, blank=True,
                help_text='Number of engines detecting as malicious',
            ),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_total',
            field=models.IntegerField(
                null=True, blank=True,
                help_text='Total number of engines scanned',
            ),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_checked_at',
            field=models.DateTimeField(
                null=True, blank=True,
                help_text='Last VirusTotal query time',
            ),
        ),
    ]
