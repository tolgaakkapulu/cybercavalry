from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0005_blacklistentry_is_pinned'),
    ]

    operations = [
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_isp',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_usage_type',
            field=models.CharField(blank=True, default='', max_length=120),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_domain',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_hostnames',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_country_code',
            field=models.CharField(blank=True, default='', max_length=2),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_country_name',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_asn',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='blacklistentry',
            name='abuse_city',
            field=models.CharField(blank=True, default='', max_length=120),
        ),
    ]
