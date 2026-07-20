from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hashlist', '0004_hashentry_is_pinned'),
    ]

    operations = [
        migrations.AddField(
            model_name='hashentry',
            name='vt_threat_label',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_type_description',
            field=models.CharField(blank=True, default='', max_length=120),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_size',
            field=models.BigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_meaningful_name',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_first_seen',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_last_analysis',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='hashentry',
            name='vt_times_submitted',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
