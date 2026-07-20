from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hashlist', '0005_hashentry_vt_metadata'),
    ]

    operations = [
        migrations.AddField(
            model_name='hashentry',
            name='vt_unavailable',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text=(
                    "True when VirusTotal was queried but did not return a result "
                    "(timeout, quota exhausted, network error). Such entries stay "
                    "is_active=True for admin visibility but are excluded from the "
                    "downstream /api/v1/hashlist/ feed until a valid score arrives."
                ),
            ),
        ),
    ]
