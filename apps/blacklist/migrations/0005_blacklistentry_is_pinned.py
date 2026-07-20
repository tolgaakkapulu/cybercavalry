from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0004_remove_permanent_group'),
    ]

    operations = [
        migrations.AddField(
            model_name='blacklistentry',
            name='is_pinned',
            field=models.BooleanField(
                default=False,
                help_text='Pinned entries are exempt from automatic score-based group reassignment and deactivation',
            ),
        ),
    ]
