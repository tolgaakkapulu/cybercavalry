from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('whitelist', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='whitelistentry',
            name='source',
            field=models.CharField(
                choices=[('manual', 'Manual'), ('import', 'Import')],
                default='manual',
                max_length=10,
            ),
        ),
    ]
