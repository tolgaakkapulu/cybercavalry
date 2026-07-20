from django.db import migrations


def create_no_group(apps, schema_editor):
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    BlacklistGroup.objects.get_or_create(
        name='no_group',
        defaults={
            'label': 'No Group',
            'default_duration_hours': None,  # permanent until re-scored
            'is_published': False,           # excluded from API blacklist endpoint
            'order': 99,
        }
    )


def delete_no_group(apps, schema_editor):
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    BlacklistGroup.objects.filter(name='no_group').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0002_blacklistentry_abuse_fields'),
    ]

    operations = [
        migrations.RunPython(create_no_group, delete_no_group),
    ]
