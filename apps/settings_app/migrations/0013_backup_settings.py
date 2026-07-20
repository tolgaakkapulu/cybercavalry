from django.db import migrations


_BACKUP_DEFAULTS = [
    ('backup.enabled', 'false', 'bool',
     'Enable automatic daily database backups.'),
    ('backup.directory', '', 'str',
     'Directory where backup files are stored. Leave blank to use <project>/backups.'),
    ('backup.time', '04:00', 'str',
     'Time of day to run the daily backup (HH:MM, 24-hour clock, server timezone).'),
    ('backup.retention_days', '30', 'int',
     'Delete backups older than this many days. Set to 0 to keep all backups (cumulative).'),
]


def add_backup_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for key, value, vtype, desc in _BACKUP_DEFAULTS:
        Setting.objects.get_or_create(
            key=key,
            defaults={
                'value': value,
                'value_type': vtype,
                'category': 'backup',
                'description': desc,
                'is_secret': False,
            },
        )


def remove_backup_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__startswith='backup.').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0012_platform_email'),
    ]

    operations = [
        migrations.RunPython(add_backup_settings, remove_backup_settings),
    ]
