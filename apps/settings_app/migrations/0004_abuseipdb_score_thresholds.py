from django.db import migrations


THRESHOLD_SETTINGS = [
    {
        'key': 'threat_intel.abuseipdb_threshold_30d',
        'value': '80',
        'value_type': 'int',
        'category': 'threat_intel',
        'is_secret': False,
    },
    {
        'key': 'threat_intel.abuseipdb_threshold_24h',
        'value': '10',
        'value_type': 'int',
        'category': 'threat_intel',
        'is_secret': False,
    },
]


def add_threshold_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for data in THRESHOLD_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)


def remove_threshold_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=[s['key'] for s in THRESHOLD_SETTINGS]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0003_alter_setting_category'),
    ]

    operations = [
        migrations.RunPython(add_threshold_settings, remove_threshold_settings),
    ]
