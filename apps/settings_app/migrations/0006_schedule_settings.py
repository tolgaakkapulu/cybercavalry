from django.db import migrations


def add_schedule_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')

    defaults = [
        {
            'key': 'threat_intel.abuseipdb_schedule_enabled',
            'value': 'false',
            'value_type': 'bool',
            'category': 'threat_intel',
            'description': 'Enable automatic scheduled AbuseIPDB score refresh.',
            'is_secret': False,
        },
        {
            'key': 'threat_intel.abuseipdb_schedule_interval',
            'value': 'daily',
            'value_type': 'str',
            'category': 'threat_intel',
            'description': 'Schedule interval: hourly or daily.',
            'is_secret': False,
        },
        {
            'key': 'threat_intel.abuseipdb_schedule_time',
            'value': '02:00',
            'value_type': 'str',
            'category': 'threat_intel',
            'description': 'Time of day for daily scheduled refresh (HH:MM, 24h).',
            'is_secret': False,
        },
    ]

    for d in defaults:
        Setting.objects.get_or_create(key=d['key'], defaults={k: v for k, v in d.items() if k != 'key'})


def remove_schedule_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=[
        'threat_intel.abuseipdb_schedule_enabled',
        'threat_intel.abuseipdb_schedule_interval',
        'threat_intel.abuseipdb_schedule_time',
    ]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0005_ldap_enabled'),
    ]

    operations = [
        migrations.RunPython(add_schedule_settings, remove_schedule_settings),
    ]
