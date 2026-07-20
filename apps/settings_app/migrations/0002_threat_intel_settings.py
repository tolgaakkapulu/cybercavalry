from django.db import migrations


THREAT_INTEL_SETTINGS = [
    {
        'key': 'threat_intel.abuseipdb_enabled',
        'value': 'false',
        'value_type': 'bool',
        'category': 'threat_intel',
        'description': 'Enable AbuseIPDB threat intelligence integration',
        'is_secret': False,
    },
    {
        'key': 'threat_intel.abuseipdb_api_key',
        'value': '',
        'value_type': 'str',
        'category': 'threat_intel',
        'description': 'AbuseIPDB API key (v2)',
        'is_secret': True,
    },
    {
        'key': 'threat_intel.abuseipdb_max_age_days',
        'value': '30',
        'value_type': 'int',
        'category': 'threat_intel',
        'description': 'Maximum age of reports to consider (days, 1–365)',
        'is_secret': False,
    },
    {
        'key': 'threat_intel.abuseipdb_auto_check',
        'value': 'true',
        'value_type': 'bool',
        'category': 'threat_intel',
        'description': 'Automatically query AbuseIPDB when a new IP is added to the blacklist',
        'is_secret': False,
    },
]


def create_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for s in THREAT_INTEL_SETTINGS:
        Setting.objects.get_or_create(key=s['key'], defaults=s)


def delete_settings(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__startswith='threat_intel.abuseipdb').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_settings, delete_settings),
    ]
