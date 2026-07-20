from django.db import migrations


VIRUSTOTAL_SETTINGS = [
    ('threat_intel.virustotal_enabled',           'false',  'bool', 'Turn on VirusTotal hash reputation lookups.',                  False),
    ('threat_intel.virustotal_api_key',           '',       'str',  'Your VirusTotal v3 API key.',                                 True),
    ('threat_intel.virustotal_auto_check',        'true',   'bool', 'Automatically query VirusTotal when a new hash is added.',     False),
    ('threat_intel.virustotal_detection_threshold','5',     'int',  'Minimum number of malicious detections to flag a hash.',       False),
    ('threat_intel.virustotal_schedule_enabled',  'false',  'bool', 'Enable automatic periodic VirusTotal score refresh.',          False),
    ('threat_intel.virustotal_schedule_interval', 'daily',  'str',  'How often to run the automatic refresh: hourly or daily.',     False),
    ('threat_intel.virustotal_schedule_time',     '03:00',  'str',  'Time of day to run the daily refresh (HH:MM, 24-hour clock).', False),
]


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0008_alter_activitylog_table'),
    ]

    operations = [
        migrations.RunPython(
            lambda apps, schema_editor: [
                apps.get_model('settings_app', 'Setting').objects.get_or_create(
                    key=key,
                    defaults={
                        'value': value,
                        'value_type': vtype,
                        'category': 'threat_intel',
                        'description': desc,
                        'is_secret': secret,
                    },
                )
                for key, value, vtype, desc, secret in VIRUSTOTAL_SETTINGS
            ],
            migrations.RunPython.noop,
        ),
    ]
