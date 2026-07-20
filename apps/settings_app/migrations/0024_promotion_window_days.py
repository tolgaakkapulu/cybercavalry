from django.db import migrations


WINDOW_SETTING = {
    'key': 'threat_intel.abuseipdb_promotion_window_days',
    'value': '7',
    'value_type': 'int',
    'category': 'threat_intel',
    'is_secret': False,
    'description': (
        "Length of the rolling window (in days) over which the promotion "
        "threshold count is evaluated. Default 7; range 1–30."
    ),
}


def add_setting(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.get_or_create(key=WINDOW_SETTING['key'], defaults=WINDOW_SETTING)


def remove_setting(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key=WINDOW_SETTING['key']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0023_blacklist_promotion_threshold'),
    ]

    operations = [
        migrations.RunPython(add_setting, remove_setting),
    ]
