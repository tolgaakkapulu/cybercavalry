from django.db import migrations


PROMOTION_SETTING = {
    'key': 'threat_intel.abuseipdb_promotion_threshold',
    'value': '',
    'value_type': 'int',
    'category': 'threat_intel',
    'is_secret': False,
    'description': (
        "Auto-promote a 24h blacklist entry to the 30d group once its API "
        "report count reaches this value. Leave empty (or 0) to disable."
    ),
}

# Legacy key used by an earlier version of this migration. Removed on apply
# so an instance that already ran the previous revision doesn't end up with
# an orphan row that the settings page can't render.
_LEGACY_KEY = 'threat_intel.promotion_threshold'


def add_setting(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key=_LEGACY_KEY).delete()
    Setting.objects.get_or_create(key=PROMOTION_SETTING['key'], defaults=PROMOTION_SETTING)


def remove_setting(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key=PROMOTION_SETTING['key']).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0022_actions_syslog'),
    ]

    operations = [
        migrations.RunPython(add_setting, remove_setting),
    ]
