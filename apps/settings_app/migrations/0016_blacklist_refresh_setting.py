"""Adds the `general.blacklist_refresh_seconds` setting.

Drives the auto-refresh interval on the IP / Hash Blacklist list pages.
The default of 5 seconds is intentionally aggressive so admins see new
entries stream in nearly real-time; the value can be raised in settings
if a large multi-admin deployment ever needs to throttle the polling.
"""
from django.db import migrations


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.get_or_create(
        key='general.blacklist_refresh_seconds',
        defaults={
            'value':       '5',
            'value_type':  'int',
            'category':    'general',
            'description': 'IP/Hash Blacklist list-page auto-refresh interval in seconds',
            'is_secret':   False,
        },
    )


def delete(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting').objects.filter(
        key='general.blacklist_refresh_seconds'
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('settings_app', '0015_cleanup_settings'),
    ]
    operations = [migrations.RunPython(create, delete)]
