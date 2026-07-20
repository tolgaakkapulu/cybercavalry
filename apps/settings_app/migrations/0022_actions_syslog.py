"""Seed the syslog block of Settings → Actions.

Adds an `Enable Syslog` master toggle plus host / port / protocol and three
per-stream checkboxes (activity, error, access). The Syslog tab in the UI
becomes a real settings surface (was a "coming soon" placeholder). Actual
forwarding is handled by `apps/settings_app/syslog_service.py` — this
migration only creates the DB rows so a fresh install ships wired but off.
"""
from django.db import migrations


NEW_SETTINGS = [
    {'key': 'actions.syslog_enabled', 'value': 'false', 'value_type': 'bool',
     'category': 'actions', 'description': 'Enable syslog forwarding', 'is_secret': False},
    {'key': 'actions.syslog_host', 'value': '', 'value_type': 'str',
     'category': 'actions', 'description': 'Syslog collector hostname or IP', 'is_secret': False},
    {'key': 'actions.syslog_port', 'value': '514', 'value_type': 'int',
     'category': 'actions', 'description': 'Syslog collector port', 'is_secret': False},
    {'key': 'actions.syslog_protocol', 'value': 'udp', 'value_type': 'str',
     'category': 'actions', 'description': 'Transport protocol — udp or tcp', 'is_secret': False},
    {'key': 'actions.syslog_send_activity', 'value': 'false', 'value_type': 'bool',
     'category': 'actions', 'description': 'Forward activity-log entries to syslog', 'is_secret': False},
    {'key': 'actions.syslog_send_error', 'value': 'false', 'value_type': 'bool',
     'category': 'actions', 'description': 'Forward Python error/warning logs to syslog', 'is_secret': False},
    {'key': 'actions.syslog_send_access', 'value': 'false', 'value_type': 'bool',
     'category': 'actions', 'description': 'Forward HTTP access logs to syslog', 'is_secret': False},
]


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for data in NEW_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)


def delete(apps, schema_editor):
    apps.get_model('settings_app', 'Setting').objects.filter(
        key__in=[s['key'] for s in NEW_SETTINGS]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0021_actions_email_and_rate_limit')]
    operations = [migrations.RunPython(create, delete)]
