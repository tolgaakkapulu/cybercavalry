"""Seed the `actions.*` category — quota-alert automation.

When either AbuseIPDB or VirusTotal daily quota usage climbs past the
configured percentage, a scheduler job sends an alert e-mail so admins can
rotate keys before the pipeline goes dark. All six knobs are user-editable
from Settings → Actions; the migration only creates the rows with sensible
defaults so a fresh install ships with monitoring disabled but pre-wired.
"""
from django.db import migrations


ACTIONS_SETTINGS = [
    {
        'key': 'actions.quota_alert_enabled', 'value': 'false',
        'value_type': 'bool', 'category': 'actions',
        'description': 'Send alert e-mails when API quota crosses the threshold',
        'is_secret': False,
    },
    {
        'key': 'actions.quota_alert_email', 'value': '',
        'value_type': 'str', 'category': 'actions',
        'description': 'Recipient e-mail address for quota alerts',
        'is_secret': False,
    },
    {
        'key': 'actions.quota_alert_threshold_pct', 'value': '80',
        'value_type': 'int', 'category': 'actions',
        'description': 'Percentage of daily quota that triggers the alert (1–100)',
        'is_secret': False,
    },
    {
        'key': 'actions.quota_check_interval', 'value': '1',
        'value_type': 'int', 'category': 'actions',
        'description': 'How often the checker runs (in the configured unit)',
        'is_secret': False,
    },
    {
        'key': 'actions.quota_check_interval_unit', 'value': 'hours',
        'value_type': 'str', 'category': 'actions',
        'description': 'Time unit for the check interval: minutes or hours',
        'is_secret': False,
    },
    {
        'key': 'actions.quota_alert_cooldown_hours', 'value': '24',
        'value_type': 'int', 'category': 'actions',
        'description': 'Suppress repeat alerts for a provider for this many hours',
        'is_secret': False,
    },
]


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for data in ACTIONS_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)


def delete(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting').objects.filter(
        key__in=[s['key'] for s in ACTIONS_SETTINGS]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0019_brand_color_red_default')]
    operations = [migrations.RunPython(create, delete)]
