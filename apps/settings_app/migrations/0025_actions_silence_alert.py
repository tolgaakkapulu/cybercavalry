"""API Silence Alert — notify when a regular integration caller stops calling.

Adds the third alert type under Actions → Alerts (alongside Quota and Rate
Limit). Detects integrated products (firewalls, XDR, SIEM) that normally
pull /api/v1/blacklist/ every minute or every hour, and mails the operator
when their heartbeat stops.

A "regular caller" is defined as any (user or IP) that produced at least
`silence_baseline_min_hits` API events during the last `24h`. This baseline
window is intentionally not configurable — 24h is long enough to absorb
weekly-cycle noise but short enough that a caller who joined yesterday
still qualifies.
"""
from django.db import migrations


NEW_SETTINGS = [
    {'key': 'actions.silence_alert_enabled', 'value': 'false', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Send alert e-mails when a regular API integration goes silent',
     'is_secret': False},
    {'key': 'actions.silence_alert_email', 'value': '', 'value_type': 'str',
     'category': 'actions',
     'description': 'Recipient e-mail address for silence alerts',
     'is_secret': False},
    {'key': 'actions.silence_threshold_minutes', 'value': '5', 'value_type': 'int',
     'category': 'actions',
     'description': 'Fire the alert when a monitored caller has not made an API request in this many minutes',
     'is_secret': False},
    {'key': 'actions.silence_baseline_min_hits', 'value': '30', 'value_type': 'int',
     'category': 'actions',
     'description': 'Minimum API hits in the past 24h for a caller to be considered a monitored integration',
     'is_secret': False},
    {'key': 'actions.silence_alert_cooldown_hours', 'value': '6', 'value_type': 'int',
     'category': 'actions',
     'description': 'Suppress repeat silence alerts per caller for this many hours',
     'is_secret': False},
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
    dependencies = [('settings_app', '0024_promotion_window_days')]
    operations = [migrations.RunPython(create, delete)]
