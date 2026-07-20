"""Extend the Actions category with SMTP settings and the Rate Limit Alert.

The Actions category is being split into tabs: E-mail (SMTP transport used by
every alert), Quota Alert (already there), API Rate Limit Alert (per-caller
watchdog), and Syslog (to be added later). SMTP fields live under the shared
`actions.email_*` prefix so future alert types automatically pick up the
same transport without duplicating knobs.
"""
from django.db import migrations


NEW_SETTINGS = [
    # SMTP
    {'key': 'actions.email_smtp_host', 'value': '', 'value_type': 'str',
     'category': 'actions', 'description': 'Outgoing SMTP server hostname', 'is_secret': False},
    {'key': 'actions.email_smtp_port', 'value': '587', 'value_type': 'int',
     'category': 'actions', 'description': 'Outgoing SMTP server port', 'is_secret': False},
    {'key': 'actions.email_smtp_user', 'value': '', 'value_type': 'str',
     'category': 'actions', 'description': 'SMTP username', 'is_secret': False},
    {'key': 'actions.email_smtp_password', 'value': '', 'value_type': 'str',
     'category': 'actions', 'description': 'SMTP password (stored encrypted)', 'is_secret': True},
    {'key': 'actions.email_smtp_use_tls', 'value': 'true', 'value_type': 'bool',
     'category': 'actions', 'description': 'Wrap the connection in STARTTLS', 'is_secret': False},
    {'key': 'actions.email_from_address', 'value': '', 'value_type': 'str',
     'category': 'actions', 'description': 'Envelope sender address', 'is_secret': False},
    # API Rate Limit Alert
    {'key': 'actions.rate_limit_alert_enabled', 'value': 'false', 'value_type': 'bool',
     'category': 'actions', 'description': 'Send alert e-mails when an API caller crosses their rate limit', 'is_secret': False},
    {'key': 'actions.rate_limit_alert_email', 'value': '', 'value_type': 'str',
     'category': 'actions', 'description': 'Recipient e-mail address for rate-limit alerts', 'is_secret': False},
    {'key': 'actions.rate_limit_alert_threshold_pct', 'value': '80', 'value_type': 'int',
     'category': 'actions', 'description': 'Percentage of the per-minute rate-limit that triggers the alert', 'is_secret': False},
    {'key': 'actions.rate_limit_alert_cooldown_hours', 'value': '24', 'value_type': 'int',
     'category': 'actions', 'description': 'Suppress repeat rate-limit alerts per caller for this many hours', 'is_secret': False},
]


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for data in NEW_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)


def delete(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting').objects.filter(
        key__in=[s['key'] for s in NEW_SETTINGS]
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0020_actions_quota_alert')]
    operations = [migrations.RunPython(create, delete)]
