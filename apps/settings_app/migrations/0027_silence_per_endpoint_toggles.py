"""Redesign the API Silence Alert again — per-endpoint checkboxes.

The 0026 design used two GET/POST group toggles with union semantics
(any request from any tracked endpoint kept the timer alive). In
production that hid a legitimate incident — POST /api/v1/report/url/
was silent for two full days while POST /api/v1/report/ip/ stayed busy,
so the union never went quiet and no alarm fired.

New model: one on/off checkbox per endpoint (see
`silence_monitor.ENDPOINT_MAP`). The alarm fires whenever a TRACKED
endpoint's window is empty — independently of the others. Cooldown is
tracked per endpoint too, so a permanently-silent one doesn't drown out
a fresh incident on another.

This migration:
  * adds seven `actions.silence_ep_*` booleans (default True — the
    safest starting point, matches the previous "both track_get and
    track_post enabled" baseline)
  * removes the obsolete `actions.silence_track_get` and
    `actions.silence_track_post` rows
  * clears `actions.silence_alert_last_sent` because its stored value
    (a single ISO timestamp) no longer matches the new per-endpoint
    JSON map format
"""
from django.db import migrations


NEW_SETTINGS = [
    {'key': 'actions.silence_ep_report_ip', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when POST /api/v1/report/ip/ receives zero requests in the silence window',
     'is_secret': False},
    {'key': 'actions.silence_ep_blacklist', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when GET /api/v1/blacklist/ receives zero requests in the silence window',
     'is_secret': False},
    {'key': 'actions.silence_ep_report_hash', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when POST /api/v1/report/hash/ receives zero requests in the silence window',
     'is_secret': False},
    {'key': 'actions.silence_ep_hashlist', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when GET /api/v1/hashlist/ receives zero requests in the silence window',
     'is_secret': False},
    {'key': 'actions.silence_ep_report_url', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when POST /api/v1/report/url/ receives zero requests in the silence window',
     'is_secret': False},
    {'key': 'actions.silence_ep_urllist', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when GET /api/v1/urllist/ receives zero requests in the silence window',
     'is_secret': False},
    {'key': 'actions.silence_ep_status', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Alert when GET /api/v1/status/ receives zero requests in the silence window',
     'is_secret': False},
]

REMOVED_KEYS = ['actions.silence_track_get', 'actions.silence_track_post']


def _forwards(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for data in NEW_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)
    Setting.objects.filter(key__in=REMOVED_KEYS).delete()
    # `silence_alert_last_sent` used to hold a single ISO timestamp; the
    # new code stores a per-endpoint JSON map (`{action: iso, ...}`). Blank
    # the value so the new reader doesn't try to parse the old shape.
    last_sent = Setting.objects.filter(key='actions.silence_alert_last_sent').first()
    if last_sent and last_sent.value and not last_sent.value.strip().startswith('{'):
        last_sent.value = ''
        last_sent.save(update_fields=['value'])


def _reverse(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=[s['key'] for s in NEW_SETTINGS]).delete()
    # Restore the previous GET/POST group toggles so a downgrade doesn't
    # leave the settings page missing fields the old code reads.
    for key, desc in [
        ('actions.silence_track_get',
         'Count GET list endpoints (blacklist/hashlist/urllist/status) as traffic'),
        ('actions.silence_track_post',
         'Count POST report endpoints (IP/hash/URL report) as traffic'),
    ]:
        Setting.objects.get_or_create(
            key=key,
            defaults={
                'value': 'true', 'value_type': 'bool', 'category': 'actions',
                'description': desc, 'is_secret': False,
            },
        )


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0026_silence_method_toggles')]
    operations = [migrations.RunPython(_forwards, _reverse)]
