"""Redesign the API Silence Alert to a global-traffic detector.

The previous version tracked each caller (user_id + IP) independently and
alerted when a "regular integration" (>= silence_baseline_min_hits in 24h)
went quiet for `silence_threshold_minutes`. That was noisy — one caller
going silent while all others kept talking still fired an alert, and it
required the operator to reason about per-caller baselines.

New model: the platform is either receiving API traffic or it isn't. Two
new checkbox settings let the operator pick which HTTP verb groups count
as "traffic":

  * actions.silence_track_get  — GET-shaped endpoints (blacklist/hashlist/
                                 urllist/status)
  * actions.silence_track_post — POST-shaped endpoints (report/ variants)

The alarm fires when the union of the tracked groups has zero requests in
the last `silence_threshold_minutes`. The old `silence_baseline_min_hits`
setting no longer applies and is removed here to keep the settings page
clean; nothing in the new code reads it.
"""
from django.db import migrations


NEW_SETTINGS = [
    {'key': 'actions.silence_track_get', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Count GET-shaped API endpoints (blacklist/hashlist/urllist/status) as traffic. '
                    'If neither this nor Track POST is enabled, the silence alert is effectively off.',
     'is_secret': False},
    {'key': 'actions.silence_track_post', 'value': 'true', 'value_type': 'bool',
     'category': 'actions',
     'description': 'Count POST-shaped API endpoints (IP / hash / URL report) as traffic. '
                    'If neither this nor Track GET is enabled, the silence alert is effectively off.',
     'is_secret': False},
]

# Obsolete under the new global-silence design.
REMOVED_KEYS = ['actions.silence_baseline_min_hits']


def _forwards(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    # Add the two new toggles (default: both on → same effective behaviour
    # as "watch all API endpoints", which is the sensible starting point).
    for data in NEW_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)
    # Drop the obsolete baseline setting. Also clear any per-caller last-sent
    # blob because the new cooldown logic stores a single ISO timestamp
    # instead of the old {caller_key: iso} JSON map.
    Setting.objects.filter(key__in=REMOVED_KEYS).delete()
    last_sent = Setting.objects.filter(key='actions.silence_alert_last_sent').first()
    if last_sent and last_sent.value and last_sent.value.strip().startswith('{'):
        # A JSON-shaped value belongs to the old per-caller cooldown map —
        # blank it so the new single-ISO code doesn't misparse it.
        last_sent.value = ''
        last_sent.save(update_fields=['value'])


def _reverse(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=[s['key'] for s in NEW_SETTINGS]).delete()
    # Restore the baseline setting to its original default so a downgrade
    # doesn't leave the settings page missing a field the old code reads.
    Setting.objects.get_or_create(
        key='actions.silence_baseline_min_hits',
        defaults={
            'value': '30', 'value_type': 'int', 'category': 'actions',
            'description': 'Minimum API hits in the past 24h for a caller to be considered a monitored integration',
            'is_secret': False,
        },
    )


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0025_actions_silence_alert')]
    operations = [migrations.RunPython(_forwards, _reverse)]
