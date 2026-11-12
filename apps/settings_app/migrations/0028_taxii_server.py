"""TAXII 2.0 server settings — the second delivery channel for the blacklists.

The firewall keeps pulling `GET /api/v1/urllist/` with source-IP auth and is
untouched by any of this. These settings drive a parallel read-only TAXII 2.0
surface at `/taxii/`.

Only three server-wide knobs live here. Everything that varies per feed —
api root, collection title, collection UUID — is a field on
`taxii.TaxiiCollection`, and credentials are the platform's own API-token
accounts rather than a shared secret stored in a setting.
"""
from django.db import migrations


NEW_SETTINGS = [
    {'key': 'taxii.enabled', 'value': 'false', 'value_type': 'bool',
     'category': 'taxii',
     'description': 'Serve the configured collections over TAXII 2.0 at /taxii/. The '
                    'existing GET /api/v1/urllist/ feed is unaffected either way.',
     'is_secret': False},
    {'key': 'taxii.require_source_ip', 'value': 'true', 'value_type': 'bool',
     'category': 'taxii',
     'description': 'Also require the caller to be in Settings → Source IPs, on top of '
                    'its API token. Turn off only if the subscriber egresses from a '
                    'changing address.',
     'is_secret': False},
    {'key': 'taxii.page_size_default', 'value': '500', 'value_type': 'int',
     'category': 'taxii',
     'description': 'Indicators returned when a client sends no HTTP Range header. '
                    'TAXII 2.0 allows a server to answer with a partial set; this caps '
                    'an unbounded pull.',
     'is_secret': False},
]

#: Superseded by TaxiiCollection fields / API-token auth. Removed so the
#: Settings page does not show knobs that no longer do anything.
REMOVED_KEYS = [
    'taxii.api_root',
    'taxii.collection_title',
    'taxii.collection_id',
    'taxii.basic_auth_user',
    'taxii.basic_auth_password',
]


def _forwards(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for data in NEW_SETTINGS:
        Setting.objects.get_or_create(key=data['key'], defaults=data)
    Setting.objects.filter(key__in=REMOVED_KEYS).delete()


def _reverse(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=[s['key'] for s in NEW_SETTINGS]).delete()


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0027_silence_per_endpoint_toggles')]
    operations = [migrations.RunPython(_forwards, _reverse)]
