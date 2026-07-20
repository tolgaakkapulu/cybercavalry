"""Per-tab auto-cleanup settings for AbuseIPDB (IP blacklist) and
VirusTotal (hash blacklist).

The cleanup deletes inactive, scored records whose score sits inside a
user-configured band [score_min, score_max] AND that were added more than
`retention_days` ago. Each run logs an ActivityLog entry with the rule
that triggered the deletion and the full list of removed records.
"""
from django.db import migrations


CLEANUP_SETTINGS = [
    # ── AbuseIPDB (IP blacklist) ─────────────────────────────────────────
    ('threat_intel.abuseipdb_cleanup_enabled',         'false', 'bool',
     'Enable automatic cleanup of old inactive AbuseIPDB-scored entries.', False),
    ('threat_intel.abuseipdb_cleanup_score_min',       '0',     'int',
     'Score lower bound (inclusive, 0–100) — only entries with AbuseIPDB score >= this value are eligible.', False),
    ('threat_intel.abuseipdb_cleanup_score_max',       '100',   'int',
     'Score upper bound (inclusive, 0–100) — only entries with AbuseIPDB score <= this value are eligible.', False),
    ('threat_intel.abuseipdb_cleanup_retention_days',  '30',    'int',
     'Delete eligible entries older than this many days (1–3650).', False),

    # ── VirusTotal (hash blacklist) ──────────────────────────────────────
    ('threat_intel.virustotal_cleanup_enabled',        'false', 'bool',
     'Enable automatic cleanup of old inactive VirusTotal-scored entries.', False),
    ('threat_intel.virustotal_cleanup_score_min',      '0',     'int',
     'Score lower bound (inclusive, 0–100) — only entries with VirusTotal malicious engine count >= this value are eligible.', False),
    ('threat_intel.virustotal_cleanup_score_max',      '100',   'int',
     'Score upper bound (inclusive, 0–100) — only entries with VirusTotal malicious engine count <= this value are eligible.', False),
    ('threat_intel.virustotal_cleanup_retention_days', '30',    'int',
     'Delete eligible entries older than this many days (1–3650).', False),
]


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    for key, value, vtype, desc, secret in CLEANUP_SETTINGS:
        Setting.objects.get_or_create(
            key=key,
            defaults={
                'value': value, 'value_type': vtype, 'category': 'threat_intel',
                'description': desc, 'is_secret': secret,
            },
        )


def delete(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    keys = [s[0] for s in CLEANUP_SETTINGS]
    Setting.objects.filter(key__in=keys).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0014_alter_setting_category'),
    ]

    operations = [
        migrations.RunPython(create, delete),
    ]
