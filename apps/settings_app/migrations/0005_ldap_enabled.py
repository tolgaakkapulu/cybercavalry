from django.db import migrations


def add_ldap_enabled(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.get_or_create(
        key='ldap.enabled',
        defaults={
            'value': 'false',
            'value_type': 'bool',
            'category': 'ldap',
            'is_secret': False,
        }
    )


def remove_ldap_enabled(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key='ldap.enabled').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0004_abuseipdb_score_thresholds'),
    ]

    operations = [
        migrations.RunPython(add_ldap_enabled, remove_ldap_enabled),
    ]
