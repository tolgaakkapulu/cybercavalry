from django.db import migrations

PASSWORD_POLICY_KEYS = [
    'security.password_min_length',
    'security.password_require_uppercase',
    'security.password_require_lowercase',
    'security.password_require_digits',
    'security.password_require_symbols',
]


def move_to_password_policy(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=PASSWORD_POLICY_KEYS).update(category='password_policy')


def move_back_to_security(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key__in=PASSWORD_POLICY_KEYS).update(category='security')


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0010_password_policy_settings'),
    ]

    operations = [
        migrations.RunPython(move_to_password_policy, move_back_to_security),
    ]
