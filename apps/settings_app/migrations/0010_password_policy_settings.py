from django.db import migrations


PASSWORD_POLICY_SETTINGS = [
    ('security.password_min_length',        '8',    'int',  'Minimum number of characters required in a password.',         False),
    ('security.password_require_uppercase', 'true', 'bool', 'Require at least one uppercase letter (A–Z).',                 False),
    ('security.password_require_lowercase', 'true', 'bool', 'Require at least one lowercase letter (a–z).',                 False),
    ('security.password_require_digits',    'true', 'bool', 'Require at least one digit (0–9).',                            False),
    ('security.password_require_symbols',   'true', 'bool', 'Require at least one symbol (e.g. !@#$%^&*).',                 False),
]


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0009_virustotal_settings'),
    ]

    operations = [
        migrations.RunPython(
            lambda apps, schema_editor: [
                apps.get_model('settings_app', 'Setting').objects.get_or_create(
                    key=key,
                    defaults={
                        'value':      value,
                        'value_type': vtype,
                        'category':   'security',
                        'description': desc,
                        'is_secret':  secret,
                    },
                )
                for key, value, vtype, desc, secret in PASSWORD_POLICY_SETTINGS
            ],
            migrations.RunPython.noop,
        ),
    ]
