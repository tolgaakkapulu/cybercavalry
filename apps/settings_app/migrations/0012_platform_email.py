from django.db import migrations


def add_platform_email(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.get_or_create(
        key='general.platform_email',
        defaults={
            'value': '',
            'value_type': 'str',
            'category': 'general',
            'description': 'Contact email shown in the sidebar footer and all PDF reports.',
            'is_secret': False,
        },
    )


def remove_platform_email(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key='general.platform_email').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0011_password_policy_category'),
    ]

    operations = [
        migrations.RunPython(add_platform_email, remove_platform_email),
    ]
