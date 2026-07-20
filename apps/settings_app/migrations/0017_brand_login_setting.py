"""Adds the optional `general.brand_login` image slot.

Shown above the email row on the login screen at 150×50. Default is empty
so fresh installs render the existing login card unchanged; the row only
appears once an admin uploads an image from Settings → General.
"""
from django.db import migrations


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.get_or_create(
        key='general.brand_login',
        defaults={
            'value':       '',
            'value_type':  'str',
            'category':    'general',
            'description': 'Login screen logo (relative media path)',
            'is_secret':   False,
        },
    )


def delete(apps, schema_editor):
    apps.get_model('settings_app', 'Setting').objects.filter(
        key='general.brand_login'
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0016_blacklist_refresh_setting')]
    operations = [migrations.RunPython(create, delete)]
