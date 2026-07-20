"""Adds the `general.brand_color` accent-colour setting.

Default `#ee5356`. Once an admin updates it from Settings → General, the
chosen hex is injected as `--brand-suffix` (and its translucent glow
recomputed in the context processor) so the new accent ripples through the
sidebar, topbar, active nav highlight, login card and PDF cover without
further edits.
"""
from django.db import migrations


def create(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.get_or_create(
        key='general.brand_color',
        defaults={
            'value':       '#ee5356',
            'value_type':  'str',
            'category':    'general',
            'description': 'Accent colour applied across the UI (hex #RRGGBB)',
            'is_secret':   False,
        },
    )


def delete(apps, schema_editor):
    apps.get_model('settings_app', 'Setting').objects.filter(
        key='general.brand_color'
    ).delete()


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0017_brand_login_setting')]
    operations = [migrations.RunPython(create, delete)]
