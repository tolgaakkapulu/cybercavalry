"""Move the default `general.brand_color` from the legacy purple to red.

Earlier deployments seeded `#682D82` as the platform accent. The new default
is `#ee5356`. This migration touches the row only when its value is still
exactly the legacy default — admins who already picked their own colour are
left alone. Reverse rolls the default back to `#682D82` under the same guard.
"""
from django.db import migrations

OLD_DEFAULT = '#682D82'
NEW_DEFAULT = '#ee5356'


def forward(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key='general.brand_color', value=OLD_DEFAULT).update(value=NEW_DEFAULT)


def backward(apps, schema_editor):
    Setting = apps.get_model('settings_app', 'Setting')
    Setting.objects.filter(key='general.brand_color', value=NEW_DEFAULT).update(value=OLD_DEFAULT)


class Migration(migrations.Migration):
    dependencies = [('settings_app', '0018_brand_color_setting')]
    operations = [migrations.RunPython(forward, backward)]
