from django.db import migrations


def remove_permanent_group(apps, schema_editor):
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    BlacklistEntry = apps.get_model('blacklist', 'BlacklistEntry')

    try:
        permanent = BlacklistGroup.objects.get(name='permanent')
    except BlacklistGroup.DoesNotExist:
        return  # already gone

    # Migrate entries to 30d if it exists, otherwise 24h
    target = (
        BlacklistGroup.objects.filter(name='30d').first() or
        BlacklistGroup.objects.filter(name='24h').first()
    )
    if target:
        BlacklistEntry.objects.filter(group=permanent).update(group=target)

    permanent.delete()


def restore_permanent_group(apps, schema_editor):
    BlacklistGroup = apps.get_model('blacklist', 'BlacklistGroup')
    BlacklistGroup.objects.get_or_create(
        name='permanent',
        defaults={
            'label': 'Permanent',
            'default_duration_hours': None,
            'is_published': True,
            'order': 3,
        }
    )


class Migration(migrations.Migration):

    dependencies = [
        ('blacklist', '0003_no_group'),
    ]

    operations = [
        migrations.RunPython(remove_permanent_group, restore_permanent_group),
    ]
