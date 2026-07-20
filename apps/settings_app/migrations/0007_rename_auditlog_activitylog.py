from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('settings_app', '0006_schedule_settings'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='AuditLog',
            new_name='ActivityLog',
        ),
    ]
