from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='HashEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hash_value', models.CharField(db_index=True, max_length=128)),
                ('hash_type', models.CharField(
                    choices=[('md5', 'MD5'), ('sha1', 'SHA1'), ('sha256', 'SHA256'), ('sha512', 'SHA512'), ('unknown', 'Unknown')],
                    default='unknown', max_length=10)),
                ('list_type', models.CharField(
                    choices=[('black', 'Blacklist'), ('white', 'Whitelist')],
                    db_index=True, default='black', max_length=10)),
                ('reason', models.TextField(blank=True)),
                ('source', models.CharField(
                    choices=[('manual', 'Manual'), ('api', 'API'), ('import', 'Import')],
                    default='manual', max_length=10)),
                ('added_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(db_index=True, default=True)),
            ],
            options={
                'ordering': ['-added_at'],
            },
        ),
        migrations.AddIndex(
            model_name='hashentry',
            index=models.Index(fields=['is_active', 'list_type'], name='hashlist_ha_is_acti_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='hashentry',
            unique_together={('hash_value', 'list_type')},
        ),
    ]
