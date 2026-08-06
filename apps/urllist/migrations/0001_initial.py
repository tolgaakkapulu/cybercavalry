"""Initial URLEntry model — mirrors HashEntry structure with URL-specific
fields (url_value + url_hash + hostname) and VT enrichment columns tuned
to what VirusTotal returns for URL scans (categories, final URL, title)
instead of the file-oriented columns HashEntry has (size, filename, etc.).
"""
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='URLEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url_value', models.TextField()),
                ('url_hash',  models.CharField(db_index=True, max_length=64)),
                ('hostname',  models.CharField(blank=True, db_index=True, default='', max_length=253)),
                ('list_type', models.CharField(
                    choices=[('black', 'Blacklist'), ('white', 'Whitelist')],
                    db_index=True, default='black', max_length=10)),
                ('reason', models.TextField(blank=True)),
                ('source', models.CharField(
                    choices=[('manual', 'Manual'), ('api', 'API'), ('import', 'Import')],
                    default='manual', max_length=10)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(db_index=True, default=True)),
                ('is_pinned', models.BooleanField(
                    default=False,
                    help_text='Pinned entries are exempt from automatic score-based deactivation')),
                ('vt_malicious', models.IntegerField(
                    blank=True, null=True,
                    help_text='Number of engines detecting as malicious')),
                ('vt_total', models.IntegerField(
                    blank=True, null=True,
                    help_text='Total number of engines scanned')),
                ('vt_checked_at', models.DateTimeField(
                    blank=True, null=True, help_text='Last VirusTotal query time')),
                ('vt_unavailable', models.BooleanField(
                    db_index=True, default=False,
                    help_text=(
                        'True when VirusTotal was queried but did not return a result '
                        '(timeout, quota exhausted, network error). Such entries stay '
                        'is_active=True for admin visibility but are excluded from the '
                        'downstream /api/v1/urllist/ feed until a valid score arrives.'
                    ))),
                ('vt_threat_label', models.CharField(blank=True, default='', max_length=255)),
                ('vt_categories', models.CharField(
                    blank=True, default='', max_length=255,
                    help_text='Comma-joined categories reported by VT engines (e.g. phishing, malware)')),
                ('vt_final_url', models.TextField(
                    blank=True, default='',
                    help_text='Final URL after redirects, as observed by VT')),
                ('vt_title', models.CharField(
                    blank=True, default='', max_length=255,
                    help_text='HTML <title> observed by VT during its last scan')),
                ('vt_first_seen',      models.DateTimeField(blank=True, null=True)),
                ('vt_last_analysis',   models.DateTimeField(blank=True, null=True)),
                ('vt_times_submitted', models.IntegerField(blank=True, null=True)),
                ('added_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=models.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-added_at'],
                'unique_together': {('url_hash', 'list_type')},
                'indexes': [
                    models.Index(fields=['is_active', 'list_type'],
                                 name='urllist_ur_is_acti_idx'),
                ],
            },
        ),
    ]
