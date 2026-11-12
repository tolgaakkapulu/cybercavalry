"""Seed the default URL Blacklist collection.

Carries over whatever the earlier flat-settings build had configured, so a
subscriber that already completed Discover keeps working:

  * `taxii.collection_id`    → the collection's UUID, preserved verbatim.
    This is the important one — Deep Discovery Director stores the id it
    discovered and re-polls that exact value. Minting a fresh UUID here
    would silently orphan an existing feed.
  * `taxii.api_root`         → the collection's api_root (default `default`).
  * `taxii.collection_title` → the collection's title.

On a fresh install none of those settings exist and the collection is
created from defaults instead. Either way the operator ends up with one
working collection and never has to type a UUID.
"""
import uuid

from django.db import migrations


def _setting(Setting, key, fallback=''):
    row = Setting.objects.filter(key=key).first()
    if row and (row.value or '').strip():
        return row.value.strip()
    return fallback


def _forwards(apps, schema_editor):
    TaxiiCollection = apps.get_model('taxii', 'TaxiiCollection')
    Setting = apps.get_model('settings_app', 'Setting')

    if TaxiiCollection.objects.exists():
        return  # already seeded or hand-created

    api_root = _setting(Setting, 'taxii.api_root', 'default') or 'default'
    title = _setting(Setting, 'taxii.collection_title', 'Malicious URLs & Domains')

    existing_uuid = _setting(Setting, 'taxii.collection_id')
    try:
        coll_uuid = uuid.UUID(existing_uuid) if existing_uuid else uuid.uuid4()
    except (ValueError, AttributeError, TypeError):
        # Malformed stored value — a new UUID is better than a crash, and a
        # fresh install has nothing to preserve anyway.
        coll_uuid = uuid.uuid4()

    TaxiiCollection.objects.create(
        collection_id=coll_uuid,
        api_root=api_root,
        title=title,
        description='Active malicious URLs, domains and subdomains from the URL '
                    'Blacklist, published as STIX 2.0 indicators.',
        feed='url',
        is_active=True,
    )
    print(f'taxii 0002: seeded collection {coll_uuid} under api root {api_root!r}')


def _reverse(apps, schema_editor):
    apps.get_model('taxii', 'TaxiiCollection').objects.filter(feed='url').delete()


class Migration(migrations.Migration):
    dependencies = [
        ('taxii', '0001_initial'),
        ('settings_app', '0027_silence_per_endpoint_toggles'),
    ]
    # MUST land before settings_app 0028, which deletes the very
    # `taxii.collection_id` row this migration reads to preserve the UUID a
    # subscriber has already discovered. Without this the two are unordered
    # and a fresh UUID could be minted, silently orphaning the feed.
    run_before = [('settings_app', '0028_taxii_server')]
    operations = [migrations.RunPython(_forwards, _reverse)]
