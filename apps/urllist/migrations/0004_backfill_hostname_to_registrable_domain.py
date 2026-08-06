# Data migration — rewrites URLEntry.hostname from the full FQDN it used to
# hold to the registrable domain (eTLD+1). Prior versions of URLEntry.save()
# stored the whole hostname; the new logic derives via `registrable_domain()`
# so an analyst filtering by hostname sees phishing operations grouped under
# their registered domain instead of scattered across every subdomain.
#
# Idempotent: re-running is safe because `registrable_domain(x)` is stable
# for any x it already produced (e.g. registrable_domain('qrbyw.xyz') is
# still 'qrbyw.xyz'). Also no-op for entries whose hostname is empty or
# whose registrable-domain equals what's already stored.

from django.db import migrations


def _forwards(apps, schema_editor):
    URLEntry = apps.get_model('urllist', 'URLEntry')
    # Import the helper lazily so an in-flight schema migration doesn't crash
    # if tldextract happens to be temporarily unavailable — the helper's own
    # try/except returns the input unchanged in that case, meaning this
    # migration becomes a safe no-op instead of raising.
    from apps.urllist.models import registrable_domain

    updates = []
    # Fetch only what we need; iterator() keeps the memory footprint flat
    # even on databases with millions of URL rows.
    for entry in URLEntry.objects.only('pk', 'hostname').iterator(chunk_size=2000):
        old = entry.hostname or ''
        new = registrable_domain(old)[:253]
        if new and new != old:
            entry.hostname = new
            updates.append(entry)
            # Batch the bulk_update() so we don't hold millions of unsaved
            # instances in memory. 1000 rows per batch is a good middle
            # ground between round-trip cost and heap pressure.
            if len(updates) >= 1000:
                URLEntry.objects.bulk_update(updates, ['hostname'])
                updates.clear()

    if updates:
        URLEntry.objects.bulk_update(updates, ['hostname'])


def _backwards(apps, schema_editor):
    # We CAN'T reconstruct the original FQDN from the registrable domain --
    # `login.qrbyw.xyz` → `qrbyw.xyz` is lossy. Rolling back this migration
    # would require re-parsing url_value on every row; keep the field as-is
    # so the reverse is a safe no-op and the columns stay populated.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('urllist', '0003_urlentry_vt_enrichment_expansion'),
    ]

    operations = [
        migrations.RunPython(_forwards, _backwards, atomic=False),
    ]
