# Data migration — replays the new `normalize_url()` on every existing row.
# The new normaliser strips `http://` / `https://` schemes so every URL
# ends up in a single canonical bare form, matching how firewalls / proxies
# filter and how the user wants to see stored entries ("I sent
# `example.com`, that's what I should see"). Consequences we need to handle:
#
# 1. Rows previously stored as `http://x.com`, `https://x.com`, `x.com`
#    now all normalise to `x.com`. If more than one such row exists we
#    have to MERGE them — pick a survivor, delete the rest — because
#    (url_hash, list_type) is unique_together.
# 2. url_hash was previously the VT-canonical hash (bare + `https://` +
#    trailing slash). It's now `SHA-256(stored_url_value)`. Every row's
#    hash gets recomputed.
# 3. hostname column stores the registrable domain (added in 0004), which
#    is derived from url_value; that logic stays valid on the bare form.
#
# Survivor pick order for merged duplicates:
#   1. is_pinned=True beats not-pinned
#   2. higher vt_malicious wins (more evidence)
#   3. is_active=True beats inactive
#   4. earliest added_at wins (preserve history)
#   5. lowest pk wins (deterministic tiebreak)
#
# Non-survivors are hard-deleted; their pk / URL is logged so an operator
# can audit the merge afterwards.

from django.db import migrations


def _survivor_key(entry):
    """Return a tuple sortable so max() picks the "best" row.

    Higher is better on each field. We use negatives / booleans so a plain
    max() over the tuple lines up with the ranking rules above."""
    return (
        1 if entry.is_pinned else 0,
        entry.vt_malicious or 0,
        1 if entry.is_active else 0,
        # added_at ascending -> negate epoch so earlier > later
        -(entry.added_at.timestamp() if entry.added_at else 0),
        -entry.pk,
    )


def _forwards(apps, schema_editor):
    URLEntry = apps.get_model('urllist', 'URLEntry')
    from apps.urllist.models import normalize_url, url_sha256, registrable_domain

    # First pass — bucket every row by (new_url_value, list_type) so we can
    # see duplicates ahead of time. This costs one full table read but keeps
    # the write phase simple and correct (no order-dependent races).
    buckets = {}   # key: (new_url_value, list_type) -> list[entry]
    unchanged = 0
    invalid = 0
    for entry in URLEntry.objects.all().iterator(chunk_size=2000):
        try:
            new_value = normalize_url(entry.url_value or '')
        except Exception:
            # Malformed row — leave it alone rather than delete or crash.
            invalid += 1
            continue
        if new_value == entry.url_value and entry.url_hash == url_sha256(new_value):
            unchanged += 1
            continue
        buckets.setdefault((new_value, entry.list_type), []).append(entry)

    to_delete_pks = []
    updates = []
    merges = 0

    for (new_value, list_type), rows in buckets.items():
        # If more than one row lands on the same (new_value, list_type)
        # pair, pick a survivor and mark the others for deletion.
        if len(rows) > 1:
            # Also probe for a THIRD kind of collision: a row we already
            # skipped (`unchanged`) may sit at this url_value too. Fold it
            # into the bucket so it can compete for survivorship.
            existing = list(
                URLEntry.objects
                .filter(url_value=new_value, list_type=list_type)
                .exclude(pk__in=[r.pk for r in rows])
            )
            candidates = rows + existing
            survivor = max(candidates, key=_survivor_key)
            for r in candidates:
                if r.pk != survivor.pk:
                    to_delete_pks.append(r.pk)
            # Survivor still needs its hash / value / hostname updated to the
            # new form (unless it was one of the "existing" pre-normalised
            # rows, in which case its fields are already correct).
            if survivor in rows:
                _stage_update(survivor, new_value, url_sha256, registrable_domain, updates)
            merges += 1
        else:
            _stage_update(rows[0], new_value, url_sha256, registrable_domain, updates)

    # Delete losers first — frees up (url_value, list_type) so the survivor
    # updates can't accidentally trip a unique_together constraint mid-run.
    if to_delete_pks:
        URLEntry.objects.filter(pk__in=to_delete_pks).delete()

    # Bulk-apply the survivor updates in reasonably sized batches. Update
    # all three columns together so a partial run can't leave the DB in
    # a mixed state (hash from new logic, value from old).
    if updates:
        for i in range(0, len(updates), 1000):
            URLEntry.objects.bulk_update(
                updates[i:i + 1000],
                ['url_value', 'url_hash', 'hostname'],
            )

    # Print a summary so the operator can reconcile against expectations.
    print(
        f'urllist 0005: unchanged={unchanged}, updated={len(updates)}, '
        f'merged={merges}, deleted={len(to_delete_pks)}, invalid={invalid}'
    )


def _stage_update(entry, new_value, url_sha256, registrable_domain, updates):
    """Stage a survivor row for bulk_update with new url_value/hash/hostname."""
    entry.url_value = new_value
    entry.url_hash = url_sha256(new_value)
    # Re-derive hostname from the new (schemeless) form so a URL entry that
    # used to store `http://sub.example.com/path` still lands on `example.com`.
    fqdn, _slash, _rest = new_value.partition('/')
    # Strip a `:port` suffix if present so registrable_domain sees a plain host.
    if ':' in fqdn and not fqdn.startswith('['):
        fqdn = fqdn.rsplit(':', 1)[0]
    entry.hostname = registrable_domain(fqdn)[:253]
    updates.append(entry)


def _backwards(apps, schema_editor):
    # Can't restore the pre-strip scheme (`http://x` vs `x`) from bare form,
    # nor bring back merged duplicates. Reverse is a safe no-op.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('urllist', '0004_backfill_hostname_to_registrable_domain'),
    ]

    operations = [
        migrations.RunPython(_forwards, _backwards, atomic=False),
    ]
