# Schema migration — adds `vt_not_found` and backfills existing rows that
# look like they landed via a VT 404 (the pre-fix code stored 0/0 with all
# enrichment fields blank, which is indistinguishable from "not indexed"
# in the UI). Heuristic explained inline.
#
# Non-matching rows keep vt_not_found=False (the field default), so a
# legitimate `malicious=0 out of N > 0 engines` result is left alone.

from django.db import migrations, models


def _backfill(apps, schema_editor):
    URLEntry = apps.get_model('urllist', 'URLEntry')
    # Heuristic for "this row is here because VT returned 404":
    #   - vt_checked_at IS NOT NULL (we did query VT)
    #   - vt_malicious in (0, NULL) AND vt_total in (0, NULL)
    #     (no real score landed)
    #   - vt_last_analysis IS NULL AND vt_first_seen IS NULL
    #     (200-with-empty-data would have populated at least one of these)
    #   - no enrichment text present (a genuine 0/N would usually populate
    #     categories or a threat label)
    # This deliberately errs on the side of tagging false-positives as
    # not_found because the alternative (leaving them as misleading 0/0
    # in the UI) is what motivated this migration in the first place.
    from django.db.models import Q

    matches = URLEntry.objects.filter(
        vt_checked_at__isnull=False,
        vt_last_analysis__isnull=True,
        vt_first_seen__isnull=True,
        vt_threat_label='',
        vt_categories='',
        vt_final_url='',
        vt_title='',
    ).filter(
        Q(vt_malicious__isnull=True) | Q(vt_malicious=0),
    ).filter(
        Q(vt_total__isnull=True) | Q(vt_total=0),
    )

    # Two-phase: flag the rows and clear their 0/0 score so the UI doesn't
    # keep showing the misleading number. Also deactivate non-pinned ones
    # to match the new runtime behaviour (`_mark_not_found`).
    updated = matches.update(
        vt_not_found=True,
        vt_malicious=None,
        vt_total=None,
    )
    deactivated = URLEntry.objects.filter(
        vt_not_found=True, is_pinned=False, is_active=True,
    ).update(is_active=False)

    print(
        f'urllist 0006: tagged {updated} entries as vt_not_found=True '
        f'(cleared 0/0 score); deactivated {deactivated} non-pinned rows.'
    )


def _reverse(apps, schema_editor):
    # The field itself is removed by RemoveField; there's nothing else to
    # undo (we deliberately blanked the misleading 0/0 scores and won't
    # restore them — they were wrong data).
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('urllist', '0005_recompute_url_hash_from_stored_form'),
    ]

    operations = [
        migrations.AddField(
            model_name='urlentry',
            name='vt_not_found',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text=(
                    "True when VirusTotal responded 404 for this URL/domain — the URL "
                    "is not indexed by VT at all (never scanned, never submitted). "
                    "Distinct from vt_unavailable (transient reachability failure) and "
                    "from a legitimate 0/N score (VT scanned it and found nothing). "
                    "Entries with this flag show a 'Not in VT' badge instead of the "
                    "misleading 0/0 score and are deactivated (excluded from the "
                    "downstream feed) until VT eventually indexes and scores them."
                ),
            ),
        ),
        migrations.RunPython(_backfill, _reverse),
    ]
