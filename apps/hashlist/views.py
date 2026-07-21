import csv
import logging
from datetime import timedelta, datetime as _dt
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse, JsonResponse
from django.db.models import Q, F
from django.urls import reverse
from django.utils import timezone

from .models import HashEntry, is_valid_hash, normalize_hash
from apps.accounts.decorators import login_required_custom, role_required
from apps.settings_app.models import ActivityLog

logger = logging.getLogger(__name__)

_VALID_STATUSES = {'active', 'inactive', 'all'}


def _hl_redirect(status='active'):
    url = reverse('hashlist:list')
    safe_status = status if status in _VALID_STATUSES else 'active'
    if safe_status != 'active':
        url += '?status={}'.format(safe_status)
    return redirect(url)


def _auto_vt_check(entry, user=None):
    """Query VirusTotal for an entry if auto-check is enabled. Fire-and-forget, never raises."""
    try:
        from apps.settings_app.cache import SettingsCache
        if (SettingsCache.get('threat_intel.virustotal_enabled', False) and
                SettingsCache.get('threat_intel.virustotal_auto_check', False)):
            from apps.hashlist.virustotal_service import update_entry_score
            result = update_entry_score(entry)
            if result is not None:
                malicious, total = result
                entry.refresh_from_db(fields=['is_active'])
                ActivityLog.log(
                    user, 'threat_intel.vt_auto_check', 'HashEntry', str(entry.pk),
                    {
                        'hash': entry.hash_value[:16] + '...',
                        'hash_type': entry.hash_type,
                        'malicious': malicious,
                        'total': total,
                        'deactivated': not entry.is_active and malicious == 0,
                        'trigger': 'auto',
                    },
                )
    except Exception:
        pass


def _vt_threshold():
    """Return the configured VT detection threshold (int)."""
    try:
        from apps.settings_app.cache import SettingsCache
        return int(SettingsCache.get('threat_intel.virustotal_detection_threshold', 5) or 5)
    except Exception:
        return 5


# ── List ──────────────────────────────────────────────────────────────────────

@login_required_custom
def hashlist_list(request):
    base_qs = HashEntry.objects.select_related('added_by').filter(list_type='black')
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status', 'active')
    pinned = request.GET.get('pinned', '')            # '' | 'yes' | 'no'

    if search:
        # Pure-digit query also matches the row's primary key.
        q = Q(hash_value__icontains=search) | Q(reason__icontains=search)
        if search.isdigit():
            q |= Q(pk=int(search))
        base_qs = base_qs.filter(q)
    if pinned == 'yes':
        base_qs = base_qs.filter(is_pinned=True)
    elif pinned == 'no':
        base_qs = base_qs.filter(is_pinned=False)

    count_active   = base_qs.filter(is_active=True).count()
    count_inactive = base_qs.filter(is_active=False).count()
    count_all      = count_active + count_inactive

    entries = base_qs
    if status == 'active':
        entries = entries.filter(is_active=True)
    elif status == 'inactive':
        entries = entries.filter(is_active=False)

    _HL_SORT = {
        'hash': 'hash_value', 'type': 'hash_type', 'source': 'source',
        'score': 'vt_malicious', 'checked': 'vt_checked_at',
        'added_by': 'added_by__username', 'added': 'added_at',
    }
    _HL_NULL = {'vt_malicious', 'vt_checked_at', 'added_by__username'}
    sort = request.GET.get('sort', 'added')
    sort_dir = request.GET.get('dir', 'desc')
    sort_field = _HL_SORT.get(sort, 'added_at')
    if sort_field in _HL_NULL:
        order = F(sort_field).asc(nulls_last=True) if sort_dir == 'asc' else F(sort_field).desc(nulls_last=True)
    else:
        order = sort_field if sort_dir == 'asc' else f'-{sort_field}'
    entries = entries.order_by(order)

    qd = request.GET.copy()
    qd.pop('sort', None); qd.pop('dir', None); qd.pop('page', None)
    sort_qs = qd.urlencode()

    from apps.settings_app.pagination import get_page_size, PAGE_SIZE_OPTIONS
    page_size = get_page_size(request)
    paginator = Paginator(entries, page_size)
    page = request.GET.get('page', 1)
    entries_page = paginator.get_page(page)

    from apps.settings_app.cache import SettingsCache
    try:
        refresh_seconds = max(1, min(3600, int(SettingsCache.get('general.blacklist_refresh_seconds', 5))))
    except (TypeError, ValueError):
        refresh_seconds = 5
    ctx = {
        'entries':           entries_page,
        'search':            search,
        'status':            status,
        'pinned':            pinned,
        'count_active':      count_active,
        'count_inactive':    count_inactive,
        'count_all':         count_all,
        'vt_threshold':      _vt_threshold(),
        'sort':              sort,
        'dir':               sort_dir,
        'sort_qs':           sort_qs,
        'page_size':         page_size,
        'page_size_options': PAGE_SIZE_OPTIONS,
        'refresh_seconds':   refresh_seconds,
    }
    # `?ajax=1` returns just the <tbody> contents — used by the in-page
    # auto-refresh poller so the table streams updates without a full
    # browser reload. Active/Inactive/All tab counts ride along as
    # response headers for the JS to splice into the badges.
    if request.GET.get('ajax') == '1':
        resp = render(request, 'hashlist/_list_rows.html', ctx)
        resp['X-Count-Active']   = str(count_active)
        resp['X-Count-Inactive'] = str(count_inactive)
        resp['X-Count-All']      = str(count_all)
        return resp
    return render(request, 'hashlist/list.html', ctx)


# ── Create ────────────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_create(request):
    if request.method == 'POST':
        raw    = request.POST.get('hash_input', '').strip()
        reason = request.POST.get('reason', '').strip()
        if not is_valid_hash(raw):
            messages.error(request, 'Invalid hash: expected MD5 (32), SHA1 (40), SHA256 (64), or SHA512 (128) hex characters.')
        else:
            hv, ht = normalize_hash(raw)
            if HashEntry.objects.filter(hash_value=hv, list_type='black').exists():
                messages.warning(request, 'This hash already exists in the list.')
            else:
                entry = HashEntry.objects.create(
                    hash_value=hv, hash_type=ht, list_type='black',
                    reason=reason, added_by=request.user,
                )
                ActivityLog.log(request.user, 'hashlist.add', 'HashEntry', str(entry.pk),
                             {'hash': hv, 'hash_type': ht, 'reason': reason or ''},
                             getattr(request, 'client_ip', ''))
                _auto_vt_check(entry, user=request.user)
                messages.success(request, 'Hash added.')
    return _hl_redirect()


# ── Bulk Create ───────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_bulk_create(request):
    if request.method == 'POST':
        raw   = request.POST.get('hash_list', '')
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        if not lines:
            messages.warning(request, 'Hash list is empty.')
            return _hl_redirect()
        reason = request.POST.get('reason', '').strip()
        added = skipped = errors = 0
        new_entries = []
        for line in lines[:500]:
            if not is_valid_hash(line):
                errors += 1
                continue
            try:
                hv, ht = normalize_hash(line)
            except ValueError:
                errors += 1
                continue
            if HashEntry.objects.filter(hash_value=hv, list_type='black').exists():
                skipped += 1
            else:
                entry = HashEntry.objects.create(
                    hash_value=hv, hash_type=ht, list_type='black',
                    reason=reason, added_by=request.user,
                )
                new_entries.append(entry)
                added += 1
        ActivityLog.log(request.user, 'hashlist.bulk_add', 'HashEntry', None,
                     {
                         'added': added, 'skipped': skipped, 'errors': errors,
                         'reason': reason or '',
                         'hashes': [e.hash_value[:16] + '...' for e in new_entries[:20]],
                     },
                     getattr(request, 'client_ip', ''))
        msg = '{} added, {} duplicate(s) skipped'.format(added, skipped)
        if errors:
            msg += ', {} invalid'.format(errors)
        messages.success(request, 'Bulk add: ' + msg + '.')
        for entry in new_entries:
            _auto_vt_check(entry, user=request.user)
    return _hl_redirect()


# ── Import CSV ────────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_import_csv(request):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _err(msg, status=400):
        if is_ajax:
            return JsonResponse({'ok': False, 'message': msg}, status=status)
        messages.error(request, msg)
        return _hl_redirect()

    if request.method == 'POST':
        csv_file = request.FILES.get('csv_file')
        if not csv_file or not csv_file.name.endswith('.csv'):
            return _err('Please upload a valid .csv file.')
        try:
            decoded = csv_file.read().decode('utf-8-sig').splitlines()
        except UnicodeDecodeError:
            return _err('File encoding not supported. Please use UTF-8.')
        lines = [l for l in decoded if l.strip()]
        if not lines:
            return _err('The CSV file is empty.')

        HASH_COLS   = ['hash', 'hash_value', 'md5', 'sha1', 'sha256', 'sha512', 'value']
        REASON_COLS = ['reason', 'description', 'note', 'comment']
        first_field = lines[0].split(',')[0].strip()
        first_is_hash = is_valid_hash(first_field)
        added = skipped = errors = 0
        new_entries = []

        def _process(raw, rsn):
            nonlocal added, skipped, errors
            if not raw or not is_valid_hash(raw):
                errors += 1
                return
            try:
                hv, ht = normalize_hash(raw)
            except ValueError:
                errors += 1
                return
            if HashEntry.objects.filter(hash_value=hv, list_type='black').exists():
                skipped += 1
            else:
                entry = HashEntry.objects.create(
                    hash_value=hv, hash_type=ht, list_type='black',
                    reason=rsn, added_by=request.user, source=HashEntry.SOURCE_IMPORT,
                )
                new_entries.append(entry)
                added += 1

        if first_is_hash:
            for line in lines:
                parts = [p.strip() for p in line.split(',')]
                _process(parts[0] if parts else '', parts[1] if len(parts) > 1 else '')
        else:
            reader = csv.DictReader(lines)
            fl = {c.strip().lower(): c for c in (reader.fieldnames or [])}

            def pick(row, candidates):
                for c in candidates:
                    val = row.get(fl.get(c, ''), '')
                    if isinstance(val, str) and val.strip():
                        return val.strip()
                return ''

            for row in reader:
                raw_h = pick(row, HASH_COLS)
                if not raw_h:
                    raw_h = next((v.strip() for v in row.values() if isinstance(v, str) and v.strip()), '')
                _process(raw_h, pick(row, REASON_COLS))

        ActivityLog.log(request.user, 'hashlist.import_csv', 'HashEntry', None,
                     {
                         'added': added, 'skipped': skipped, 'errors': errors,
                         'filename': csv_file.name,
                         'hashes': [e.hash_value[:16] + '...' for e in new_entries[:20]],
                     },
                     getattr(request, 'client_ip', ''))
        for entry in new_entries:
            _auto_vt_check(entry, user=request.user)

        if is_ajax:
            return JsonResponse({
                'ok': True,
                'added': added,
                'skipped': skipped,
                'errors': errors,
            })
        messages.success(request, 'CSV import: {} added, {} duplicate(s) skipped, {} invalid.'.format(added, skipped, errors))
    return _hl_redirect()


# ── Export CSV ────────────────────────────────────────────────────────────────

@login_required_custom
def hashlist_export(request):
    entries = HashEntry.objects.filter(list_type='black').order_by('hash_type', 'hash_value')
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status', 'active')
    if search:
        q = Q(hash_value__icontains=search) | Q(reason__icontains=search)
        if search.isdigit():
            q |= Q(pk=int(search))
        entries = entries.filter(q)
    if status == 'active':
        entries = entries.filter(is_active=True)
    elif status == 'inactive':
        entries = entries.filter(is_active=False)
    status_label = status if status in ('active', 'inactive', 'all') else 'active'
    ts = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
    response = HttpResponse(content_type='text/csv')
    from apps.settings_app.branding import brand_filename_prefix
    response['Content-Disposition'] = f'attachment; filename="{brand_filename_prefix()}_hashlist_{status_label}_{ts}.csv"'
    from apps.settings_app.csv_util import safe_row
    writer = csv.writer(response)
    writer.writerow(['Hash Value', 'Hash Type', 'Reason', 'Source', 'Added By', 'Added At', 'VT Malicious', 'VT Total', 'VT Checked At'])
    for e in entries:
        writer.writerow(safe_row([
            e.hash_value, e.hash_type, e.reason, e.source,
            e.added_by.username if e.added_by else '',
            timezone.localtime(e.added_at).strftime('%Y-%m-%d %H:%M:%S'),
            e.vt_malicious if e.vt_malicious is not None else '',
            e.vt_total if e.vt_total is not None else '',
            timezone.localtime(e.vt_checked_at).strftime('%Y-%m-%d %H:%M:%S') if e.vt_checked_at else '',
        ]))
    return response


# ── VT Score — Single ─────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_score_single(request, entry_id):
    """Query VirusTotal for a single hash entry — always returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)

    entry = get_object_or_404(HashEntry, pk=entry_id, list_type='black')

    from apps.settings_app.cache import SettingsCache
    if not SettingsCache.get('threat_intel.virustotal_enabled', False):
        return JsonResponse({'success': False, 'message': 'VirusTotal is disabled. Enable it in Settings → Threat Intelligence.'})

    was_active = entry.is_active

    from apps.hashlist.virustotal_service import update_entry_score
    result = update_entry_score(entry)
    if result is not None:
        entry.refresh_from_db()
        malicious, total = result
        threshold = _vt_threshold()
        deactivated = was_active and not entry.is_active
        ActivityLog.log(
            request.user, 'threat_intel.vt_score_single', 'HashEntry', str(entry.pk),
            {'hash': entry.hash_value[:16], 'malicious': malicious, 'total': total,
             'deactivated': deactivated},
            getattr(request, 'client_ip', ''),
        )
        vt_checked_display = (
            timezone.localtime(entry.vt_checked_at).strftime('%Y-%m-%d %H:%M')
            if entry.vt_checked_at else ''
        )
        return JsonResponse({
            'success': True,
            'malicious': malicious,
            'total': total,
            'threshold': threshold,
            'is_active': entry.is_active,
            'deactivated': deactivated,
            'vt_checked_at': vt_checked_display,
            'message': '{} — {}/{} engines detected as malicious'.format(
                entry.hash_value[:16] + '...', malicious, total),
        })
    return JsonResponse({'success': False, 'message': 'VirusTotal query failed. Check API key and settings.'})


# ── VT Score — Bulk ───────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_bulk_score(request):
    """Query VirusTotal for multiple selected hash entries — always returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)

    ids = request.POST.getlist('entry_ids')
    if not ids:
        return JsonResponse({'success': False, 'message': 'No entries selected.'})

    from apps.settings_app.cache import SettingsCache
    if not SettingsCache.get('threat_intel.virustotal_enabled', False):
        return JsonResponse({'success': False, 'message': 'VirusTotal is disabled. Enable it in Settings → Threat Intelligence.'})

    from apps.hashlist.virustotal_service import update_entry_score
    entries = HashEntry.objects.filter(pk__in=ids, list_type='black')
    scored = failed = 0
    scores = []
    for entry in entries:
        was_active = entry.is_active
        result = update_entry_score(entry)
        if result is not None:
            malicious, total = result
            scored += 1
            entry.refresh_from_db(fields=['vt_checked_at', 'is_active'])
            checked_display = (
                timezone.localtime(entry.vt_checked_at).strftime('%Y-%m-%d %H:%M')
                if entry.vt_checked_at else ''
            )
            deactivated = was_active and not entry.is_active
            scores.append({'id': entry.pk, 'malicious': malicious, 'total': total,
                           'vt_checked_at': checked_display, 'deactivated': deactivated})
        else:
            failed += 1

    deactivated_count = sum(1 for s in scores if s.get('deactivated'))
    ActivityLog.log(
        request.user, 'threat_intel.vt_bulk_score', 'HashEntry', None,
        {
            'scored': scored,
            'failed': failed,
            'deactivated': deactivated_count,
            'trigger': 'manual',
            'hashes': ['{}/{}:{}'.format(s['malicious'], s['total'], str(s['id'])) for s in scores[:20]],
        },
        getattr(request, 'client_ip', ''),
    )
    msg = "{} entr{} scored.".format(scored, 'y' if scored == 1 else 'ies')
    if failed:
        msg += " {} failed (check API key).".format(failed)
    return JsonResponse({'success': scored > 0 or failed == 0, 'scored': scored, 'failed': failed, 'message': msg, 'scores': scores})


# ── Bulk Delete ───────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_bulk_delete(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, 'No entries selected.')
            return _hl_redirect(status)
        qs = HashEntry.objects.filter(pk__in=ids, list_type='black')
        active_count = qs.filter(is_active=True).count()
        if active_count:
            messages.error(request, '{} active entry(s) cannot be deleted. Deactivate them first.'.format(active_count))
            return _hl_redirect(status)
        hashes = list(qs.values_list('hash_value', flat=True)[:20])
        count = qs.count()
        qs.delete()
        ActivityLog.log(request.user, 'hashlist.bulk_delete', 'HashEntry', None,
                     {'count': count, 'hashes': [h[:16] + '...' for h in hashes]},
                     getattr(request, 'client_ip', ''))
        messages.success(request, '{} entry(s) removed.'.format(count))
        return _hl_redirect(status)
    return _hl_redirect()


# ── Bulk Deactivate ───────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_bulk_deactivate(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, 'No entries selected.')
            return _hl_redirect(status)
        hashes = list(HashEntry.objects.filter(pk__in=ids, list_type='black').values_list('hash_value', flat=True)[:20])
        count = HashEntry.objects.filter(pk__in=ids, list_type='black').update(is_active=False)
        ActivityLog.log(request.user, 'hashlist.bulk_deactivate', 'HashEntry', None,
                     {'count': count, 'hashes': [h[:16] + '...' for h in hashes]},
                     getattr(request, 'client_ip', ''))
        messages.success(request, '{} entry(s) deactivated.'.format(count))
        return _hl_redirect(status)
    return _hl_redirect()


# ── Bulk Activate ─────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_bulk_activate(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, 'No entries selected.')
            return _hl_redirect(status)
        hashes = list(HashEntry.objects.filter(pk__in=ids, list_type='black').values_list('hash_value', flat=True)[:20])
        count = HashEntry.objects.filter(pk__in=ids, list_type='black').update(is_active=True)
        ActivityLog.log(request.user, 'hashlist.bulk_activate', 'HashEntry', None,
                     {'count': count, 'hashes': [h[:16] + '...' for h in hashes]},
                     getattr(request, 'client_ip', ''))
        messages.success(request, '{} entry(s) activated.'.format(count))
        return _hl_redirect(status)
    return _hl_redirect()


# ── Edit ──────────────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_edit(request, entry_id):
    entry = get_object_or_404(HashEntry, pk=entry_id, list_type='black')
    if request.method == 'POST':
        raw    = request.POST.get('hash_input', '').strip()
        reason = request.POST.get('reason', '').strip()
        if not is_valid_hash(raw):
            messages.error(request, 'Invalid hash value.')
        else:
            hv, ht = normalize_hash(raw)
            if HashEntry.objects.filter(hash_value=hv, list_type='black').exclude(pk=entry.pk).exists():
                messages.error(request, 'This hash already exists in the list.')
            else:
                old        = entry.hash_value
                old_reason = entry.reason or ''
                entry.hash_value = hv
                entry.hash_type  = ht
                entry.reason     = reason
                entry.save()
                ActivityLog.log(request.user, 'hashlist.edit', 'HashEntry', str(entry.pk),
                             {
                                 'old': old, 'new': hv, 'hash_type': ht,
                                 'old_reason': old_reason, 'new_reason': reason or '',
                                 'reason': reason or '',   # backwards-compat with existing readers
                             },
                             getattr(request, 'client_ip', ''))
                messages.success(request, 'Entry updated.')
    return _hl_redirect()


# ── Delete Single ─────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_delete(request, entry_id):
    entry = get_object_or_404(HashEntry, pk=entry_id, list_type='black')
    status = request.POST.get('status', 'active')
    if request.method == 'POST':
        if entry.is_active:
            messages.error(request, 'Active entries cannot be deleted. Deactivate first.')
            return _hl_redirect(status)
        hv = entry.hash_value
        ht = entry.hash_type
        rsn = entry.reason or ''
        entry.delete()
        ActivityLog.log(request.user, 'hashlist.delete', 'HashEntry', str(entry_id),
                     {'hash': hv, 'hash_type': ht, 'reason': rsn}, getattr(request, 'client_ip', ''))
        messages.success(request, 'Entry removed.')
    return _hl_redirect(status)


# ── Deactivate Single ─────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_deactivate_single(request, entry_id):
    entry = get_object_or_404(HashEntry, pk=entry_id, list_type='black')
    status = request.POST.get('status', 'active')
    if request.method == 'POST':
        entry.is_active = False
        entry.save(update_fields=['is_active'])
        ActivityLog.log(request.user, 'hashlist.deactivate', 'HashEntry', str(entry.pk),
                     {'hash': entry.hash_value, 'hash_type': entry.hash_type, 'reason': entry.reason or ''},
                     getattr(request, 'client_ip', ''))
        messages.success(request, 'Entry deactivated.')
    return _hl_redirect(status)


# ── Activate Single ───────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_activate_single(request, entry_id):
    entry = get_object_or_404(HashEntry, pk=entry_id, list_type='black')
    status = request.POST.get('status', 'active')
    if request.method == 'POST':
        entry.is_active = True
        entry.save(update_fields=['is_active'])
        ActivityLog.log(request.user, 'hashlist.activate', 'HashEntry', str(entry.pk),
                     {'hash': entry.hash_value, 'hash_type': entry.hash_type, 'reason': entry.reason or ''},
                     getattr(request, 'client_ip', ''))
        messages.success(request, 'Entry activated.')
    return _hl_redirect(status)


# ── Pin Toggle ────────────────────────────────────────────────────────────────

@login_required_custom
@role_required('admin', 'operator')
def hashlist_pin_toggle(request, entry_id):
    """Toggle is_pinned on a hash entry — always returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)
    entry = get_object_or_404(HashEntry, pk=entry_id, list_type='black')
    entry.is_pinned = not entry.is_pinned
    entry.save(update_fields=['is_pinned'])
    ActivityLog.log(
        request.user, 'hashlist.pin_toggle', 'HashEntry', str(entry.pk),
        {'hash': entry.hash_value[:16] + '...', 'hash_type': entry.hash_type, 'is_pinned': entry.is_pinned},
        getattr(request, 'client_ip', ''),
    )
    state = 'pinned' if entry.is_pinned else 'unpinned'
    return JsonResponse({'success': True, 'is_pinned': entry.is_pinned, 'message': f"{entry.hash_value[:16]}... {state}."})


# ── PDF Report ─────────────────────────────────────────────────────────────
@login_required_custom
@role_required('admin', 'operator')
def hashlist_pdf_report(request):
    from apps.reports.pdf_generator import generate_hashlist_executive
    from apps.settings_app.cache import SettingsCache

    entries = HashEntry.objects.select_related('added_by').filter(list_type='black')
    now = timezone.now()

    date_preset  = request.GET.get('date_preset', '')
    date_from    = request.GET.get('date_from', '')
    date_to      = request.GET.get('date_to', '')
    status       = request.GET.get('status', 'active')
    if date_preset == 'today':
        entries = entries.filter(added_at__date=now.date())
    elif date_preset == '7d':
        entries = entries.filter(added_at__gte=now - timedelta(days=7))
    elif date_preset == '30d':
        entries = entries.filter(added_at__gte=now - timedelta(days=30))
    elif date_preset == 'custom':
        if date_from:
            try:
                entries = entries.filter(added_at__date__gte=_dt.strptime(date_from, '%Y-%m-%d').date())
            except ValueError:
                pass
        if date_to:
            try:
                entries = entries.filter(added_at__date__lte=_dt.strptime(date_to, '%Y-%m-%d').date())
            except ValueError:
                pass

    if status == 'active':
        entries = entries.filter(is_active=True)
    elif status == 'inactive':
        entries = entries.filter(is_active=False)

    try:
        vt_threshold = int(SettingsCache.get('threat_intel.virustotal_detection_threshold', 5) or 5)
    except (TypeError, ValueError):
        vt_threshold = 5

    filters = {'date_preset': date_preset, 'date_from': date_from,
                'date_to': date_to, 'status': status}
    ts = timezone.localtime(now).strftime('%Y%m%d_%H%M%S')

    _full = request.user.get_full_name()
    _generated_by = f'{request.user.username} ({_full})' if _full else request.user.username
    pdf_bytes = generate_hashlist_executive(entries, filters, _generated_by, vt_threshold)
    from apps.settings_app.branding import brand_filename_prefix
    filename = f'{brand_filename_prefix()}_hashlist_{status}_{ts}.pdf'

    ActivityLog.log(request.user, 'report.download', 'HashEntry', None,
                    {'report_type': 'hashlist', 'status': status,
                     'date_preset': date_preset, 'filename': filename},
                    getattr(request, 'client_ip', ''))
    resp = HttpResponse(pdf_bytes, content_type='application/pdf')
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp
