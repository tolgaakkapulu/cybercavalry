import csv
import logging
from datetime import timedelta, datetime as _dt
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.db.models import Q, F
from django.core.paginator import Paginator

from .models import BlacklistEntry, BlacklistGroup
from .forms import BlacklistEntryForm, BulkBlacklistForm
from .utils import normalize_cidr, is_valid_ip_or_cidr, check_whitelist_overlap, check_blacklist_overlap
from . import abuseipdb_service
from apps.accounts.decorators import login_required_custom, role_required
from apps.settings_app.models import ActivityLog

logger = logging.getLogger(__name__)


def _auto_abuse_check(entry):
    """Query AbuseIPDB for an entry if auto-check is enabled. Fire-and-forget, never raises."""
    try:
        from apps.settings_app.cache import SettingsCache
        if SettingsCache.get('threat_intel.abuseipdb_enabled', False) and \
           SettingsCache.get('threat_intel.abuseipdb_auto_check', False):
            abuseipdb_service.update_entry_score(entry)
    except Exception:
        pass


_VALID_STATUSES = {'active', 'inactive', 'expired', 'all'}


def _bl_redirect(status='active'):
    url = reverse('blacklist:list')
    safe_status = status if status in _VALID_STATUSES else 'active'
    if safe_status != 'active':
        url += f'?status={safe_status}'
    return redirect(url)


@login_required_custom
def blacklist_list(request):
    entries = BlacklistEntry.objects.select_related('group', 'added_by').all()

    # Filters
    search = request.GET.get('search', '').strip()
    group_id = request.GET.get('group', '')
    source = request.GET.get('source', '')
    status = request.GET.get('status', 'active')
    pinned = request.GET.get('pinned', '')            # '' | 'yes' | 'no'
    hit_min_raw   = request.GET.get('hit_min',   '').strip()
    hit_max_raw   = request.GET.get('hit_max',   '').strip()
    score_min_raw = request.GET.get('score_min', '').strip()
    score_max_raw = request.GET.get('score_max', '').strip()

    def _parse_int(raw):
        try:
            return int(raw)
        except (ValueError, TypeError):
            return None

    hit_min   = _parse_int(hit_min_raw)
    hit_max   = _parse_int(hit_max_raw)
    score_min = _parse_int(score_min_raw)
    score_max = _parse_int(score_max_raw)

    if search:
        # Search box matches CIDR + reason substrings; a pure-digit query
        # additionally matches the row's primary key so admins can paste an
        # ID from an activity-log row and land on the exact entry.
        q = Q(cidr__icontains=search) | Q(reason__icontains=search)
        if search.isdigit():
            q |= Q(pk=int(search))
        entries = entries.filter(q)
    if group_id:
        entries = entries.filter(group_id=group_id)
    if source:
        entries = entries.filter(source=source)
    if pinned == 'yes':
        entries = entries.filter(is_pinned=True)
    elif pinned == 'no':
        entries = entries.filter(is_pinned=False)
    if score_min is not None:
        entries = entries.filter(abuse_confidence_score__gte=score_min)
    if score_max is not None:
        entries = entries.filter(abuse_confidence_score__lte=score_max)
    now = timezone.now()

    # Counts per status (after search/group/source filters, before status filter)
    count_active   = entries.filter(is_active=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    ).count()
    count_inactive = entries.filter(
        Q(is_active=False) | Q(is_active=True, expires_at__lt=now)
    ).count()
    count_all      = entries.count()

    if status == 'active':
        entries = entries.filter(is_active=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=now)
        )
    elif status == 'expired':
        entries = entries.filter(is_active=True, expires_at__lt=now)
    elif status == 'inactive':
        entries = entries.filter(
            Q(is_active=False) | Q(is_active=True, expires_at__lt=now)
        )

    # Count column sorts by the LENGTH of `recent_hit_timestamps` — the stored
    # rolling-window list — instead of the lifetime `hit_count`, so the sort
    # order matches the number displayed in the badge. Function name differs
    # across backends: SQLite `json_array_length`, PostgreSQL `jsonb_array_length`.
    from django.db import connection as _db_connection
    from django.db.models.expressions import RawSQL
    _json_len_fn = 'jsonb_array_length' if _db_connection.vendor == 'postgresql' else 'json_array_length'
    entries = entries.annotate(
        _recent_len=RawSQL(f'{_json_len_fn}(recent_hit_timestamps)', [])
    )
    # Hit-count range filter uses the same JSON length as the sort key and the
    # `Count` column badge -- so a "Count >= N" filter returns exactly the
    # entries whose visible count matches. Applied AFTER the annotation.
    if hit_min is not None:
        entries = entries.filter(_recent_len__gte=hit_min)
    if hit_max is not None:
        entries = entries.filter(_recent_len__lte=hit_max)
    _BL_SORT = {
        'ip': 'ip_address', 'group': 'group__name', 'source': 'source',
        'score': 'abuse_confidence_score', 'checked': 'abuse_checked_at',
        'added': 'added_at', 'added_by': 'added_by__username', 'expires': 'expires_at',
        'hit_count': '_recent_len',
    }
    _BL_NULL = {'abuse_confidence_score', 'abuse_checked_at', 'expires_at', 'added_by__username'}
    sort = request.GET.get('sort', 'added')
    sort_dir = request.GET.get('dir', 'desc')
    sort_field = _BL_SORT.get(sort, 'added_at')
    if sort_field in _BL_NULL:
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

    groups = BlacklistGroup.objects.all()
    total_count = entries.count()

    from apps.settings_app.cache import SettingsCache
    try:
        score_30d = int(SettingsCache.get('threat_intel.abuseipdb_threshold_30d', 80))
    except (TypeError, ValueError):
        score_30d = 80
    try:
        score_24h = int(SettingsCache.get('threat_intel.abuseipdb_threshold_24h', 10))
    except (TypeError, ValueError):
        score_24h = 10

    try:
        refresh_seconds = max(1, min(3600, int(SettingsCache.get('general.blacklist_refresh_seconds', 5))))
    except (TypeError, ValueError):
        refresh_seconds = 5
    try:
        promotion_threshold = int(SettingsCache.get('threat_intel.abuseipdb_promotion_threshold', 0) or 0)
    except (TypeError, ValueError):
        promotion_threshold = 0
    try:
        promotion_window_days = int(SettingsCache.get('threat_intel.abuseipdb_promotion_window_days', 7) or 7)
    except (TypeError, ValueError):
        promotion_window_days = 7
    promotion_window_days = max(1, min(30, promotion_window_days))
    # Annotate each entry on this page with the recent-hit count computed
    # against the currently configured window. Template consumes it as
    # `entry.recent_hit_count` — reading a plain attribute is cheaper than
    # re-invoking the model method per template access and it keeps the
    # tooltip's window value in sync with the number in the badge.
    for _e in entries_page:
        _e.recent_hit_count = _e.count_recent_hits_within(promotion_window_days)
    ctx = {
        'entries': entries_page,
        'groups': groups,
        'total_count': total_count,
        'filters': {
            'search':    search,
            'group':     group_id,
            'source':    source,
            'status':    status,
            'pinned':    pinned,
            'hit_min':   hit_min_raw,
            'hit_max':   hit_max_raw,
            'score_min': score_min_raw,
            'score_max': score_max_raw,
        },
        'score_30d': score_30d,
        'score_24h': score_24h,
        'count_active': count_active,
        'count_inactive': count_inactive,
        'count_all': count_all,
        'sort': sort,
        'dir': sort_dir,
        'sort_qs': sort_qs,
        'page_size': page_size,
        'page_size_options': PAGE_SIZE_OPTIONS,
        'refresh_seconds': refresh_seconds,
        'promotion_threshold': promotion_threshold,
        'promotion_window_days': promotion_window_days,
    }
    # `?ajax=1` returns just the <tbody> contents — used by the in-page
    # auto-refresh poller so the table streams updates without a full
    # browser reload (no Alpine reinit, no scroll jump, no FOUC). The
    # Active/Inactive/All tab counts come back as response headers so the
    # JS can refresh them in place without an extra round-trip.
    if request.GET.get('ajax') == '1':
        resp = render(request, 'blacklist/_list_rows.html', ctx)
        resp['X-Count-Active']   = str(count_active)
        resp['X-Count-Inactive'] = str(count_inactive)
        resp['X-Count-All']      = str(count_all)
        return resp
    return render(request, 'blacklist/list.html', ctx)


@login_required_custom
@role_required('admin', 'operator')
def blacklist_create(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        form = BlacklistEntryForm(request.POST)
        if form.is_valid():
            input_cidr = form.cleaned_data['_cidr']
            group = form.cleaned_data['group']
            reason = form.cleaned_data.get('reason', '')

            # Only /32 single IPs accepted
            cidr, ip, prefix = normalize_cidr(input_cidr)
            if prefix != 32:
                messages.error(request, f"'{form.cleaned_data['ip_input']}' is a CIDR block. Only single IP addresses (/32) are accepted.")
                return _bl_redirect(status)

            if check_whitelist_overlap(cidr):
                messages.warning(request, f"{cidr} skipped — overlaps with a whitelisted entry.")
                return _bl_redirect(status)
            if check_blacklist_overlap(cidr, group, exclude_cidr=cidr):
                messages.warning(request, f"{cidr} already exists or overlaps with an existing blacklist entry in {group.label}.")
                return _bl_redirect(status)

            existing = BlacklistEntry.objects.filter(cidr=cidr, group=group).first()
            if existing:
                if not existing.is_active:
                    existing.is_active = True
                    existing.set_expiry_from_group()
                    if reason:
                        existing.reason = reason
                    existing.save()
                    _auto_abuse_check(existing)
                    messages.success(request, f"{cidr} re-activated in {group.label}.")
                else:
                    messages.warning(request, f"{cidr} already exists in {group.label}.")
            else:
                entry = BlacklistEntry(
                    cidr=cidr, ip_address=ip, prefix_length=prefix,
                    group=group, reason=reason,
                    added_by=request.user, source=BlacklistEntry.SOURCE_MANUAL,
                )
                entry.set_expiry_from_group()
                entry.save()
                _auto_abuse_check(entry)
                ActivityLog.log(request.user, 'blacklist.add', 'BlacklistEntry', None,
                             {'input': input_cidr, 'added': 1, 'group': group.name},
                             getattr(request, 'client_ip', ''))
                messages.success(request, f"{cidr} added to {group.label}.")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    return _bl_redirect(request.POST.get('status', 'active'))


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_create(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        form = BulkBlacklistForm(request.POST)
        if form.is_valid():
            ip_list = form.cleaned_data['ip_list']
            group = form.cleaned_data['group']
            reason = form.cleaned_data.get('reason', '')
            added = 0
            duplicates = 0
            whitelisted = 0
            bl_overlaps = 0

            cidr_block_count = 0
            cidr_block_list = []
            for ip_str in ip_list:
                cidr, ip, prefix = normalize_cidr(ip_str)
                if prefix != 32:
                    cidr_block_count += 1
                    cidr_block_list.append(ip_str)
                    continue
                if check_whitelist_overlap(cidr):
                    whitelisted += 1
                    continue
                if check_blacklist_overlap(cidr, group, exclude_cidr=cidr):
                    bl_overlaps += 1
                    continue
                obj, created = BlacklistEntry.objects.get_or_create(
                    cidr=cidr, group=group,
                    defaults={
                        'ip_address': ip,
                        'prefix_length': prefix,
                        'reason': reason,
                        'source': BlacklistEntry.SOURCE_MANUAL,
                        'added_by': request.user,
                    }
                )
                if created:
                    obj.set_expiry_from_group()
                    obj.save()
                    _auto_abuse_check(obj)
                    added += 1
                elif not obj.is_active:
                    obj.is_active = True
                    obj.set_expiry_from_group()
                    if reason:
                        obj.reason = reason
                    obj.save()
                    _auto_abuse_check(obj)
                    added += 1
                else:
                    duplicates += 1

            msg = f"Bulk add complete: {added} added, {duplicates} duplicates skipped."
            if cidr_block_count:
                skipped_list = ', '.join(cidr_block_list[:10])
                if cidr_block_count > 10:
                    skipped_list += f' ... (+{cidr_block_count - 10} more)'
                msg += f" {cidr_block_count} CIDR block(s) skipped (only /32 single IPs accepted): {skipped_list}."
            if whitelisted:
                msg += f" {whitelisted} skipped (whitelisted)."
            if bl_overlaps:
                msg += f" {bl_overlaps} skipped (overlaps with existing blacklist entry)."
            messages.success(request, msg)
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    return _bl_redirect(request.POST.get('status', 'active'))


@login_required_custom
@role_required('admin', 'operator')
def blacklist_edit(request, entry_id):
    entry = get_object_or_404(BlacklistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')

    if request.method == 'POST':
        # Snapshot pre-edit values for the audit-log diff.
        old_cidr   = entry.cidr
        old_group  = entry.group.name if entry.group_id else ''
        old_reason = entry.reason or ''
        form = BlacklistEntryForm(request.POST, instance=entry)
        if form.is_valid():
            new_cidr  = form.cleaned_data['_cidr']
            new_group = form.cleaned_data['group']

            # Check for duplicate (cidr, group) on a different entry
            conflict = BlacklistEntry.objects.filter(
                cidr=new_cidr, group=new_group
            ).exclude(pk=entry.pk).first()

            if conflict:
                messages.error(
                    request,
                    f"{new_cidr} already exists in {new_group.label}. "
                    f"Edit the existing entry or choose a different group."
                )
            else:
                updated = form.save(commit=False)
                updated.cidr         = new_cidr
                updated.ip_address   = form.cleaned_data['_ip']
                updated.prefix_length = form.cleaned_data['_prefix']
                updated.save()
                new_group_name = updated.group.name if updated.group_id else ''
                new_reason     = updated.reason or ''
                ActivityLog.log(request.user, 'blacklist.edit', 'BlacklistEntry', str(entry.pk),
                             {
                                 'cidr':       updated.cidr,
                                 'old_cidr':   old_cidr,    'new_cidr':   updated.cidr,
                                 'old_group':  old_group,   'new_group':  new_group_name,
                                 'old_reason': old_reason,  'new_reason': new_reason,
                             }, getattr(request, 'client_ip', ''))
                messages.success(request, f"{updated.cidr} updated.")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    return _bl_redirect(status)


@login_required_custom
@role_required('admin', 'operator')
def blacklist_delete(request, entry_id):
    """Hard delete — permanently removes the entry from DB."""
    entry = get_object_or_404(BlacklistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')

    if request.method == 'POST':
        cidr = entry.cidr
        pk = str(entry.pk)
        entry.delete()
        ActivityLog.log(request.user, 'blacklist.delete', 'BlacklistEntry', pk,
                     {'cidr': cidr}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{cidr} permanently removed.")

    return _bl_redirect(status)


@login_required_custom
@role_required('admin', 'operator')
def blacklist_deactivate_single(request, entry_id):
    """Soft delete — moves the entry to Inactive."""
    entry = get_object_or_404(BlacklistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')

    if request.method == 'POST':
        entry.is_active = False
        entry.save(update_fields=['is_active'])
        ActivityLog.log(request.user, 'blacklist.deactivate', 'BlacklistEntry', str(entry.pk),
                     {'cidr': entry.cidr}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{entry.cidr} deactivated.")

    return _bl_redirect(status)


@login_required_custom
@role_required('admin', 'operator')
def blacklist_import_csv(request):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _err(msg):
        if is_ajax:
            return JsonResponse({'ok': False, 'message': msg}, status=400)
        messages.error(request, msg)
        return redirect('blacklist:list')

    if request.method == 'POST':
        csv_file = request.FILES.get('csv_file')
        if not csv_file or not csv_file.name.endswith('.csv'):
            return _err("Please upload a valid .csv file.")

        try:
            decoded = csv_file.read().decode('utf-8-sig').splitlines()
        except UnicodeDecodeError:
            return _err("File encoding not supported. Please use UTF-8.")

        # Non-empty lines
        lines = [l for l in decoded if l.strip()]
        if not lines:
            return _err("CSV file is empty.")

        # Cap import size — each row triggers DB overlap scans (and optional
        # AbuseIPDB calls), so an unbounded file is a DoS vector. Reject loudly
        # rather than silently truncating so the operator notices.
        _MAX_IMPORT_ROWS = 10000
        if len(lines) > _MAX_IMPORT_ROWS:
            return _err(f"Too many rows ({len(lines)}). Maximum {_MAX_IMPORT_ROWS} "
                        f"per import — split the file into smaller batches.")

        IP_COLS     = ['cidr', 'ip', 'ip_address', 'address', 'network', 'subnet']
        GROUP_COLS  = ['group', 'group_name', 'list', 'blacklist_group']
        REASON_COLS = ['reason', 'description', 'note', 'comment']

        groups_cache = {g.name: g for g in BlacklistGroup.objects.all()}
        default_group = groups_cache.get('30d') or groups_cache.get('24h') or next(iter(groups_cache.values()), None)
        added = skipped = errors = whitelisted = bl_overlaps = cidr_blocks = 0
        added_cidrs = []
        skipped_cidrs = []
        error_lines = []
        whitelisted_cidrs = []
        bl_overlap_cidrs = []
        cidr_block_lines = []

        # Detect whether first row is a header or raw IP data
        first_line_is_ip = is_valid_ip_or_cidr(lines[0].split(',')[0].strip())

        def _process_entry(i, cidr_raw, group, reason):
            nonlocal added, skipped, errors, whitelisted, bl_overlaps, cidr_blocks
            if not cidr_raw:
                errors += 1
                error_lines.append(f'row {i}: empty')
                return
            if not group:
                errors += 1
                error_lines.append(f'row {i}: no group')
                logger.warning(f"CSV import row {i}: no valid group")
                return
            try:
                cidr, ip, prefix = normalize_cidr(cidr_raw)
            except ValueError:
                errors += 1
                error_lines.append(f'row {i}: {cidr_raw}')
                logger.warning(f"CSV import row {i}: invalid CIDR '{cidr_raw}'")
                return
            if prefix != 32:
                cidr_blocks += 1
                cidr_block_lines.append(cidr_raw)
                logger.warning(f"CSV import row {i}: '{cidr_raw}' is a CIDR block, only /32 allowed")
                return
            if check_whitelist_overlap(cidr):
                whitelisted += 1
                whitelisted_cidrs.append(cidr)
                logger.info(f"CSV import row {i}: {cidr} skipped — overlaps with whitelist")
                return
            matched_bl = check_blacklist_overlap(cidr, group, exclude_cidr=cidr)
            if matched_bl:
                bl_overlaps += 1
                bl_overlap_cidrs.append(cidr)
                logger.info(f"CSV import row {i}: {cidr} skipped — overlaps with blacklist entry {matched_bl}")
                return
            obj, created = BlacklistEntry.objects.get_or_create(
                cidr=cidr, group=group,
                defaults={
                    'ip_address': ip, 'prefix_length': prefix,
                    'reason': reason, 'source': BlacklistEntry.SOURCE_IMPORT,
                    'added_by': request.user,
                }
            )
            if created:
                obj.set_expiry_from_group()
                obj.save()
                _auto_abuse_check(obj)
                added += 1
                added_cidrs.append(cidr)
            elif not obj.is_active:
                obj.is_active = True
                obj.set_expiry_from_group()
                if reason:
                    obj.reason = reason
                obj.save()
                _auto_abuse_check(obj)
                added += 1
                added_cidrs.append(cidr)
            else:
                skipped += 1
                skipped_cidrs.append(cidr)

        if first_line_is_ip:
            # No-header mode: each line is an IP/CIDR optionally followed by group and reason
            for i, line in enumerate(lines, start=1):
                parts = [p.strip() for p in line.split(',')]
                cidr_raw   = parts[0] if len(parts) > 0 else ''
                group_name = parts[1].lower() if len(parts) > 1 else ''
                reason     = parts[2] if len(parts) > 2 else ''
                group = groups_cache.get(group_name) if group_name else default_group
                _process_entry(i, cidr_raw, group, reason)
        else:
            # Header mode: use DictReader
            reader = csv.DictReader(lines)
            fields_lower = {c.strip().lower(): c for c in (reader.fieldnames or [])}

            def pick(row, candidates):
                for c in candidates:
                    val = row.get(fields_lower.get(c, ''), '')
                    if isinstance(val, str):
                        val = val.strip()
                        if val:
                            return val
                for c in candidates:
                    for k, orig in fields_lower.items():
                        if k.startswith(c[:4]):
                            val = row.get(orig, '')
                            if isinstance(val, str):
                                val = val.strip()
                                if val:
                                    return val
                return ''

            for i, row in enumerate(reader, start=2):
                cidr_raw   = pick(row, IP_COLS)
                if not cidr_raw:
                    cidr_raw = next(
                        (v.strip() for v in row.values() if isinstance(v, str) and v.strip()),
                        ''
                    )
                group_name = pick(row, GROUP_COLS).lower()
                reason     = pick(row, REASON_COLS)
                group = groups_cache.get(group_name) if group_name else default_group
                _process_entry(i, cidr_raw, group, reason)

        ActivityLog.log(request.user, 'blacklist.import_csv', 'BlacklistEntry', None,
                     {
                         'added': added, 'skipped': skipped, 'errors': errors,
                         'whitelisted': whitelisted, 'bl_overlaps': bl_overlaps,
                         'cidr_blocks': cidr_blocks,
                         'added_cidrs': added_cidrs,
                         'skipped_cidrs': skipped_cidrs,
                         'error_lines': error_lines,
                         'whitelisted_cidrs': whitelisted_cidrs,
                         'bl_overlap_cidrs': bl_overlap_cidrs,
                         'cidr_block_lines': cidr_block_lines,
                     },
                     getattr(request, 'client_ip', ''))

        msg = f"CSV import complete: {added} added, {skipped} duplicates skipped, {errors} errors."
        if cidr_blocks:
            msg += f" {cidr_blocks} skipped (CIDR blocks not allowed — only single IPs accepted)."
        if whitelisted:
            msg += f" {whitelisted} skipped (whitelisted)."
        if bl_overlaps:
            msg += f" {bl_overlaps} skipped (overlaps with existing blacklist entry)."

        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return JsonResponse({
                'ok': True,
                'added': added,
                'skipped': skipped,
                'errors': errors,
                'whitelisted': whitelisted,
                'bl_overlaps': bl_overlaps,
                'cidr_blocks': cidr_blocks,
                'message': msg,
            })
        messages.success(request, msg)
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_activate(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _bl_redirect(status)
        entries = BlacklistEntry.objects.filter(pk__in=ids).select_related('group')
        count = 0
        activated_cidrs = []
        skipped_cidrs = []
        for entry in entries:
            if entry.group.name == 'no_group':
                skipped_cidrs.append(entry.cidr)
                continue
            entry.is_active = True
            entry.set_expiry_from_group()
            entry.save(update_fields=['is_active', 'expires_at'])
            count += 1
            activated_cidrs.append(entry.cidr)
        if count:
            ActivityLog.log(request.user, 'blacklist.bulk_activate', 'BlacklistEntry', None,
                         {'count': count, 'cidrs': activated_cidrs}, getattr(request, 'client_ip', ''))
            messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} activated.")
        if skipped_cidrs:
            messages.error(
                request,
                f"{len(skipped_cidrs)} entr{'y' if len(skipped_cidrs) == 1 else 'ies'} skipped because "
                f"{'it has' if len(skipped_cidrs) == 1 else 'they have'} no group assigned "
                f"({', '.join(skipped_cidrs[:10])}{'...' if len(skipped_cidrs) > 10 else ''}). "
                "Assign a blacklist group (24h or 30d) before activating."
            )
        if not count and not skipped_cidrs:
            messages.warning(request, "No entries were activated.")
        return _bl_redirect(status)
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_deactivate(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _bl_redirect(status)
        entries = BlacklistEntry.objects.filter(pk__in=ids)
        deactivated_cidrs = list(entries.values_list('cidr', flat=True))
        count = len(deactivated_cidrs)
        entries.update(is_active=False)
        ActivityLog.log(request.user, 'blacklist.bulk_deactivate', 'BlacklistEntry', None,
                     {'count': count, 'cidrs': deactivated_cidrs}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} deactivated.")
        return _bl_redirect(status)
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_deactivate_all(request):
    if request.method == 'POST':
        entries = BlacklistEntry.objects.filter(is_active=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        )
        search = request.POST.get('search', '').strip()
        group_id = request.POST.get('group', '').strip()
        source = request.POST.get('source', '').strip()
        if search:
            q = Q(cidr__icontains=search) | Q(reason__icontains=search)
            if search.isdigit():
                q |= Q(pk=int(search))
            entries = entries.filter(q)
        if group_id:
            entries = entries.filter(group_id=group_id)
        if source:
            entries = entries.filter(source=source)
        deactivated_cidrs = list(entries.values_list('cidr', flat=True))
        count = len(deactivated_cidrs)
        entries.update(is_active=False)
        ActivityLog.log(request.user, 'blacklist.deactivate_all', 'BlacklistEntry', None,
                     {'count': count, 'cidrs': deactivated_cidrs}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} deactivated.")
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_delete(request):
    """Hard delete — permanently removes entries from DB."""
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _bl_redirect(status)
        entries = BlacklistEntry.objects.filter(pk__in=ids)
        deleted_cidrs = list(entries.values_list('cidr', flat=True))
        count = len(deleted_cidrs)
        entries.delete()
        ActivityLog.log(request.user, 'blacklist.bulk_delete', 'BlacklistEntry', None,
                     {'count': count, 'cidrs': deleted_cidrs}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} permanently removed.")
        return _bl_redirect(status)
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_edit_group(request):
    """Change the group (and recalculate expiry) for multiple entries at once."""
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        group_id = request.POST.get('group_id', '').strip()

        if not ids:
            messages.warning(request, "No entries selected.")
            return _bl_redirect(status)
        if not group_id:
            messages.error(request, "Please select a group.")
            return _bl_redirect(status)

        group = get_object_or_404(BlacklistGroup, pk=group_id)
        entries = BlacklistEntry.objects.filter(pk__in=ids)
        count = 0
        edited_cidrs = []
        for entry in entries:
            entry.group = group
            entry.set_expiry_from_group()
            entry.save(update_fields=['group', 'expires_at'])
            count += 1
            edited_cidrs.append(entry.cidr)

        ActivityLog.log(request.user, 'blacklist.bulk_edit_group', 'BlacklistEntry', None,
                     {'count': count, 'group': group.name, 'cidrs': edited_cidrs}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} moved to {group.label}.")
        return _bl_redirect(status)
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_hard_delete(request):
    """Hard delete — permanently removes entries from DB (for inactive entries)."""
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _bl_redirect(status)
        entries = BlacklistEntry.objects.filter(pk__in=ids)
        deleted_cidrs = list(entries.values_list('cidr', flat=True))
        count = len(deleted_cidrs)
        entries.delete()
        ActivityLog.log(request.user, 'blacklist.bulk_delete', 'BlacklistEntry', None,
                     {'count': count, 'cidrs': deleted_cidrs}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} permanently removed.")
        return _bl_redirect(status)
    return _bl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def blacklist_score_single(request, entry_id):
    """Query AbuseIPDB for a single entry — always returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)
    entry = get_object_or_404(BlacklistEntry, pk=entry_id)
    from apps.settings_app.cache import SettingsCache
    if not SettingsCache.get('threat_intel.abuseipdb_enabled', False):
        return JsonResponse({'success': False, 'message': 'AbuseIPDB is disabled. Enable it in Settings → Threat Intelligence.'})
    score = abuseipdb_service.update_entry_score(entry)
    if score is not None:
        entry.refresh_from_db()
        ActivityLog.log(request.user, 'threat_intel.score_single', 'BlacklistEntry', str(entry.pk),
                     {'ip': entry.ip_address, 'score': score}, getattr(request, 'client_ip', ''))
        expires_display = (
            timezone.localtime(entry.expires_at).strftime('%Y-%m-%d %H:%M')
            if entry.expires_at else None
        )
        return JsonResponse({
            'success': True,
            'score': score,
            'group_label': entry.group.label,
            'group_name': entry.group.name,
            'is_active': entry.is_active,
            'expires_at': expires_display,
            'message': f"{entry.ip_address} — Score: {score}/100 → {entry.group.label}",
        })
    return JsonResponse({'success': False, 'message': f"AbuseIPDB query failed for {entry.ip_address}. Check API key and settings."})


@login_required_custom
@role_required('admin', 'operator')
def blacklist_bulk_score(request):
    """Query AbuseIPDB for multiple selected entries — always returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)
    ids = request.POST.getlist('entry_ids')
    if not ids:
        return JsonResponse({'success': False, 'message': 'No entries selected.'})
    from apps.settings_app.cache import SettingsCache
    if not SettingsCache.get('threat_intel.abuseipdb_enabled', False):
        return JsonResponse({'success': False, 'message': 'AbuseIPDB is disabled. Enable it in Settings → Threat Intelligence.'})
    entries = BlacklistEntry.objects.filter(pk__in=ids).select_related('group')
    scored = failed = 0
    for entry in entries:
        score = abuseipdb_service.update_entry_score(entry)
        if score is not None:
            scored += 1
        else:
            failed += 1
    ActivityLog.log(request.user, 'threat_intel.bulk_score', 'BlacklistEntry', None,
                 {'scored': scored, 'failed': failed}, getattr(request, 'client_ip', ''))
    msg = f"{scored} entr{'y' if scored == 1 else 'ies'} scored."
    if failed:
        msg += f" {failed} failed (check API key)."
    return JsonResponse({'success': scored > 0 or failed == 0, 'scored': scored, 'failed': failed, 'message': msg})


@login_required_custom
@role_required('admin', 'operator')
def blacklist_pin_toggle(request, entry_id):
    """Toggle is_pinned on a blacklist entry — always returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'POST required'}, status=405)
    entry = get_object_or_404(BlacklistEntry, pk=entry_id)
    entry.is_pinned = not entry.is_pinned
    entry.save(update_fields=['is_pinned'])
    ActivityLog.log(
        request.user, 'blacklist.pin_toggle', 'BlacklistEntry', str(entry.pk),
        {'cidr': entry.cidr, 'is_pinned': entry.is_pinned},
        getattr(request, 'client_ip', ''),
    )
    state = 'pinned' if entry.is_pinned else 'unpinned'
    return JsonResponse({'success': True, 'is_pinned': entry.is_pinned, 'message': f"{entry.cidr} {state}."})


@login_required_custom
@role_required('admin', 'operator')
def blacklist_reactivate(request, entry_id):
    entry = get_object_or_404(BlacklistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')
    if request.method == 'POST':
        if entry.group.name == 'no_group':
            messages.error(
                request,
                f"{entry.cidr} cannot be activated because it has no group assigned. "
                "Edit the entry and assign a blacklist group (24h or 30d) first."
            )
            return _bl_redirect(status)
        entry.is_active = True
        entry.set_expiry_from_group()
        entry.save()
        ActivityLog.log(request.user, 'blacklist.reactivate', 'BlacklistEntry', str(entry.pk),
                     {'cidr': entry.cidr, 'group': entry.group.name}, getattr(request, 'client_ip', ''))
        messages.success(request, f"{entry.cidr} re-activated in {entry.group.label}.")
    return _bl_redirect(status)


@login_required_custom
def blacklist_export(request):
    entries = BlacklistEntry.objects.select_related('group').all()

    search   = request.GET.get('search', '').strip()
    group_id = request.GET.get('group', '')
    source   = request.GET.get('source', '')
    status   = request.GET.get('status', 'active')

    if search:
        entries = entries.filter(Q(cidr__icontains=search) | Q(reason__icontains=search))
    if group_id:
        entries = entries.filter(group_id=group_id)
    if source:
        entries = entries.filter(source=source)
    _now = timezone.now()
    if status == 'active':
        entries = entries.filter(is_active=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=_now)
        )
    elif status == 'inactive':
        entries = entries.filter(
            Q(is_active=False) | Q(is_active=True, expires_at__lt=_now)
        )
    elif status == 'expired':
        entries = entries.filter(is_active=True, expires_at__lt=_now)
    # status == 'all' → no additional filter

    ts = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
    status_label = status if status in ('active', 'inactive', 'expired', 'all') else 'active'
    response = HttpResponse(content_type='text/csv')
    from apps.settings_app.branding import brand_filename_prefix
    response['Content-Disposition'] = f'attachment; filename="{brand_filename_prefix()}_blacklist_{status_label}_{ts}.csv"'

    from apps.settings_app.csv_util import safe_row
    writer = csv.writer(response)
    writer.writerow(['IP', 'Group', 'Source', 'Reason', 'Status', 'Abuse Score', 'Abuse Checked At', 'Added At', 'Expires At'])
    for entry in entries:
        writer.writerow(safe_row([
            entry.ip_address,
            entry.group.label,
            entry.source,
            entry.reason or '',
            'Active' if entry.is_active else 'Inactive',
            entry.abuse_confidence_score if entry.abuse_confidence_score is not None else '',
            timezone.localtime(entry.abuse_checked_at).strftime('%Y-%m-%d %H:%M:%S') if entry.abuse_checked_at else '',
            timezone.localtime(entry.added_at).strftime('%Y-%m-%d %H:%M:%S'),
            timezone.localtime(entry.expires_at).strftime('%Y-%m-%d %H:%M:%S') if entry.expires_at else 'Never',
        ]))

    return response


# ── PDF Report ─────────────────────────────────────────────────────────────
@login_required_custom
@role_required('admin', 'operator')
def blacklist_pdf_report(request):
    from apps.reports.pdf_generator import generate_blacklist_executive
    from apps.settings_app.cache import SettingsCache

    entries = BlacklistEntry.objects.select_related('group', 'added_by').all()
    now = timezone.now()

    date_preset  = request.GET.get('date_preset', '')
    date_from    = request.GET.get('date_from', '')
    date_to      = request.GET.get('date_to', '')
    status       = request.GET.get('status', 'active')
    # Date filter
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

    # Status filter
    if status == 'active':
        entries = entries.filter(is_active=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=now)
        )
    elif status == 'inactive':
        entries = entries.filter(
            Q(is_active=False) | Q(is_active=True, expires_at__lt=now)
        )

    try:
        score_30d = int(SettingsCache.get('threat_intel.abuseipdb_threshold_30d', 80))
    except (TypeError, ValueError):
        score_30d = 80
    try:
        score_24h = int(SettingsCache.get('threat_intel.abuseipdb_threshold_24h', 10))
    except (TypeError, ValueError):
        score_24h = 10

    filters = {'date_preset': date_preset, 'date_from': date_from,
                'date_to': date_to, 'status': status}
    ts = timezone.localtime(now).strftime('%Y%m%d_%H%M%S')

    _full = request.user.get_full_name()
    _generated_by = f'{request.user.username} ({_full})' if _full else request.user.username
    pdf_bytes = generate_blacklist_executive(entries, filters, _generated_by, score_30d, score_24h)
    from apps.settings_app.branding import brand_filename_prefix
    filename = f'{brand_filename_prefix()}_blacklist_{status}_{ts}.pdf'

    ActivityLog.log(request.user, 'report.download', 'BlacklistEntry', None,
                    {'report_type': 'blacklist', 'status': status,
                     'date_preset': date_preset, 'filename': filename},
                    getattr(request, 'client_ip', ''))
    resp = HttpResponse(pdf_bytes, content_type='application/pdf')
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp
