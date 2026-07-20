import csv
import ipaddress
import logging
from datetime import timedelta, datetime as _dt
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.db.models import Q, F
from django.utils import timezone

from .models import WhitelistEntry
from apps.accounts.decorators import login_required_custom, role_required
from apps.settings_app.models import ActivityLog
from apps.blacklist.utils import normalize_cidr, is_valid_ip_or_cidr

logger = logging.getLogger(__name__)

from django.urls import reverse

_VALID_STATUSES = {'active', 'inactive', 'all'}


def _wl_redirect(status='active'):
    url = reverse('whitelist:list')
    safe_status = status if status in _VALID_STATUSES else 'active'
    if safe_status != 'active':
        url += f'?status={safe_status}'
    return redirect(url)


def _deactivate_blacklist_overlaps(wl_cidr, user, client_ip=''):
    """
    Deactivate any active blacklist entries whose CIDR overlaps with wl_cidr.
    Returns a list of deactivated CIDR strings.
    """
    from apps.blacklist.models import BlacklistEntry

    try:
        wl_net = ipaddress.ip_network(wl_cidr, strict=False)
    except ValueError:
        return []

    active_entries = BlacklistEntry.objects.filter(is_active=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    ).select_related('group')

    deactivated = []
    for entry in active_entries:
        try:
            bl_net = ipaddress.ip_network(entry.cidr, strict=False)
            if wl_net.overlaps(bl_net):
                entry.is_active = False
                entry.save(update_fields=['is_active'])
                ActivityLog.log(user, 'blacklist.auto_deactivate', 'BlacklistEntry', str(entry.pk),
                             {'cidr': entry.cidr, 'reason': f'Overlaps with new whitelist entry {wl_cidr}'},
                             client_ip)
                deactivated.append(entry.cidr)
        except ValueError:
            continue

    return deactivated


def _reactivate_blacklist_overlaps(wl_cidr, user, client_ip=''):
    """
    Reactivate inactive blacklist entries that overlap with wl_cidr,
    but only if they are no longer covered by any remaining active whitelist entry.
    Returns a list of reactivated CIDR strings.
    """
    from apps.blacklist.models import BlacklistEntry

    try:
        wl_net = ipaddress.ip_network(wl_cidr, strict=False)
    except ValueError:
        return []

    inactive_entries = BlacklistEntry.objects.filter(is_active=False).select_related('group')
    # Remaining active whitelist entries (removed/deactivated entry already gone from DB)
    remaining_wl_nets = []
    for wl in WhitelistEntry.objects.filter(is_active=True):
        try:
            remaining_wl_nets.append(ipaddress.ip_network(wl.cidr, strict=False))
        except ValueError:
            pass

    reactivated = []
    for entry in inactive_entries:
        try:
            bl_net = ipaddress.ip_network(entry.cidr, strict=False)
        except ValueError:
            continue

        if not wl_net.overlaps(bl_net):
            continue

        # Skip if still protected by another active whitelist entry
        if any(other.overlaps(bl_net) for other in remaining_wl_nets):
            continue

        entry.is_active = True
        entry.set_expiry_from_group()
        entry.save(update_fields=['is_active', 'expires_at'])
        ActivityLog.log(user, 'blacklist.auto_reactivate', 'BlacklistEntry', str(entry.pk),
                     {'cidr': entry.cidr, 'reason': f'Whitelist entry {wl_cidr} removed/deactivated'},
                     client_ip)
        reactivated.append(entry.cidr)

    return reactivated


def _notify_reactivated(request, reactivated):
    if not reactivated:
        return
    count = len(reactivated)
    cidrs = ', '.join(reactivated[:10])
    suffix = f' and {count - 10} more' if count > 10 else ''
    messages.info(
        request,
        f"{count} blacklist entr{'y' if count == 1 else 'ies'} automatically re-activated "
        f"({cidrs}{suffix})."
    )


@login_required_custom
def whitelist_list(request):
    base_qs = WhitelistEntry.objects.select_related('added_by').all()
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status', 'active')

    if search:
        # Pure-digit query also matches the row's primary key.
        q = Q(cidr__icontains=search) | Q(reason__icontains=search)
        if search.isdigit():
            q |= Q(pk=int(search))
        base_qs = base_qs.filter(q)

    count_active   = base_qs.filter(is_active=True).count()
    count_inactive = base_qs.filter(is_active=False).count()
    count_all      = count_active + count_inactive

    entries = base_qs
    if status == 'active':
        entries = entries.filter(is_active=True)
    elif status == 'inactive':
        entries = entries.filter(is_active=False)

    _WL_SORT = {
        'cidr': 'cidr', 'prefix': 'prefix_length', 'source': 'source',
        'added_by': 'added_by__username', 'added': 'added_at',
    }
    _WL_NULL = {'added_by__username'}
    sort = request.GET.get('sort', 'added')
    sort_dir = request.GET.get('dir', 'desc')
    sort_field = _WL_SORT.get(sort, 'added_at')
    if sort_field in _WL_NULL:
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

    return render(request, 'whitelist/list.html', {
        'entries': entries_page,
        'search': search,
        'status': status,
        'count_active': count_active,
        'count_inactive': count_inactive,
        'count_all': count_all,
        'sort': sort,
        'dir': sort_dir,
        'sort_qs': sort_qs,
        'page_size': page_size,
        'page_size_options': PAGE_SIZE_OPTIONS,
    })


@login_required_custom
@role_required('admin', 'operator')
def whitelist_create(request):
    if request.method == 'POST':
        ip_input = request.POST.get('ip_input', '').strip()
        reason = request.POST.get('reason', '').strip()

        if not is_valid_ip_or_cidr(ip_input):
            messages.error(request, f"'{ip_input}' is not a valid IP address or CIDR notation.")
        else:
            cidr, ip, prefix = normalize_cidr(ip_input)
            if WhitelistEntry.objects.filter(cidr=cidr).exists():
                messages.warning(request, f"{cidr} is already in the whitelist.")
            else:
                entry = WhitelistEntry.objects.create(
                    cidr=cidr, ip_address=ip, prefix_length=prefix,
                    reason=reason, added_by=request.user,
                    source=WhitelistEntry.SOURCE_MANUAL,
                )
                ActivityLog.log(request.user, 'whitelist.add', 'WhitelistEntry', str(entry.pk),
                             {'cidr': cidr}, getattr(request, 'client_ip', ''))
                messages.success(request, f"{cidr} added to whitelist.")

                deactivated = _deactivate_blacklist_overlaps(
                    cidr, request.user, getattr(request, 'client_ip', '')
                )
                if deactivated:
                    cidrs = ', '.join(deactivated[:10])
                    suffix = f' and {len(deactivated) - 10} more' if len(deactivated) > 10 else ''
                    messages.warning(
                        request,
                        f"{len(deactivated)} blacklist entr{'y' if len(deactivated) == 1 else 'ies'} "
                        f"deactivated because {'it overlaps' if len(deactivated) == 1 else 'they overlap'} "
                        f"with the new whitelist entry ({cidrs}{suffix})."
                    )
    return redirect('whitelist:list')


@login_required_custom
@role_required('admin', 'operator')
def whitelist_bulk_create(request):
    if request.method == 'POST':
        raw = request.POST.get('ip_list', '')
        lines = [l.strip() for l in raw.splitlines() if l.strip()]

        if not lines:
            messages.warning(request, "No IP addresses provided.")
            return _wl_redirect()

        added = skipped = errors = 0
        added_cidrs = []
        skipped_cidrs = []
        error_lines = []
        auto_deactivated = []
        client_ip = getattr(request, 'client_ip', '')

        for line in lines[:500]:
            if not is_valid_ip_or_cidr(line):
                errors += 1
                error_lines.append(line)
                continue
            try:
                cidr, ip, prefix = normalize_cidr(line)
            except ValueError:
                errors += 1
                error_lines.append(line)
                continue
            if WhitelistEntry.objects.filter(cidr=cidr).exists():
                skipped += 1
                skipped_cidrs.append(cidr)
            else:
                entry = WhitelistEntry.objects.create(
                    cidr=cidr, ip_address=ip, prefix_length=prefix,
                    reason=request.POST.get('reason', '').strip(),
                    added_by=request.user,
                    source=WhitelistEntry.SOURCE_MANUAL,
                )
                added += 1
                added_cidrs.append(cidr)
                auto_deactivated.extend(
                    _deactivate_blacklist_overlaps(cidr, request.user, client_ip)
                )

        ActivityLog.log(request.user, 'whitelist.bulk_add', 'WhitelistEntry', None,
                     {
                         'added': added,
                         'skipped': skipped,
                         'errors': errors,
                         'blacklist_deactivated': len(auto_deactivated),
                         'added_cidrs': added_cidrs,
                         'skipped_cidrs': skipped_cidrs,
                         'error_lines': error_lines,
                         'blacklist_deactivated_cidrs': auto_deactivated,
                     },
                     client_ip)

        msg = f"Bulk add complete: {added} added, {skipped} duplicates skipped"
        if errors:
            msg += f", {errors} invalid"
        messages.success(request, msg + ".")

        if auto_deactivated:
            count = len(auto_deactivated)
            cidrs = ', '.join(auto_deactivated[:10])
            suffix = f' and {count - 10} more' if count > 10 else ''
            messages.warning(
                request,
                f"{count} blacklist entr{'y' if count == 1 else 'ies'} deactivated because "
                f"{'it overlaps' if count == 1 else 'they overlap'} with the new whitelist "
                f"entries ({cidrs}{suffix})."
            )

    return _wl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def whitelist_edit(request, entry_id):
    entry = get_object_or_404(WhitelistEntry, pk=entry_id)

    if request.method == 'POST':
        ip_input = request.POST.get('ip_input', '').strip()
        reason = request.POST.get('reason', '').strip()

        if not is_valid_ip_or_cidr(ip_input):
            messages.error(request, f"'{ip_input}' is not a valid IP address or CIDR notation.")
        else:
            cidr, ip, prefix = normalize_cidr(ip_input)
            existing = WhitelistEntry.objects.filter(cidr=cidr).exclude(pk=entry.pk).first()
            if existing:
                messages.error(request, f"{cidr} already exists in the whitelist.")
            else:
                old_cidr   = entry.cidr
                old_reason = entry.reason or ''
                entry.cidr = cidr
                entry.ip_address = ip
                entry.prefix_length = prefix
                entry.reason = reason
                entry.save()
                ActivityLog.log(request.user, 'whitelist.edit', 'WhitelistEntry', str(entry.pk),
                             {
                                 'old_cidr':   old_cidr,    'new_cidr':   cidr,
                                 'old_reason': old_reason,  'new_reason': reason or '',
                             }, getattr(request, 'client_ip', ''))
                messages.success(request, f"Whitelist entry updated to {cidr}.")

    return redirect('whitelist:list')


@login_required_custom
@role_required('admin', 'operator')
def whitelist_import_csv(request):
    if request.method == 'POST':
        csv_file = request.FILES.get('csv_file')
        if not csv_file or not csv_file.name.endswith('.csv'):
            messages.error(request, "Please upload a valid .csv file.")
            return redirect('whitelist:list')

        try:
            decoded = csv_file.read().decode('utf-8-sig').splitlines()
        except UnicodeDecodeError:
            messages.error(request, "File encoding not supported. Please use UTF-8.")
            return redirect('whitelist:list')

        # Non-empty lines
        lines = [l for l in decoded if l.strip()]
        if not lines:
            messages.error(request, "CSV file is empty.")
            return redirect('whitelist:list')

        IP_COLS     = ['cidr', 'ip', 'ip_address', 'address', 'network', 'subnet']
        REASON_COLS = ['reason', 'description', 'note', 'comment']

        # Detect whether the first row is a header or raw IP data
        first_line_is_ip = is_valid_ip_or_cidr(lines[0].split(',')[0].strip())

        added = skipped = errors = 0
        added_cidrs = []
        skipped_cidrs = []
        error_lines = []
        auto_deactivated = []
        client_ip = getattr(request, 'client_ip', '')

        if first_line_is_ip:
            # No-header mode: each line is an IP/CIDR, optionally comma-separated with reason
            for i, line in enumerate(lines, start=1):
                parts = [p.strip() for p in line.split(',')]
                cidr_raw = parts[0] if parts else ''
                reason = parts[1] if len(parts) > 1 else ''
                if not cidr_raw:
                    errors += 1
                    error_lines.append(f'row {i}: empty')
                    continue
                try:
                    cidr, ip, prefix = normalize_cidr(cidr_raw)
                except ValueError:
                    errors += 1
                    error_lines.append(f'row {i}: {cidr_raw}')
                    logger.warning(f"CSV import row {i}: invalid CIDR '{cidr_raw}'")
                    continue
                if WhitelistEntry.objects.filter(cidr=cidr).exists():
                    skipped += 1
                    skipped_cidrs.append(cidr)
                else:
                    WhitelistEntry.objects.create(
                        cidr=cidr, ip_address=ip, prefix_length=prefix,
                        reason=reason, added_by=request.user,
                        source=WhitelistEntry.SOURCE_IMPORT,
                    )
                    added += 1
                    added_cidrs.append(cidr)
                    auto_deactivated.extend(
                        _deactivate_blacklist_overlaps(cidr, request.user, client_ip)
                    )
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
                cidr_raw = pick(row, IP_COLS)
                if not cidr_raw:
                    cidr_raw = next(
                        (v.strip() for v in row.values() if isinstance(v, str) and v.strip()),
                        ''
                    )
                reason = pick(row, REASON_COLS)
                if not cidr_raw:
                    errors += 1
                    error_lines.append(f'row {i}: empty')
                    continue
                try:
                    cidr, ip, prefix = normalize_cidr(cidr_raw)
                except ValueError:
                    errors += 1
                    error_lines.append(f'row {i}: {cidr_raw}')
                    logger.warning(f"CSV import row {i}: invalid CIDR '{cidr_raw}'")
                    continue
                if WhitelistEntry.objects.filter(cidr=cidr).exists():
                    skipped += 1
                    skipped_cidrs.append(cidr)
                else:
                    WhitelistEntry.objects.create(
                        cidr=cidr, ip_address=ip, prefix_length=prefix,
                        reason=reason, added_by=request.user,
                        source=WhitelistEntry.SOURCE_IMPORT,
                    )
                    added += 1
                    added_cidrs.append(cidr)
                    auto_deactivated.extend(
                        _deactivate_blacklist_overlaps(cidr, request.user, client_ip)
                    )

        ActivityLog.log(request.user, 'whitelist.import_csv', 'WhitelistEntry', None,
                     {
                         'added': added,
                         'skipped': skipped,
                         'errors': errors,
                         'blacklist_deactivated': len(auto_deactivated),
                         'added_cidrs': added_cidrs,
                         'skipped_cidrs': skipped_cidrs,
                         'error_lines': error_lines,
                         'blacklist_deactivated_cidrs': auto_deactivated,
                     },
                     client_ip)

        messages.success(request, f"CSV import complete: {added} added, {skipped} duplicates skipped, {errors} errors.")
        if auto_deactivated:
            count = len(auto_deactivated)
            cidrs = ', '.join(auto_deactivated[:10])
            suffix = f' and {count - 10} more' if count > 10 else ''
            messages.warning(
                request,
                f"{count} blacklist entr{'y' if count == 1 else 'ies'} deactivated because "
                f"{'it overlaps' if count == 1 else 'they overlap'} with the imported whitelist "
                f"entries ({cidrs}{suffix})."
            )
    return redirect('whitelist:list')


@login_required_custom
@role_required('admin', 'operator')
def whitelist_bulk_delete(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _wl_redirect(status)

        client_ip = getattr(request, 'client_ip', '')
        entries = list(WhitelistEntry.objects.filter(pk__in=ids))
        cidrs = [e.cidr for e in entries]
        count = len(entries)

        for entry in entries:
            ActivityLog.log(request.user, 'whitelist.delete', 'WhitelistEntry', str(entry.pk),
                         {'cidr': entry.cidr}, client_ip)
        WhitelistEntry.objects.filter(pk__in=ids).delete()

        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} removed from whitelist.")

        all_reactivated = []
        for cidr in cidrs:
            all_reactivated.extend(_reactivate_blacklist_overlaps(cidr, request.user, client_ip))
        _notify_reactivated(request, all_reactivated)

        return _wl_redirect(status)
    return _wl_redirect()


@login_required_custom
def whitelist_export(request):
    entries = WhitelistEntry.objects.all().order_by('cidr')
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status', 'active')
    if search:
        q = Q(cidr__icontains=search) | Q(reason__icontains=search)
        if search.isdigit():
            q |= Q(pk=int(search))
        entries = entries.filter(q)
    if status == 'active':
        entries = entries.filter(is_active=True)
    elif status == 'inactive':
        entries = entries.filter(is_active=False)
    # status == 'all' → no additional filter
    status_label = status if status in ('active', 'inactive', 'all') else 'active'

    from django.utils import timezone
    ts = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
    response = HttpResponse(content_type='text/csv')
    from apps.settings_app.branding import brand_filename_prefix
    response['Content-Disposition'] = f'attachment; filename="{brand_filename_prefix()}_whitelist_{status_label}_{ts}.csv"'
    from apps.settings_app.csv_util import safe_row
    writer = csv.writer(response)
    writer.writerow(['CIDR', 'Prefix Length', 'Reason', 'Added By', 'Added At'])
    for entry in entries:
        writer.writerow(safe_row([
            entry.cidr,
            entry.prefix_length,
            entry.reason,
            entry.added_by.username if entry.added_by else '',
            timezone.localtime(entry.added_at).strftime('%Y-%m-%d %H:%M:%S'),
        ]))
    return response


@login_required_custom
@role_required('admin', 'operator')
def whitelist_delete(request, entry_id):
    entry = get_object_or_404(WhitelistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')

    if request.method == 'POST':
        cidr = entry.cidr
        client_ip = getattr(request, 'client_ip', '')
        entry.delete()
        ActivityLog.log(request.user, 'whitelist.delete', 'WhitelistEntry', str(entry_id),
                     {'cidr': cidr}, client_ip)
        messages.success(request, f"{cidr} removed from whitelist.")
        reactivated = _reactivate_blacklist_overlaps(cidr, request.user, client_ip)
        _notify_reactivated(request, reactivated)

    return _wl_redirect(status)


@login_required_custom
@role_required('admin', 'operator')
def whitelist_deactivate_single(request, entry_id):
    entry = get_object_or_404(WhitelistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')

    if request.method == 'POST':
        cidr = entry.cidr
        client_ip = getattr(request, 'client_ip', '')
        entry.is_active = False
        entry.save(update_fields=['is_active'])
        ActivityLog.log(request.user, 'whitelist.deactivate', 'WhitelistEntry', str(entry.pk),
                     {'cidr': cidr}, client_ip)
        messages.success(request, f"{cidr} deactivated.")
        reactivated = _reactivate_blacklist_overlaps(cidr, request.user, client_ip)
        _notify_reactivated(request, reactivated)

    return _wl_redirect(status)


@login_required_custom
@role_required('admin', 'operator')
def whitelist_activate_single(request, entry_id):
    entry = get_object_or_404(WhitelistEntry, pk=entry_id)
    status = request.POST.get('status', 'active')

    if request.method == 'POST':
        cidr = entry.cidr
        client_ip = getattr(request, 'client_ip', '')
        entry.is_active = True
        entry.save(update_fields=['is_active'])
        ActivityLog.log(request.user, 'whitelist.activate', 'WhitelistEntry', str(entry.pk),
                     {'cidr': cidr}, client_ip)
        messages.success(request, f"{cidr} activated.")
        deactivated = _deactivate_blacklist_overlaps(cidr, request.user, client_ip)
        if deactivated:
            count = len(deactivated)
            cidrs = ', '.join(deactivated[:10])
            suffix = f' and {count - 10} more' if count > 10 else ''
            messages.warning(
                request,
                f"{count} blacklist entr{'y' if count == 1 else 'ies'} deactivated because "
                f"{'it overlaps' if count == 1 else 'they overlap'} with the activated whitelist "
                f"entry ({cidrs}{suffix})."
            )

    return _wl_redirect(status)


@login_required_custom
@role_required('admin', 'operator')
def whitelist_bulk_deactivate(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _wl_redirect(status)

        client_ip = getattr(request, 'client_ip', '')
        # Collect CIDRs before update so we can reactivate overlapping blacklist entries
        cidrs = list(WhitelistEntry.objects.filter(pk__in=ids).values_list('cidr', flat=True))
        count = WhitelistEntry.objects.filter(pk__in=ids).update(is_active=False)
        ActivityLog.log(request.user, 'whitelist.bulk_deactivate', 'WhitelistEntry', None,
                     {'count': count}, client_ip)
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} deactivated.")

        all_reactivated = []
        for cidr in cidrs:
            all_reactivated.extend(_reactivate_blacklist_overlaps(cidr, request.user, client_ip))
        _notify_reactivated(request, all_reactivated)

        return _wl_redirect(status)
    return _wl_redirect()


@login_required_custom
@role_required('admin', 'operator')
def whitelist_bulk_activate(request):
    if request.method == 'POST':
        status = request.POST.get('status', 'active')
        ids = request.POST.getlist('entry_ids')
        if not ids:
            messages.warning(request, "No entries selected.")
            return _wl_redirect(status)

        client_ip = getattr(request, 'client_ip', '')
        cidrs = list(WhitelistEntry.objects.filter(pk__in=ids).values_list('cidr', flat=True))
        count = WhitelistEntry.objects.filter(pk__in=ids).update(is_active=True)
        ActivityLog.log(request.user, 'whitelist.bulk_activate', 'WhitelistEntry', None,
                     {'count': count}, client_ip)
        messages.success(request, f"{count} entr{'y' if count == 1 else 'ies'} activated.")

        all_deactivated = []
        for cidr in cidrs:
            all_deactivated.extend(_deactivate_blacklist_overlaps(cidr, request.user, client_ip))
        if all_deactivated:
            dc = len(all_deactivated)
            dc_cidrs = ', '.join(all_deactivated[:10])
            suffix = f' and {dc - 10} more' if dc > 10 else ''
            messages.warning(
                request,
                f"{dc} blacklist entr{'y' if dc == 1 else 'ies'} deactivated because "
                f"{'it overlaps' if dc == 1 else 'they overlap'} with the activated whitelist "
                f"entries ({dc_cidrs}{suffix})."
            )

        return _wl_redirect(status)
    return _wl_redirect()


# ── PDF Report ─────────────────────────────────────────────────────────────
@login_required_custom
@role_required('admin', 'operator')
def whitelist_pdf_report(request):
    from apps.reports.pdf_generator import generate_whitelist_executive

    entries = WhitelistEntry.objects.select_related('added_by').all()
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

    filters = {'date_preset': date_preset, 'date_from': date_from,
                'date_to': date_to, 'status': status}
    ts = timezone.localtime(now).strftime('%Y%m%d_%H%M%S')

    _full = request.user.get_full_name()
    _generated_by = f'{request.user.username} ({_full})' if _full else request.user.username
    pdf_bytes = generate_whitelist_executive(entries, filters, _generated_by)
    from apps.settings_app.branding import brand_filename_prefix
    filename = f'{brand_filename_prefix()}_whitelist_{status}_{ts}.pdf'

    ActivityLog.log(request.user, 'report.download', 'WhitelistEntry', None,
                    {'report_type': 'whitelist', 'status': status,
                     'date_preset': date_preset, 'filename': filename},
                    getattr(request, 'client_ip', ''))
    resp = HttpResponse(pdf_bytes, content_type='application/pdf')
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp
