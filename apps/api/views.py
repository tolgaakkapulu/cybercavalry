import json
import logging
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Q

from .auth import authenticate_token, check_source_ip, get_client_ip, check_rate_limit
from apps.blacklist.models import BlacklistEntry, BlacklistGroup
from apps.blacklist.utils import normalize_cidr, is_valid_ip_or_cidr, filter_whitelisted
from apps.settings_app.models import ActivityLog
from apps.settings_app.cache import SettingsCache

logger = logging.getLogger(__name__)


_MAX_BODY_BYTES = 4 * 1024   # 4 KB — more than enough for an IP + reason


def json_error(message, status=400):
    return JsonResponse({'error': message}, status=status)


def _log_api_request(request):
    """Emit a one-line log entry for every incoming API request — runs at the
    very top of each view so even auth, rate-limit, and validation failures are
    visible in the log. Format:

        API REQ <METHOD> <path> | ip=<client> | user=<X-Username|'anon'> | body=<json>

    For POST/PUT the JSON body is included (whitespace collapsed, capped at 2 KB).
    For GET the query string (if any) is shown after a leading '?'.
    """
    body = ''
    try:
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            raw = request.body or b''
            body = ' '.join(raw.decode('utf-8', errors='replace').split())[:2048]
        elif request.META.get('QUERY_STRING'):
            body = '?' + request.META['QUERY_STRING'][:512]
    except Exception:
        body = '<unreadable>'
    user = request.META.get('HTTP_X_USERNAME', 'anon')
    try:
        ip = get_client_ip(request)
    except Exception:
        ip = '?'
    logger.info("API REQ %s %s | ip=%s | user=%s | body=%s",
                request.method, request.path, ip, user, body or '-')


def _api_request_context(request):
    """Structured version of the file-log line for the ActivityLog detail dict.
    Same fields as _log_api_request but returned instead of logged, so each
    endpoint's ActivityLog entry carries the full request context (method,
    path, query/body, header-declared username) alongside its business result."""
    body = ''
    try:
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            raw = request.body or b''
            body = ' '.join(raw.decode('utf-8', errors='replace').split())[:2048]
        elif request.META.get('QUERY_STRING'):
            body = '?' + request.META['QUERY_STRING'][:512]
    except Exception:
        body = '<unreadable>'
    return {
        'method':      request.method,
        'path':        request.path,
        'body':        body or '-',
        'req_user':    request.META.get('HTTP_X_USERNAME', 'anon'),
        'user_agent':  (request.META.get('HTTP_USER_AGENT', '') or '')[:200],
    }


@csrf_exempt
@require_http_methods(["POST"])
def report_ip(request):
    """
    POST /api/v1/report/ip/
    Add an IP/CIDR to the 24h and 30d blacklists.
    Requires: Token auth + source IP allowlist.
    """
    _log_api_request(request)
    # Token + username authentication
    profile = authenticate_token(request)
    if profile is None:
        return json_error(
            "Authentication failed. Provide both 'Authorization: Token <token>' "
            "and 'X-Username: <username>' headers with valid, matching credentials.",
            status=401
        )

    # Rate limiting (per-token + burst + per-IP)
    limit_rpm = SettingsCache.get('api.rate_limit_rpm', 60)
    _client_ip = get_client_ip(request)
    if not check_rate_limit(profile.api_token_hash or '', limit_rpm, client_ip=_client_ip):
        ActivityLog.log(
            profile.user, 'api.rate_limit', 'API', '/api/v1/report/ip/',
            {'endpoint': '/api/v1/report/ip/', 'limit_rpm': limit_rpm, 'client_ip': _client_ip},
            _client_ip,
        )
        logger.warning(f"Rate limit exceeded: user={profile.user.username} ip={_client_ip} endpoint=/api/v1/report/ip/")
        return json_error("Rate limit exceeded.", status=429)

    # Source IP check
    if not check_source_ip(request):
        logger.warning(f"API report blocked: source IP {_client_ip} not in allowed list")
        return json_error("Source IP not authorized.", status=403)

    # Reject oversized bodies before parsing (DoS / resource exhaustion guard)
    if len(request.body) > _MAX_BODY_BYTES:
        return json_error(
            f"Request body too large (max {_MAX_BODY_BYTES} bytes).", status=413
        )

    # Parse request body
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return json_error("Invalid JSON body.")

    ip_input = data.get('ip') or data.get('cidr', '')
    reason = data.get('reason', 'API report')

    if not ip_input:
        return json_error("'ip' field is required.")

    if not is_valid_ip_or_cidr(ip_input):
        return json_error(f"'{ip_input}' is not a valid IP address or CIDR.")

    cidr, ip, prefix = normalize_cidr(ip_input)
    if prefix != 32:
        return json_error(
            f"Only single IP addresses (/32) are accepted. "
            f"'{ip_input}' is a CIDR block. Submit individual IPs."
        )

    reporter_ip = get_client_ip(request)

    # Check whitelist
    from apps.whitelist.models import WhitelistEntry
    import ipaddress as _ipmod
    whitelist_cidrs = list(WhitelistEntry.objects.filter(is_active=True).values_list('cidr', flat=True))
    try:
        target_net = _ipmod.ip_network(cidr, strict=False)
        for wl_cidr in whitelist_cidrs:
            if target_net.overlaps(_ipmod.ip_network(wl_cidr, strict=False)):
                logger.debug(f"API report: {cidr} is whitelisted, skipping")
                return JsonResponse({'status': 'whitelisted', 'cidr': cidr, 'action': 'skipped'}, status=200)
    except ValueError:
        pass

    # Query AbuseIPDB with 30s timeout to get score AND the full enrichment
    # payload (ISP, country, hostnames, ASN, totalReports, lastReportedAt …)
    # so the entry has the same metadata an in-UI "Rescore" would produce.
    from apps.blacklist.abuseipdb_service import (
        fetch_ip_data_with_timeout, _resolve_group_by_score, _apply_score_to_entry,
    )
    score = None
    ip_data = None
    group = None
    if SettingsCache.get('threat_intel.abuseipdb_enabled', False):
        ip_data = fetch_ip_data_with_timeout(ip, timeout=30)
        if ip_data is not None:
            score = ip_data.get('abuseConfidenceScore')

    if score is not None:
        group = _resolve_group_by_score(score)
        # score < 10 → _resolve_group_by_score returns None → goes to no_group then deactivated below

    if group is None:
        # Timeout, disabled, or score < 10 → place in no_group (unpublished)
        try:
            group = BlacklistGroup.objects.get(name='no_group')
        except BlacklistGroup.DoesNotExist:
            logger.error("BlacklistGroup 'no_group' not found. Run migrations or re-seed initial data.")
            return json_error(
                "Server configuration error: 'no_group' blacklist group is missing. "
                "Please contact the administrator.",
                status=500,
            )

    now = timezone.now()

    # Look up by CIDR alone — every IP must collapse to at most one row across
    # all groups and both active states. Earlier versions keyed on (cidr, group)
    # so the same IP could end up with one row in 24h and another in 30d once
    # its AbuseIPDB score moved over time.
    existing = list(BlacklistEntry.objects.filter(cidr=cidr).order_by('-added_at'))

    if existing:
        # Prefer the row already in the target group so we don't reassign the
        # FK unnecessarily; otherwise take the most-recent row and move it.
        # Any extra duplicate rows (legacy data) are deleted to enforce
        # "one row per IP" going forward.
        entry = next((e for e in existing if e.group_id == group.id), existing[0])
        for stale in existing:
            if stale.id != entry.id:
                stale.delete()
        entry.group = group
        entry.is_active = True
        entry.hit_count += 1
        entry.record_recent_hit(when=now)
        entry.last_seen_at = now
        # Replace the reason with the latest report's value so the record
        # reflects the most recent context. Defaults to 'API report' upstream
        # if the caller omits the field, matching the create-path default.
        entry.reason = reason
        # Bump added_at to the latest report time so the entry's "Added" column
        # reflects the most recent activity (the field is auto_now_add, which
        # only triggers on the initial INSERT — manual assignment on UPDATE
        # persists). This also lifts the row to the top of -added_at lists.
        entry.added_at = now

        entry.set_expiry_from_group()
        entry.save()
        # Promotion (24h → 30d based on hit_count threshold) is applied inside
        # _apply_score_to_entry below, so it survives the score-based group
        # re-resolution and also fires from bulk_refresh / manual rescore.
        action = 'updated'
        message = 'Existing blacklist entry refreshed with the latest AbuseIPDB data.'
        status_code = 200
    else:
        # New IP — block creation if a broader CIDR already covers it.
        from apps.blacklist.utils import check_blacklist_overlap
        matched_bl = check_blacklist_overlap(cidr, group, exclude_cidr=cidr)
        if matched_bl:
            # Logged under a distinct action so dashboard's success counter ignores it.
            ActivityLog.log(profile.user, 'api.report.skipped', 'BlacklistEntry', cidr,
                         {'cidr': cidr, 'action': 'skipped', 'reason': f'overlaps {matched_bl}',
                          'reporter_ip': reporter_ip}, reporter_ip)
            return JsonResponse({
                'status': 'skipped',
                'cidr': cidr,
                'action': 'skipped',
                'reason': f'overlaps with existing entry {matched_bl}',
                'message': f'Skipped — already covered by broader entry {matched_bl}.',
            }, status=200)

        entry = BlacklistEntry.objects.create(
            cidr=cidr, group=group,
            ip_address=ip, prefix_length=prefix, reason=reason,
            source=BlacklistEntry.SOURCE_API, added_by=profile.user,
            reporter_ip=reporter_ip,
        )
        entry.record_recent_hit(when=now)
        entry.set_expiry_from_group()
        entry.save()
        action = 'blacklisted'
        message = 'New blacklist entry created.'
        status_code = 201

    # If score was already retrieved, apply it (saves another API call) — also
    # store the full AbuseIPDB enrichment so the entry has ISP/country/hostnames
    # right away instead of waiting for a manual rescore.
    if score is not None:
        _apply_score_to_entry(entry, score, now, meta=ip_data)
        entry.refresh_from_db()

    ActivityLog.log(profile.user, 'api.report', 'BlacklistEntry', cidr,
                 {'cidr': cidr, 'group': entry.group.name, 'score': score,
                  'action': action, 'reporter_ip': reporter_ip,
                  **_api_request_context(request)}, reporter_ip)

    return JsonResponse({
        'status': 'blacklisted',
        'cidr': cidr,
        'group': entry.group.name,
        'group_label': entry.group.label,
        'abuse_confidence_score': score,
        'action': action,
        'message': message,
        'expires_at': entry.expires_at.isoformat() if entry.expires_at else None,
    }, status=status_code)


@require_http_methods(["GET"])
def get_blacklist(request, group_filter=None):
    """
    GET /api/v1/blacklist/
    GET /api/v1/blacklist/24h/
    GET /api/v1/blacklist/30d/

    Returns the published blacklist, excluding whitelisted IPs.
    Supports ?format=txt for firewall-friendly plain text output.

    Auth: source IP allowlist only — no token or username required.
    Firewall/SIEM systems can pull the list without managing API credentials.
    """
    _log_api_request(request)
    client_ip = get_client_ip(request)

    # Source IP check — only auth mechanism for blacklist reads
    if not check_source_ip(request):
        logger.warning(f"API blacklist blocked: source IP {client_ip} not in allowed list")
        return json_error("Source IP not authorized.", status=403)

    # Build queryset
    entries = BlacklistEntry.objects.filter(
        is_active=True,
        group__is_published=True,
    ).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    ).select_related('group')

    if group_filter:
        entries = entries.filter(group__name=group_filter)

    # Filter whitelisted
    entries_list = list(entries)
    entries_list = filter_whitelisted(entries_list)

    output_format = request.GET.get('format', 'json')

    ActivityLog.log(None, 'api.blacklist', 'BlacklistEntry', group_filter or 'all',
                 {'count': len(entries_list), 'format': output_format, 'source_ip': client_ip,
                  **_api_request_context(request)}, client_ip)

    if output_format == 'txt':
        # Use the stored CIDR (`ip/prefix`) so single-IP rows ship as `x.x.x.x/32`
        # and CIDR-block rows keep their original prefix — both forms are what
        # firewalls / SIEM scripts expect when ingesting the list.
        lines = [e.cidr for e in entries_list]
        response = HttpResponse('\n'.join(lines), content_type='text/plain')
        response['Cache-Control'] = 'max-age=300'
        return response

    # JSON format with pagination
    try:
        page = max(1, int(request.GET.get('page', 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        page_size = min(max(1, int(request.GET.get('page_size', 1000))), 5000)
    except (ValueError, TypeError):
        page_size = 1000
    start = (page - 1) * page_size
    end = start + page_size
    page_entries = entries_list[start:end]

    data = {
        'count': len(entries_list),
        'page': page,
        'page_size': page_size,
        'generated_at': timezone.now().isoformat(),
        'entries': [
            {
                'ip': e.ip_address,
                'group': e.group.name,
                'added_at': e.added_at.isoformat(),
                'expires_at': e.expires_at.isoformat() if e.expires_at else None,
            }
            for e in page_entries
        ],
    }
    response = JsonResponse(data)
    response['Cache-Control'] = 'max-age=300'
    return response


@csrf_exempt
@require_http_methods(["POST"])
def report_hash(request):
    """
    POST /api/v1/report/hash/
    Add a hash to the blacklist.
    Requires: Token auth + source IP allowlist.
    Body: {"hash": "<hex>", "reason": "<optional>"}
    """
    _log_api_request(request)
    profile = authenticate_token(request)
    if profile is None:
        return json_error(
            "Authentication failed. Provide both 'Authorization: Token <token>' "
            "and 'X-Username: <username>' headers with valid, matching credentials.",
            status=401
        )

    limit_rpm = SettingsCache.get('api.rate_limit_rpm', 60)
    _client_ip = get_client_ip(request)
    if not check_rate_limit(profile.api_token_hash or '', limit_rpm, client_ip=_client_ip):
        ActivityLog.log(
            profile.user, 'api.rate_limit', 'API', '/api/v1/report/hash/',
            {'endpoint': '/api/v1/report/hash/', 'limit_rpm': limit_rpm, 'client_ip': _client_ip},
            _client_ip,
        )
        logger.warning(f"Rate limit exceeded: user={profile.user.username} ip={_client_ip} endpoint=/api/v1/report/hash/")
        return json_error("Rate limit exceeded.", status=429)

    if not check_source_ip(request):
        client_ip = get_client_ip(request)
        logger.warning(f"API hash report blocked: source IP {client_ip} not in allowed list")
        return json_error("Source IP not authorized.", status=403)

    if len(request.body) > _MAX_BODY_BYTES:
        return json_error(f"Request body too large (max {_MAX_BODY_BYTES} bytes).", status=413)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return json_error("Invalid JSON body.")

    hash_input = (data.get('hash') or '').strip()
    reason = data.get('reason', 'API report')

    if not hash_input:
        return json_error("'hash' field is required.")

    from apps.hashlist.models import HashEntry, is_valid_hash, normalize_hash
    if not is_valid_hash(hash_input):
        return json_error(
            f"'{hash_input}' is not a valid hash. "
            "Accepted formats: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128) hex characters."
        )

    hash_value, hash_type = normalize_hash(hash_input)
    client_ip = get_client_ip(request)

    # Look up by hash_value alone within the blacklist — unique_together
    # ('hash_value', 'list_type') already prevents duplicates here, so the same
    # hash always collapses to one row whether previously active or inactive.
    entry, created = HashEntry.objects.get_or_create(
        hash_value=hash_value,
        list_type=HashEntry.LIST_BLACK,
        defaults={
            'hash_type': hash_type,
            'reason': reason,
            'source': HashEntry.SOURCE_API,
            'added_by': profile.user,
            'is_active': True,
        }
    )

    if not created:
        # Existing record -- respect whatever state it's already in. We do NOT:
        #   * reactivate  -- a deactivation was either an explicit admin call
        #                    or a VT-threshold decision; re-reporting the same
        #                    hash must not override that verdict.
        #   * update reason / added_at -- keeping the row byte-identical avoids
        #                    the "did VT get re-queried at 17:52?" confusion
        #                    caused by timestamps that only reflect the last
        #                    report, not the last real state change.
        # The report is still recorded in ActivityLog below for audit.
        action = 'existing'
        _prior_state = 'active' if entry.is_active else 'inactive'
        _prior_vt = (
            f"{entry.vt_malicious}/{entry.vt_total}" if entry.vt_checked_at
            else ('N/A' if entry.vt_unavailable else 'never-scored')
        )
        response_message = (
            f'Hash already tracked (currently {_prior_state}, VT={_prior_vt}) -- no changes made.'
        )
        # This log line is the ground-truth signal that the no-op path was
        # taken. If a supposedly-inactive record gets reactivated after this,
        # something OTHER than this endpoint did it (scheduler bulk_refresh,
        # admin panel, manual scoring, etc.) -- grep the logs for the hash to
        # find out which.
        logger.info(
            "API hash report NO-OP: hash=%s state=%s vt=%s (no reactivation, no VT query)",
            hash_value[:16], _prior_state, _prior_vt,
        )
    else:
        action = 'added'
        response_message = 'New hash blacklist entry created.'
        logger.info(
            "API hash report NEW: hash=%s -- created as is_active=True (will be scored by VT if enabled)",
            hash_value[:16],
        )

    # ── VirusTotal auto-check ────────────────────────────────────
    # Only hit VT for genuinely NEW entries. Existing rows already carry a
    # score from their first insertion (and are periodically refreshed by the
    # scheduler) -- re-querying VT on every duplicate report just burns quota.
    # Pull the full attributes dict (not just the score) so threat label, file
    # type, size, name, first/last analysis, times_submitted etc. populate on
    # the entry without needing a manual rescore.
    vt_result = None
    vt_unavailable = False
    if created and SettingsCache.get('threat_intel.virustotal_enabled', False) and \
            SettingsCache.get('threat_intel.virustotal_auto_check', False):
        from apps.hashlist.virustotal_service import (
            fetch_hash_data_with_timeout, _stats_from_attrs, _apply_score_to_entry,
        )
        from django.utils import timezone as _tz
        vt_attrs = fetch_hash_data_with_timeout(hash_value, timeout=30)
        if vt_attrs is not None:
            malicious, total = _stats_from_attrs(vt_attrs)
            vt_result = (malicious, total)
            entry.refresh_from_db()
            _apply_score_to_entry(entry, malicious, total, _tz.now(), meta=vt_attrs)
            entry.refresh_from_db()
            logger.info(
                "API hash report VT check: hash=%s malicious=%d/%d is_active=%s",
                hash_value[:16], malicious, total, entry.is_active,
            )
        else:
            # VT was expected to answer (auto-check on) but didn't -- timeout,
            # quota, network. Flag the entry so it stays visible in the admin
            # console but is hidden from /api/v1/hashlist/ downstream feed.
            # Cleared automatically by _apply_score_to_entry once a real score
            # arrives (via scheduled refresh or a manual rescore).
            entry.vt_unavailable = True
            entry.save(update_fields=['vt_unavailable'])
            vt_unavailable = True
            logger.warning(
                "API hash report: VT unavailable for hash=%s -- flagged (hidden from /api/v1/hashlist/)",
                hash_value[:16],
            )

    ActivityLog.log(
        profile.user, 'api.hash_report', 'HashEntry', hash_value,
        {
            'hash': hash_value,
            'hash_type': hash_type,
            'action': action,                     # 'added' | 'existing'
            'is_active_after': entry.is_active,   # ground-truth final state
            'reporter_ip': client_ip,
            **(
                {'vt_malicious': vt_result[0], 'vt_total': vt_result[1]}
                if vt_result is not None else {}
            ),
            **({'vt_unavailable': True} if vt_unavailable else {}),
            **_api_request_context(request),
        },
        client_ip
    )

    response_data = {
        # 'blacklisted' when the hash IS currently active in the blacklist;
        # 'inactive' when the record exists but is deactivated (below VT
        # threshold, manually disabled, or was never reactivated on report).
        'status': 'blacklisted' if entry.is_active else 'inactive',
        'hash': hash_value,
        'hash_type': hash_type,
        'action': action,
        'message': response_message,
        'is_active': entry.is_active,
    }
    if vt_result is not None:
        response_data['virustotal'] = {
            'malicious': vt_result[0],
            'total': vt_result[1],
            'threshold': max(0, int(SettingsCache.get('threat_intel.virustotal_detection_threshold', 5) or 5)),
        }
    elif vt_unavailable:
        response_data['virustotal'] = {'status': 'unavailable'}
    return JsonResponse(response_data, status=201 if action == 'added' else 200)


@require_http_methods(["GET"])
def get_hashlist(request):
    """
    GET /api/v1/hashlist/

    Returns active blacklisted hashes.
    Auth: source IP allowlist only (same as blacklist reads).
    Supports ?format=txt for plain-text output (one hash per line).
    Supports ?page and ?page_size for pagination (default 1000, max 5000).
    """
    _log_api_request(request)
    client_ip = get_client_ip(request)
    if not check_source_ip(request):
        logger.warning(f"API hashlist blocked: source IP {client_ip} not in allowed list")
        return json_error("Source IP not authorized.", status=403)

    from apps.hashlist.models import HashEntry
    # vt_unavailable=False hides entries where VT couldn't be reached at
    # insert time -- those stay visible in the admin console (still is_active)
    # but never leak into the downstream feed without a real VT verdict.
    entries = list(
        HashEntry.objects.filter(is_active=True, list_type='black', vt_unavailable=False)
        .order_by('hash_type', 'hash_value')
    )

    output_format = request.GET.get('format', 'json')
    ActivityLog.log(None, 'api.hashlist', 'HashEntry', 'black',
                 {'count': len(entries), 'format': output_format, 'source_ip': client_ip,
                  **_api_request_context(request)}, client_ip)

    if output_format == 'txt':
        lines = [e.hash_value for e in entries]
        response = HttpResponse('\n'.join(lines), content_type='text/plain')
        response['Cache-Control'] = 'max-age=300'
        return response

    try:
        page = max(1, int(request.GET.get('page', 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        page_size = min(max(1, int(request.GET.get('page_size', 1000))), 5000)
    except (ValueError, TypeError):
        page_size = 1000
    start = (page - 1) * page_size
    page_entries = entries[start:start + page_size]

    data = {
        'count':        len(entries),
        'page':         page,
        'page_size':    page_size,
        'generated_at': timezone.now().isoformat(),
        'entries': [
            {
                'hash':      e.hash_value,
                'hash_type': e.hash_type,
                'added_at':  e.added_at.isoformat(),
            }
            for e in page_entries
        ],
    }
    response = JsonResponse(data)
    response['Cache-Control'] = 'max-age=300'
    return response


@require_http_methods(["GET"])
def api_status(request):
    """GET /api/v1/status/ — Health check. Requires token + username auth and source IP."""
    _log_api_request(request)
    if not check_source_ip(request):
        client_ip = get_client_ip(request)
        logger.warning(f"API status blocked: source IP {client_ip} not in allowed list")
        return json_error("Source IP not authorized.", status=403)

    profile = authenticate_token(request)
    if profile is None:
        return json_error(
            "Authentication failed. Provide both 'Authorization: Token <token>' "
            "and 'X-Username: <username>' headers with valid, matching credentials.",
            status=401
        )

    limit_rpm = SettingsCache.get('api.rate_limit_rpm', 60)
    _client_ip_status = get_client_ip(request)
    if not check_rate_limit(profile.api_token_hash or '', limit_rpm, client_ip=_client_ip_status):
        ActivityLog.log(
            profile.user, 'api.rate_limit', 'API', '/api/v1/status/',
            {'endpoint': '/api/v1/status/', 'limit_rpm': limit_rpm, 'client_ip': _client_ip_status},
            _client_ip_status,
        )
        logger.warning(f"Rate limit exceeded: user={profile.user.username} ip={_client_ip_status} endpoint=/api/v1/status/")
        return json_error("Rate limit exceeded.", status=429)

    now = timezone.now()
    local_now = timezone.localtime(now)
    total = BlacklistEntry.objects.count()
    active = BlacklistEntry.objects.filter(is_active=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    ).count()

    client_ip = get_client_ip(request)
    ActivityLog.log(profile.user, 'api.status', None, None, _api_request_context(request), client_ip)

    from apps.settings_app.branding import platform_name as _platform_name
    platform_name = _platform_name()

    return JsonResponse({
        'status': 'ok',
        'version': '1.0.0',
        'platform': platform_name,
        'timestamp': local_now.isoformat(),
        'entries': {
            'total': total,
            'active': active,
        },
    })
