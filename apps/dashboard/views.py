from datetime import date, datetime, timedelta
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.db.models import Q, Count
from django.db.models.functions import TruncDate, TruncHour, TruncMinute, TruncMonth
from django.contrib.auth.models import User as DjangoUser

from apps.accounts.decorators import login_required_custom, role_required
from apps.blacklist.models import BlacklistEntry, BlacklistGroup
from apps.whitelist.models import WhitelistEntry
from apps.hashlist.models import HashEntry
from apps.urllist.models import URLEntry

from apps.settings_app.models import ActivityLog
from apps.reports.pdf_generator import generate_dashboard_snapshot


# Gradient stops (low → high), interpolated for any slice count. Highest = #d3737a.
# Score charts (IP/Hash Score) — ordered buckets:
_SCORE_STOPS = ['#9cc4a8', '#bcd9b8', '#e8d39a', '#eaa896', '#d3737a']
# Categorical charts (top countries / threat labels) — count-ranked. Stored
# low→high; with reverse=True the largest (first) slice becomes #d3737a.
_CATEGORICAL_STOPS = ['#d3a8c4', '#ab98c4', '#9fb3cc', '#8fb8b4',
                      '#a8c896', '#d9b97a', '#e8a48a', '#d3737a']


def _gradient_colors(n, stops):
    """Return n colours smoothly interpolated across `stops`."""
    if n <= 0:
        return []
    if n == 1:
        return [stops[0]]
    rgb = [(int(s[1:3], 16), int(s[3:5], 16), int(s[5:7], 16)) for s in stops]
    seg = len(stops) - 1
    out = []
    for k in range(n):
        t = k / (n - 1) * seg            # position along the ramp [0..seg]
        i = min(int(t), seg - 1)         # lower stop index
        f = t - i                        # fraction into the segment
        c = tuple(round(rgb[i][j] + (rgb[i + 1][j] - rgb[i][j]) * f) for j in range(3))
        out.append('#%02x%02x%02x' % c)
    return out


def _flag_url(code):
    """Resolve a 2-letter ISO code to the bundled flag SVG URL ('' if missing).
    Honours staticfiles_storage (WhiteNoise / manifest hashing)."""
    if not code or len(code) != 2 or not code.isascii() or not code.isalpha():
        return ''
    from django.contrib.staticfiles.storage import staticfiles_storage
    return staticfiles_storage.url(f'img/flags/{code.lower()}.svg')


def _chart_data(pairs, stops, reverse=False, codes=None):
    """
    Build Chart.js pie data from [(label, count), ...] using gradient `stops`.
    Zero-count slices are dropped. `reverse=True` flips the ramp so the first
    (largest) slice gets the high-end colour — used for the count-ranked
    categorical charts (top countries / threat labels).
    If `codes` is provided (parallel list of 2-letter ISO codes), the result
    also carries a `flags` array of pre-resolved SVG URLs ('' when no code).
    Returns {'labels', 'data', 'colors', 'flags', 'total'}.
    """
    triples = []
    codes = list(codes) if codes is not None else [''] * len(pairs)
    for (label, c), code in zip(pairs, codes):
        if c and c > 0:
            triples.append((str(label), c, code))
    total = sum(c for _, c, _ in triples)
    colors = _gradient_colors(len(triples), stops)
    if reverse:
        colors = colors[::-1]
    return {
        'labels': [label for label, _, _ in triples],
        'data':   [c for _, c, _ in triples],
        'colors': colors,
        'flags':  [_flag_url(code) for _, _, code in triples],
        'total':  total,
    }


def _ip_score_thresholds():
    """Read (t24, t30) from SettingsCache with sane fallbacks (10 / 80).
    Returned as ints clamped to [0, 100] so band math can't escape the
    AbuseIPDB confidence-score range."""
    from apps.settings_app.cache import SettingsCache
    def _i(key, default):
        try:
            v = int(SettingsCache.get(key, default) or default)
        except (TypeError, ValueError):
            v = default
        return max(0, min(100, v))
    return _i('threat_intel.abuseipdb_threshold_24h', 10), \
           _i('threat_intel.abuseipdb_threshold_30d', 80)


def _score_bands_ip(t24, t30):
    """Return monotonic (b_info, b_low, b_med, b_high) cut-points for the
    IP-score pie. Each value is the *upper-exclusive* edge of its band:

        Info  : [0,         t24/2)
        Low   : [t24/2,     t24)
        Medium: [t24,       (t24+t30)/2)
        High  : [(t24+t30)/2, t30)
        Crit. : [t30,       100]

    `Info` and `Low` split the 0..t24 range evenly so neither dwarfs the other
    when t24 is small; `Medium` and `High` split the t24..t30 range evenly so
    the bulk of scored IPs (which usually land between the two thresholds)
    spread across two equally-weighted severity bands instead of piling into
    one. `max(…)` chains keep the cut-points ordered even if an admin sets
    t24 ≥ t30 (the squeezed bands just end up empty).
    """
    b_info = max(0, t24 // 2)
    b_low  = max(b_info, t24)
    b_med  = max(b_low,  (t24 + t30) // 2)
    b_high = max(b_med,  t30)
    return b_info, b_low, b_med, b_high


def _ip_score_tooltip(t24, t30):
    """Tooltip body for the IP Score pie — reflects the live bands."""
    b_info, b_low, b_med, b_high = _score_bands_ip(t24, t30)
    def _rng(lo, hi_exclusive, cap=100):
        # Render as 'lo–hi' inclusive on both ends for readability.
        hi = min(cap, hi_exclusive - 1)
        return f'{lo}–{hi}' if hi >= lo else f'{lo}'
    return (
        'AbuseIPDB confidence score bands (0–100):\n'
        f'• Info — {_rng(0, b_info)}\n'
        f'• Low — {_rng(b_info, b_low)}\n'
        f'• Medium — {_rng(b_low, b_med)}\n'
        f'• High — {_rng(b_med, b_high)}\n'
        f'• Critical — {b_high}–100'
    )


def _analytics_distributions(active_q):
    """Compute the four analytics pie datasets. Used by index() and stats_api()
    so the dashboard auto-refresh updates the charts too."""
    bl_scored = BlacklistEntry.objects.filter(active_q, abuse_confidence_score__isnull=False)
    # Severity bands derive from the admin-configured AbuseIPDB thresholds so
    # the chart tracks how each deployment classifies abuse scores in practice.
    #   Critical: ≥ t30                    High:   [(t24+t30)/2, t30)
    #   Medium:   [t24, (t24+t30)/2)       Low:    [t24/2, t24)
    #   Info:     [0, t24/2)
    # Medium/High split the t24..t30 mid-range evenly; Info/Low split the
    # 0..t24 range evenly. `_score_bands_ip()` clamps the cut-points so the
    # bands stay monotonic even if an admin sets t24 ≥ t30.
    t24, t30 = _ip_score_thresholds()
    b_info, b_low, b_med, b_high = _score_bands_ip(t24, t30)
    ip_score = _chart_data([
        ('Info',     bl_scored.filter(abuse_confidence_score__lt=b_info).count()),
        ('Low',      bl_scored.filter(abuse_confidence_score__gte=b_info, abuse_confidence_score__lt=b_low).count()),
        ('Medium',   bl_scored.filter(abuse_confidence_score__gte=b_low,  abuse_confidence_score__lt=b_med).count()),
        ('High',     bl_scored.filter(abuse_confidence_score__gte=b_med,  abuse_confidence_score__lt=b_high).count()),
        ('Critical', bl_scored.filter(abuse_confidence_score__gte=b_high).count()),
    ], _SCORE_STOPS)
    ip_country_rows = list(
        BlacklistEntry.objects.filter(active_q).exclude(abuse_country_name='')
        .values('abuse_country_name', 'abuse_country_code')
        .annotate(n=Count('id')).order_by('-n')[:10]
    )
    ip_country = _chart_data(
        [(d['abuse_country_name'], d['n']) for d in ip_country_rows],
        _CATEGORICAL_STOPS, reverse=True,
        codes=[d['abuse_country_code'] for d in ip_country_rows],
    )
    # VirusTotal malicious-engine bands. Tightened so most flagged samples
    # land in Medium/High instead of bunching into Critical:
    #   Info 0 · Low 1–5 · Medium 6–12 · High 13–19 · Critical 20+
    hl_scored = HashEntry.objects.filter(is_active=True, list_type='black', vt_malicious__isnull=False)
    hash_score = _chart_data([
        ('Info',     hl_scored.filter(vt_malicious=0).count()),
        ('Low',      hl_scored.filter(vt_malicious__gte=1,  vt_malicious__lt=6).count()),
        ('Medium',   hl_scored.filter(vt_malicious__gte=6,  vt_malicious__lt=13).count()),
        ('High',     hl_scored.filter(vt_malicious__gte=13, vt_malicious__lt=20).count()),
        ('Critical', hl_scored.filter(vt_malicious__gte=20).count()),
    ], _SCORE_STOPS)
    # Top threat labels — bucket VT labels by their leading segment (everything
    # before the first dot) so siblings like `trojan.crack` / `trojan.msil`
    # collapse into a single "trojan" slice. Entries with no VT-supplied label
    # (or whose normalized segment is empty) fall into "Other".
    from collections import Counter
    hl_black = HashEntry.objects.filter(is_active=True, list_type='black')
    raw_labels = hl_black.exclude(vt_threat_label='').values_list('vt_threat_label', flat=True)
    counter = Counter()
    unparseable = 0
    for raw in raw_labels:
        head = raw.split('.', 1)[0].strip() if raw else ''
        if head:
            counter[head] += 1
        else:
            unparseable += 1
    pairs = list(counter.most_common(10))
    other_n = hl_black.filter(vt_threat_label='').count() + unparseable
    if other_n:
        pairs.append(('Other', other_n))
    hash_threat = _chart_data(pairs, _CATEGORICAL_STOPS, reverse=True)

    # URL Score — same VirusTotal malicious-engine bands as hash score. VT's
    # URL reputation returns fewer engines than files (~90 vs ~70+), but the
    # thresholds hold: a URL flagged by 20+ engines is unambiguously bad.
    ul_scored = URLEntry.objects.filter(is_active=True, list_type='black', vt_malicious__isnull=False)
    url_score = _chart_data([
        ('Info',     ul_scored.filter(vt_malicious=0).count()),
        ('Low',      ul_scored.filter(vt_malicious__gte=1,  vt_malicious__lt=6).count()),
        ('Medium',   ul_scored.filter(vt_malicious__gte=6,  vt_malicious__lt=13).count()),
        ('High',     ul_scored.filter(vt_malicious__gte=13, vt_malicious__lt=20).count()),
        ('Critical', ul_scored.filter(vt_malicious__gte=20).count()),
    ], _SCORE_STOPS)
    return {'ipscore': ip_score, 'ipcountry': ip_country,
            'urlscore': url_score,
            'hashscore': hash_score, 'hashthreat': hash_threat}


# Allowed window sizes and bucket granularities for the timeline chart.
_TIMELINE_MAX_DAYS = 366
_TIMELINE_MAX_HOURLY_HOURS = 168   # cap the hourly window at 7 days of points
_TIMELINE_MAX_MINUTELY_MINUTES = 180  # cap the minutely window at 3 hours of points
_TIMELINE_DEFAULT_DAYS = 30
_TIMELINE_DEFAULT_MINUTES = 60


def _add_month(d):
    """First day of the month following `d` (a first-of-month date)."""
    return date(d.year + 1, 1, 1) if d.month == 12 else date(d.year, d.month + 1, 1)


def _timeline(now, days=_TIMELINE_DEFAULT_DAYS, bucket='day', minutes=_TIMELINE_DEFAULT_MINUTES):
    """IP + hash blacklist additions over a window, bucketed by minute, hour, day or month.

    Counts are by the local minute/hour/day/month of `added_at` (TruncMinute/
    TruncHour/TruncDate/TruncMonth all honour the active timezone). Buckets are
    keyed by a unique formatted string so timezone-aware values match cleanly,
    and every bucket in the window is present (0 when none) so the line chart
    never has gaps.

    `days` is the window length in days (used for hour/day/month buckets);
    `minutes` is the window length in minutes (used only for the minute bucket).
    For the hourly bucket the window is days*24 hours (capped). Returns
    {labels, ip, hash, days, minutes, bucket}.
    """
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = _TIMELINE_DEFAULT_DAYS
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        minutes = _TIMELINE_DEFAULT_MINUTES
    if bucket not in ('minute', 'hour', 'day', 'month'):
        bucket = 'day'

    today = timezone.localdate(now)

    if bucket == 'minute':
        minutes = max(1, min(minutes, _TIMELINE_MAX_MINUTELY_MINUTES))
        cur = timezone.localtime(now).replace(second=0, microsecond=0)
        periods = [cur - timedelta(minutes=m) for m in range(minutes - 1, -1, -1)]
        trunc = TruncMinute('added_at')
        keyfmt, fmt = '%Y-%m-%d %H:%M', '%H:%M'
        flt = {'added_at__gte': periods[0]}

        def norm(v):
            return timezone.localtime(v) if timezone.is_aware(v) else v

    elif bucket == 'hour':
        hours = max(1, min(days * 24, _TIMELINE_MAX_HOURLY_HOURS))
        days = max(1, min(days, _TIMELINE_MAX_HOURLY_HOURS // 24 or 1))
        cur = timezone.localtime(now).replace(minute=0, second=0, microsecond=0)
        periods = [cur - timedelta(hours=h) for h in range(hours - 1, -1, -1)]
        trunc = TruncHour('added_at')
        keyfmt, fmt = '%Y-%m-%d %H', '%H:%M'
        flt = {'added_at__gte': periods[0]}

        def norm(v):
            return timezone.localtime(v) if timezone.is_aware(v) else v

    elif bucket == 'month':
        days = max(1, min(days, _TIMELINE_MAX_DAYS))
        start = today - timedelta(days=days - 1)
        periods, b = [], date(start.year, start.month, 1)
        last = date(today.year, today.month, 1)
        while b <= last:
            periods.append(b)
            b = _add_month(b)
        trunc = TruncMonth('added_at')
        keyfmt, fmt = '%Y-%m', '%b %Y'
        flt = {'added_at__date__gte': periods[0]}

        def norm(v):
            if isinstance(v, datetime):
                v = (timezone.localtime(v) if timezone.is_aware(v) else v).date()
            return v

    else:  # day
        days = max(1, min(days, _TIMELINE_MAX_DAYS))
        start = today - timedelta(days=days - 1)
        periods = [start + timedelta(days=i) for i in range(days)]
        trunc = TruncDate('added_at')
        keyfmt, fmt = '%Y-%m-%d', '%d %b'
        flt = {'added_at__date__gte': periods[0]}

        def norm(v):
            if isinstance(v, datetime):
                v = (timezone.localtime(v) if timezone.is_aware(v) else v).date()
            return v

    def counts(qs):
        rows = (qs.filter(**flt).annotate(b=trunc).values('b').annotate(n=Count('id')))
        out = {}
        for r in rows:
            if r['b'] is None:
                continue
            k = norm(r['b']).strftime(keyfmt)
            out[k] = out.get(k, 0) + r['n']
        return out

    ip_map   = counts(BlacklistEntry.objects.all())
    hash_map = counts(HashEntry.objects.filter(list_type='black'))
    url_map  = counts(URLEntry.objects.filter(list_type='black'))
    keys = [p.strftime(keyfmt) for p in periods]
    return {
        'labels':  [p.strftime(fmt) for p in periods],
        'ip':      [ip_map.get(k, 0)   for k in keys],
        'hash':    [hash_map.get(k, 0) for k in keys],
        'url':     [url_map.get(k, 0)  for k in keys],
        'days':    days,
        'minutes': minutes,
        'bucket':  bucket,
    }


@login_required_custom
def index(request):
    now = timezone.now()

    active_q = Q(is_active=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    stats = {
        'blacklist_total': BlacklistEntry.objects.filter(active_q).count(),
        'blacklist_24h': BlacklistEntry.objects.filter(active_q, group__name='24h').count(),
        'blacklist_30d': BlacklistEntry.objects.filter(active_q, group__name='30d').count(),
        'whitelist_total': WhitelistEntry.objects.filter(is_active=True).count(),
        'hashlist_total': HashEntry.objects.filter(is_active=True, list_type='black').count(),
        'urllist_total':  URLEntry.objects.filter(is_active=True, list_type='black').count(),
        'api_reports': ActivityLog.objects.filter(
            action__in=['api.report', 'api.hash_report'],
            timestamp__gte=now - timedelta(hours=24)
        ).count(),
        'users_total': DjangoUser.objects.filter(is_active=True).count(),
    }

    recent_blacklist = (
        BlacklistEntry.objects
        .filter(active_q)
        .select_related('group', 'added_by')
        .order_by('-added_at')[:8]
    )

    recent_whitelist = (
        WhitelistEntry.objects
        .filter(is_active=True)
        .select_related('added_by')
        .order_by('-added_at')[:8]
    )

    recent_hashlist = (
        HashEntry.objects
        .filter(is_active=True, list_type='black')
        .select_related('added_by')
        .order_by('-added_at')[:8]
    )

    recent_urllist = (
        URLEntry.objects
        .filter(is_active=True, list_type='black')
        .select_related('added_by')
        .order_by('-added_at')[:8]
    )

    entry_active_q = Q(entries__is_active=True) & (
        Q(entries__expires_at__isnull=True) | Q(entries__expires_at__gt=now)
    )
    groups = BlacklistGroup.objects.annotate(
        active_count=Count('entries', filter=entry_active_q)
    )

    # Analytics pie datasets (rendered on load; also refreshed via stats_api)
    charts = _analytics_distributions(active_q)
    _t24, _t30 = _ip_score_thresholds()
    # data-tip needs literal &#10; for line breaks; escape <>& first so any
    # future copy that contains them stays safe, then swap newlines.
    from django.utils.html import escape as _esc
    from django.utils.safestring import mark_safe as _safe
    ip_score_tooltip = _safe(_esc(_ip_score_tooltip(_t24, _t30)).replace('\n', '&#10;'))

    return render(request, 'dashboard/index.html', {
        'stats': stats,
        'recent_blacklist': recent_blacklist,
        'recent_whitelist': recent_whitelist,
        'recent_hashlist': recent_hashlist,
        'recent_urllist': recent_urllist,
        'groups': groups,
        'ip_score_dist': charts['ipscore'],
        'ip_score_tooltip': ip_score_tooltip,
        'ip_country_dist': charts['ipcountry'],
        'url_score_dist': charts['urlscore'],
        'hash_score_dist': charts['hashscore'],
        'hash_threat_dist': charts['hashthreat'],
        'timeline_init': _timeline(now, 1, 'minute', minutes=60),
    })


@login_required_custom
def stats_api(request):
    """JSON endpoint for dashboard auto-refresh."""
    now = timezone.now()
    active_q = Q(is_active=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    def fmt(dt):
        return timezone.localtime(dt).strftime('%Y-%m-%d %H:%M') if dt else ''

    def fmt_d(dt):
        return timezone.localtime(dt).strftime('%Y-%m-%d') if dt else ''

    stats = {
        'hashlist_total':  HashEntry.objects.filter(is_active=True, list_type='black').count(),
        'urllist_total':   URLEntry.objects.filter(is_active=True, list_type='black').count(),
        'blacklist_total': BlacklistEntry.objects.filter(active_q).count(),
        'blacklist_24h':   BlacklistEntry.objects.filter(active_q, group__name='24h').count(),
        'blacklist_30d':   BlacklistEntry.objects.filter(active_q, group__name='30d').count(),
        'whitelist_total': WhitelistEntry.objects.filter(is_active=True).count(),
        'api_reports':     ActivityLog.objects.filter(
            action__in=['api.report', 'api.hash_report'],
            timestamp__gte=now - timedelta(hours=24)
        ).count(),
        'users_total': DjangoUser.objects.filter(is_active=True).count(),
    }

    recent_hashlist = [
        {
            'id':             e.id,
            'hash_prefix':    e.hash_value.upper()[:16],
            'fullhash':       e.hash_value.upper(),
            'hash_type':      e.hash_type,
            'source':         e.source,
            'source_display': e.get_source_display(),
            'added_at':       fmt(e.added_at),
            # VirusTotal enrichment for the hover tooltip
            'has_intel':      e.has_vt_intel,
            'threat':         e.vt_threat_label,
            'filetype':       e.vt_type_description,
            'size':           e.vt_size_display,
            'filename':       e.vt_meaningful_name,
            'firstseen':      fmt_d(e.vt_first_seen),
            'lastanalysis':   fmt_d(e.vt_last_analysis),
            'submitted':      e.vt_times_submitted or '',
        }
        for e in HashEntry.objects.filter(is_active=True, list_type='black')
                          .select_related('added_by').order_by('-added_at')[:8]
    ]

    recent_blacklist = [
        {
            'id':          e.id,
            'ip_address':  e.ip_address,
            'group_name':  e.group.name,
            'group_label': e.group.label,
            'source':      e.source,
            'source_display': e.get_source_display(),
            'added_at':    fmt(e.added_at),
            # AbuseIPDB enrichment for the hover tooltip
            'has_intel':   e.has_abuse_intel,
            'isp':         e.abuse_isp,
            'usage':       e.abuse_usage_type,
            'asn':         e.abuse_asn,
            'hostnames':   e.abuse_hostnames_display,
            'domain':      e.abuse_domain,
            'country':      e.abuse_country_display,
            'city':         e.abuse_city,
            'totalreports': e.abuse_total_reports or '',
            'lastreported': fmt(e.abuse_last_reported_at),
            'country_code': e.abuse_country_code,
            'flag_url':     _flag_url(e.abuse_country_code),
        }
        for e in BlacklistEntry.objects.filter(active_q)
                               .select_related('group', 'added_by').order_by('-added_at')[:8]
    ]

    recent_whitelist = [
        {
            'id':            e.id,
            'cidr':          e.cidr,
            'prefix_length': e.prefix_length,
            'source':        e.source,
            'added_at':      fmt(e.added_at),
        }
        for e in WhitelistEntry.objects.filter(is_active=True)
                               .select_related('added_by').order_by('-added_at')[:8]
    ]

    recent_urllist = [
        {
            'id':             e.id,
            'url':            e.url_value,
            'url_short':      (e.url_value[:48] + '…') if len(e.url_value) > 48 else e.url_value,
            'hostname':       e.hostname,
            'source':         e.source,
            'source_display': e.get_source_display(),
            'added_at':       fmt(e.added_at),
            # VirusTotal enrichment for the hover tooltip. Numeric fields are
            # pre-formatted into display strings (empty when the underlying value
            # is None) so the JS emitter can splice them straight into the DOM
            # without extra null-checks.
            'has_intel':      e.has_vt_intel,
            'threat':         e.vt_threat_label,
            'categories':     e.vt_categories,
            'tags':           e.vt_tags,
            'reputation':     '' if e.vt_reputation is None else str(e.vt_reputation),
            'votes':          (
                '' if (e.vt_votes_harmless is None and e.vt_votes_malicious is None)
                else f"{e.vt_votes_harmless or 0} harmless / {e.vt_votes_malicious or 0} malicious"
            ),
            'enginebreakdown': (
                '' if (e.vt_harmless is None and e.vt_suspicious is None and e.vt_undetected is None)
                else f"{e.vt_harmless or 0} harmless · {e.vt_suspicious or 0} suspicious · {e.vt_undetected or 0} undetected"
            ),
            'finalurl':       e.vt_final_url,
            'redirects':      '' if e.vt_redirect_count is None else str(e.vt_redirect_count),
            'pagetitle':      e.vt_title,
            'httpcode':       '' if e.vt_http_code is None else str(e.vt_http_code),
            'contentlength':  '' if e.vt_content_length is None else f"{e.vt_content_length} bytes",
            'servingip':      e.vt_serving_ip,
            'languages':      e.vt_languages,
            'registrar':      e.vt_registrar,
            'created':        fmt_d(e.vt_creation_date),
            'popularity':     '' if e.vt_popularity_rank is None else f"#{e.vt_popularity_rank}",
            'firstseen':      fmt_d(e.vt_first_seen),
            'lastanalysis':   fmt_d(e.vt_last_analysis),
            'submitted':      e.vt_times_submitted or '',
        }
        for e in URLEntry.objects.filter(is_active=True, list_type='black')
                         .select_related('added_by').order_by('-added_at')[:8]
    ]

    return JsonResponse({
        'stats':            stats,
        'recent_hashlist':  recent_hashlist,
        'recent_blacklist': recent_blacklist,
        'recent_whitelist': recent_whitelist,
        'recent_urllist':   recent_urllist,
        'charts':           _analytics_distributions(active_q),
    })


@login_required_custom
def timeline_api(request):
    """JSON endpoint for the blacklist-additions timeline.

    Query params:
      days    — window size in days (1..366, default 30) — used when bucket
                is 'hour', 'day', or 'month'
      minutes — window size in minutes (1..180, default 60) — used only when
                bucket is 'minute'
      bucket  — 'minute' | 'hour' | 'day' (default) | 'month'
    """
    try:
        days = int(request.GET.get('days', _TIMELINE_DEFAULT_DAYS))
    except (TypeError, ValueError):
        days = _TIMELINE_DEFAULT_DAYS
    try:
        minutes = int(request.GET.get('minutes', _TIMELINE_DEFAULT_MINUTES))
    except (TypeError, ValueError):
        minutes = _TIMELINE_DEFAULT_MINUTES
    bucket = request.GET.get('bucket', 'day')
    return JsonResponse(_timeline(timezone.now(), days, bucket, minutes))


@login_required_custom
@role_required('admin', 'operator', 'viewer')
def dashboard_pdf(request):
    """Generate and stream a portrait A4 dashboard PDF."""
    now = timezone.now()
    active_q = Q(is_active=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    stats = {
        'blacklist_total': BlacklistEntry.objects.filter(active_q).count(),
        'blacklist_24h':   BlacklistEntry.objects.filter(active_q, group__name='24h').count(),
        'blacklist_30d':   BlacklistEntry.objects.filter(active_q, group__name='30d').count(),
        'whitelist_total': WhitelistEntry.objects.filter(is_active=True).count(),
        'hashlist_total':  HashEntry.objects.filter(is_active=True, list_type='black').count(),
        'urllist_total':   URLEntry.objects.filter(is_active=True, list_type='black').count(),
        'api_reports':     ActivityLog.objects.filter(
            action__in=['api.report', 'api.hash_report'],
            timestamp__gte=now - timedelta(hours=24)
        ).count(),
        'users_total': DjangoUser.objects.filter(is_active=True).count(),
    }

    entry_active_q = Q(entries__is_active=True) & (
        Q(entries__expires_at__isnull=True) | Q(entries__expires_at__gt=now)
    )
    groups = BlacklistGroup.objects.annotate(
        active_count=Count('entries', filter=entry_active_q)
    )

    recent_blacklist = (
        BlacklistEntry.objects
        .filter(active_q)
        .select_related('group', 'added_by')
        .order_by('-added_at')[:8]
    )
    recent_whitelist = (
        WhitelistEntry.objects
        .filter(is_active=True)
        .select_related('added_by')
        .order_by('-added_at')[:8]
    )
    recent_hashlist = (
        HashEntry.objects
        .filter(is_active=True, list_type='black')
        .select_related('added_by')
        .order_by('-added_at')[:8]
    )
    recent_urllist = (
        URLEntry.objects
        .filter(is_active=True, list_type='black')
        .select_related('added_by')
        .order_by('-added_at')[:8]
    )

    _full = request.user.get_full_name()
    generated_by = f'{request.user.username} ({_full})' if _full else request.user.username

    # Analytics pie datasets + a timeline matching the dashboard's current
    # selection (?days=&bucket=&minutes=). _timeline sanitizes all params and
    # falls back to the view defaults (30 days / 60 minutes / daily) when any
    # are missing or invalid.
    charts = _analytics_distributions(active_q)
    timeline = _timeline(
        now,
        request.GET.get('days', _TIMELINE_DEFAULT_DAYS),
        request.GET.get('bucket', 'day'),
        minutes=request.GET.get('minutes', _TIMELINE_DEFAULT_MINUTES),
    )

    pdf_bytes = generate_dashboard_snapshot(
        stats, groups, recent_blacklist, recent_whitelist, recent_hashlist, generated_by,
        charts=charts, timeline=timeline, recent_urllist=recent_urllist,
    )

    ts = timezone.localtime(now).strftime('%Y%m%d_%H%M%S')
    from apps.settings_app.branding import brand_filename_prefix
    filename = f'{brand_filename_prefix()}_dashboard_{ts}.pdf'

    ActivityLog.log(request.user, 'report.download', None, None,
                    {'report_type': 'dashboard', 'filename': filename},
                    getattr(request, 'client_ip', ''))
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def error_403(request, exception=None):
    return render(request, 'errors/403.html', status=403)


def error_404(request, exception=None):
    return render(request, 'errors/404.html', status=404)


def error_500(request):
    return render(request, 'errors/500.html', status=500)
