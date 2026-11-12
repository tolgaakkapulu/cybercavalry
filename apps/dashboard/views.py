import logging
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

logger = logging.getLogger(__name__)


# Gradient stops (low → high), interpolated for any slice count. Highest = #d3737a.
# Score charts (IP/Hash Score) — ordered buckets:
_SCORE_STOPS = ['#9cc4a8', '#bcd9b8', '#e8d39a', '#eaa896', '#d3737a']
# Categorical charts (top countries / threat labels) — count-ranked. Stored
# low→high; with reverse=True the largest (first) slice becomes #d3737a.
_CATEGORICAL_STOPS = ['#d3a8c4', '#ab98c4', '#9fb3cc', '#8fb8b4',
                      '#a8c896', '#d9b97a', '#e8a48a', '#d3737a']


def _taxii_status():
    """Is the TAXII server on the air, and is it publishing anything?

    For the dashboard's API Endpoints card. Two states are worth telling
    apart and neither is visible from the endpoint list alone: the server
    being off (every /taxii/ path answers 404) and the server being on with
    no active collection (it answers, but there is nothing to subscribe to).

    Deliberately tolerant: the card is informational, so a TAXII-side
    problem must not take the whole dashboard down with it. It is logged
    rather than swallowed, so a failure is not invisible.
    """
    try:
        from apps.taxii import conf as taxii_conf
        from apps.taxii.models import TaxiiCollection
        return {
            'enabled': taxii_conf.enabled(),
            'collections': TaxiiCollection.objects.filter(is_active=True).count(),
        }
    except Exception:
        logger.warning('Dashboard: could not read TAXII status', exc_info=True)
        return {'enabled': False, 'collections': 0}


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


# Allowed window sizes and bucket granularities for the timeline charts.
_TIMELINE_MAX_DAYS = 366
_TIMELINE_MAX_HOURLY_HOURS = 168   # cap the hourly window at 7 days of points
_TIMELINE_MAX_MINUTELY_MINUTES = 180  # cap the minutely window at 3 hours of points
# Both dashboard timelines open on the last 24 hours bucketed hourly: short
# enough to show what the platform is doing right now, long enough to cover a
# full daily cycle of firewall polls. Used for the first paint, as the fallback
# when a request omits or mangles the params, and as the PDF window.
_TIMELINE_DEFAULT_DAYS = 1
_TIMELINE_DEFAULT_BUCKET = 'hour'
_TIMELINE_DEFAULT_MINUTES = 60

# How the blacklist timeline counts. All three plot one line per list.
#   'activity' — everything that happened to each list during the bucket:
#                entries added, entries activated, entries edited, and repeat
#                reports that bumped an existing entry's hit count. The
#                default, because an entry table dates only additions, so a
#                batch switched from passive to active used to move nothing on
#                the chart at all.
#   'new'      — entries added during the bucket, and nothing else. Isolates
#                genuine ingestion from re-activation of entries you already
#                had.
#   'total'    — how many entries the list held at the end of the bucket.
_TIMELINE_MODE_ACTIVITY = 'activity'
_TIMELINE_MODE_NEW = 'new'
_TIMELINE_MODE_TOTAL = 'total'
_TIMELINE_MODES = (_TIMELINE_MODE_ACTIVITY, _TIMELINE_MODE_NEW, _TIMELINE_MODE_TOTAL)
_TIMELINE_DEFAULT_MODE = _TIMELINE_MODE_ACTIVITY
_TIMELINE_FEEDS = ('ip', 'hash', 'url')


def _add_month(d):
    """First day of the month following `d` (a first-of-month date)."""
    return date(d.year + 1, 1, 1) if d.month == 12 else date(d.year, d.month + 1, 1)


class _BucketPlan:
    """A resolved timeline window: every bucket in it, plus what is needed to
    count rows into those buckets.

    Built by `_bucket_plan()`. Call `counts(qs)` once per series — the lists it
    returns are aligned with `labels`, with a 0 for buckets that have no rows,
    so a line chart never has gaps.
    """

    def __init__(self, periods, trunc, keyfmt, fmt, flt, pre_flt, norm,
                 days, minutes, bucket):
        self.periods = periods
        self.trunc = trunc        # TruncMinute/Hour/Date/Month on the date column
        self.keyfmt = keyfmt      # unique per-bucket key (matches DB rows to buckets)
        self.fmt = fmt            # human label shown on the x axis
        self.flt = flt            # queryset filter narrowing to the window
        self.pre_flt = pre_flt    # the complement: everything before the window
        self.norm = norm          # DB value -> comparable local date/datetime
        self.days = days
        self.minutes = minutes
        self.bucket = bucket
        self._index = None        # built on demand by index_of()

    @property
    def labels(self):
        return [p.strftime(self.fmt) for p in self.periods]

    def counts(self, qs):
        """Rows of `qs` per bucket, as a list aligned with `labels`."""
        rows = (qs.filter(**self.flt).annotate(b=self.trunc)
                  .values('b').annotate(n=Count('id')))
        out = {}
        for r in rows:
            if r['b'] is None:
                continue
            k = self.norm(r['b']).strftime(self.keyfmt)
            out[k] = out.get(k, 0) + r['n']
        return [out.get(p.strftime(self.keyfmt), 0) for p in self.periods]

    def cumulative(self, qs):
        """Running total: how many rows of `qs` existed by the end of each
        bucket, as a list aligned with `labels`.

        Rows added before the window are the starting level, so a 24-hour view
        of a list filled last week reports the list's real size instead of a
        flat zero. `pre_flt` is the exact complement of `flt`, so no row is
        counted twice and none is missed.
        """
        running = qs.filter(**self.pre_flt).count()
        out = []
        for n in self.counts(qs):
            running += n
            out.append(running)
        return out

    def index_of(self, when):
        """Index of the bucket `when` falls in, or None if it is outside the
        window. Lets a caller bucket rows in Python when the counting cannot
        be expressed as a queryset — see `_activity_events()`."""
        if self._index is None:
            self._index = {p.strftime(self.keyfmt): i
                           for i, p in enumerate(self.periods)}
        return self._index.get(self.norm(when).strftime(self.keyfmt))

    def meta(self):
        """The selection echoed back to the caller, after clamping."""
        return {'days': self.days, 'minutes': self.minutes, 'bucket': self.bucket}


def _bucket_plan(now, days, bucket, minutes, field):
    """Resolve a window and granularity into a `_BucketPlan`.

    `field` is the datetime column to bucket on — `added_at` for blacklist
    entries, `timestamp` for activity-log rows — so one implementation serves
    every timeline on the dashboard.

    Counts are by the local minute/hour/day/month of `field` (TruncMinute/
    TruncHour/TruncDate/TruncMonth all honour the active timezone). `days` is
    the window length in days (hour/day/month buckets); `minutes` is the window
    length in minutes (minute bucket only). For the hourly bucket the window is
    days*24 hours, capped at `_TIMELINE_MAX_HOURLY_HOURS`.
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
        bucket = _TIMELINE_DEFAULT_BUCKET

    today = timezone.localdate(now)

    if bucket == 'minute':
        minutes = max(1, min(minutes, _TIMELINE_MAX_MINUTELY_MINUTES))
        cur = timezone.localtime(now).replace(second=0, microsecond=0)
        periods = [cur - timedelta(minutes=m) for m in range(minutes - 1, -1, -1)]
        trunc = TruncMinute(field)
        keyfmt, fmt = '%Y-%m-%d %H:%M', '%H:%M'
        flt = {f'{field}__gte': periods[0]}
        pre_flt = {f'{field}__lt': periods[0]}

        def norm(v):
            return timezone.localtime(v) if timezone.is_aware(v) else v

    elif bucket == 'hour':
        hours = max(1, min(days * 24, _TIMELINE_MAX_HOURLY_HOURS))
        days = max(1, min(days, _TIMELINE_MAX_HOURLY_HOURS // 24 or 1))
        cur = timezone.localtime(now).replace(minute=0, second=0, microsecond=0)
        periods = [cur - timedelta(hours=h) for h in range(hours - 1, -1, -1)]
        trunc = TruncHour(field)
        keyfmt, fmt = '%Y-%m-%d %H', '%H:%M'
        flt = {f'{field}__gte': periods[0]}
        pre_flt = {f'{field}__lt': periods[0]}

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
        trunc = TruncMonth(field)
        keyfmt, fmt = '%Y-%m', '%b %Y'
        flt = {f'{field}__date__gte': periods[0]}
        pre_flt = {f'{field}__date__lt': periods[0]}

        def norm(v):
            if isinstance(v, datetime):
                v = (timezone.localtime(v) if timezone.is_aware(v) else v).date()
            return v

    else:  # day
        days = max(1, min(days, _TIMELINE_MAX_DAYS))
        start = today - timedelta(days=days - 1)
        periods = [start + timedelta(days=i) for i in range(days)]
        trunc = TruncDate(field)
        keyfmt, fmt = '%Y-%m-%d', '%d %b'
        flt = {f'{field}__date__gte': periods[0]}
        pre_flt = {f'{field}__date__lt': periods[0]}

        def norm(v):
            if isinstance(v, datetime):
                v = (timezone.localtime(v) if timezone.is_aware(v) else v).date()
            return v

    return _BucketPlan(periods, trunc, keyfmt, fmt, flt, pre_flt, norm,
                       days, minutes, bucket)


def _timeline_sources(now, live_only=True):
    """The three lists the blacklist timeline charts.

    `live_only=True` is the active, unexpired list — exactly what the stat
    cards above the chart count, and what they are built from, so a card and
    the chart beneath it cannot drift apart. The 'total' measure uses it
    because it reports list *size*.

    `live_only=False` is every row. The event measures use it: an entry added
    on Tuesday was added on Tuesday, and deactivating it on Friday must not
    rewrite Tuesday's bar. Filtering history by present state would make the
    past change every time someone edits the list.
    """
    if live_only:
        active_q = Q(is_active=True) & (Q(expires_at__isnull=True)
                                        | Q(expires_at__gt=now))
        return {
            'ip':   BlacklistEntry.objects.filter(active_q),
            'hash': HashEntry.objects.filter(is_active=True, list_type='black'),
            'url':  URLEntry.objects.filter(is_active=True, list_type='black'),
        }
    return {
        'ip':   BlacklistEntry.objects.all(),
        'hash': HashEntry.objects.filter(list_type='black'),
        'url':  URLEntry.objects.filter(list_type='black'),
    }


# Changes an entry table cannot date by itself. A row carries only `added_at`,
# so an activation or an edit leaves no per-row trace — but the activity log
# recorded it, together with how many entries it touched.
#
# Additions are deliberately absent: they come from `added_at`, which is exact
# per entry and present even for rows imported before this log had any entries.
# Deactivations and deletions are absent too — they are the opposite sign, and
# folding them in would make 100 adds plus 100 removals read as 200 changes.
#
#   action -> (series, detail key holding how many entries it touched)
_ACTIVITY_EVENTS = {
    'blacklist.reactivate':      ('ip',   None),
    'blacklist.bulk_activate':   ('ip',   'count'),
    'blacklist.edit':            ('ip',   None),
    'blacklist.bulk_edit_group': ('ip',   'count'),
    'hashlist.activate':         ('hash', None),
    'hashlist.bulk_activate':    ('hash', 'count'),
    'hashlist.edit':             ('hash', None),
    'urllist.activate':          ('url',  None),
    'urllist.bulk_activate':     ('url',  'count'),
    'urllist.edit':              ('url',  None),
}

# A repeat report bumps an existing entry's hit count and last-seen instead of
# creating anything. A report that CREATED the entry is excluded, because
# `added_at` already dates it and counting both would double it — the api app
# records which of the two happened in `detail['action']`.
#
#   action -> (series, the detail['action'] values that mean "already existed")
_ACTIVITY_REPEAT_REPORTS = {
    'api.report':      ('ip',   {'updated'}),
    'api.hash_report': ('hash', {'existing'}),
    'api.url_report':  ('url',  {'existing'}),
}


def _event_weight(detail, key):
    """How many entries one activity-log row stands for.

    Bulk actions record it (`detail['count']`); single-entry actions have no
    key and count as one. A row whose count is missing or unreadable still
    counts as one, because it definitely represents at least one change.
    """
    if key is None:
        return 1
    try:
        return max(0, int(detail.get(key, 1)))
    except (TypeError, ValueError):
        return 1


def _activity_events(now, days, bucket, minutes):
    """Per-bucket counts of the list changes `added_at` cannot express.

    Returns {'ip': [...], 'hash': [...], 'url': [...]}, aligned with the
    entry-table buckets for the same window.

    Bucketed in Python rather than in SQL: the weight lives inside a JSONField
    and summing it portably across SQLite and PostgreSQL is not worth it for
    rows that number in the tens — these are operator actions, not traffic.
    """
    plan = _bucket_plan(now, days, bucket, minutes, 'timestamp')
    out = {feed: [0] * len(plan.periods) for feed in _TIMELINE_FEEDS}

    rows = (ActivityLog.objects
            .filter(action__in=list(_ACTIVITY_EVENTS) + list(_ACTIVITY_REPEAT_REPORTS),
                    **plan.flt)
            .values_list('action', 'timestamp', 'detail'))

    for action, when, detail in rows:
        detail = detail or {}
        if action in _ACTIVITY_EVENTS:
            feed, key = _ACTIVITY_EVENTS[action]
            weight = _event_weight(detail, key)
        else:
            feed, repeat_values = _ACTIVITY_REPEAT_REPORTS[action]
            if detail.get('action') not in repeat_values:
                continue          # it created the entry; added_at has it
            weight = 1
        if not weight:
            continue
        i = plan.index_of(when)
        if i is not None:
            out[feed][i] += weight

    return out


def _timeline(now, days=_TIMELINE_DEFAULT_DAYS, bucket=_TIMELINE_DEFAULT_BUCKET,
              minutes=_TIMELINE_DEFAULT_MINUTES, mode=_TIMELINE_DEFAULT_MODE):
    """IP / hash / URL blacklist activity per bucket (mode='activity', the
    default), additions only (mode='new'), or list size (mode='total').

    Returns {labels, ip, hash, url, days, minutes, bucket, mode}, every series
    aligned with `labels`. See `_bucket_plan()` for how the window is resolved.
    """
    if mode not in _TIMELINE_MODES:
        mode = _TIMELINE_DEFAULT_MODE
    plan = _bucket_plan(now, days, bucket, minutes, 'added_at')

    if mode == _TIMELINE_MODE_TOTAL:
        src = _timeline_sources(now, live_only=True)
        series = {feed: plan.cumulative(src[feed]) for feed in _TIMELINE_FEEDS}
    else:
        src = _timeline_sources(now, live_only=False)
        series = {feed: plan.counts(src[feed]) for feed in _TIMELINE_FEEDS}
        if mode == _TIMELINE_MODE_ACTIVITY:
            events = _activity_events(now, plan.days, plan.bucket, plan.minutes)
            series = {feed: [a + b for a, b in zip(series[feed], events[feed])]
                      for feed in _TIMELINE_FEEDS}

    return {
        'labels': plan.labels,
        'ip':     series['ip'],
        'hash':   series['hash'],
        'url':    series['url'],
        'mode':   mode,
        **plan.meta(),
    }


# ── Request Timeline ────────────────────────────────────────────────────────
# Incoming API traffic, grouped by what the caller was doing. Every row the api
# app writes to the activity log is prefixed `api.`; these three groups cover
# what matters operationally:
#   Feed pulls — a firewall / SIEM fetching a published list, over either
#                the /api/v1/ endpoints or TAXII
#   Reports    — a client submitting an IOC back to the platform
#   Rejected   — a caller turned away: throttled by the per-token limit, or
#                refused by TAXII auth (expired token, IP off the allowlist)
# `other` is deliberately computed as the remainder (all `api.*` minus the
# three groups) rather than listed, so the chart always accounts for every
# logged request: `api.status`, `api.report.skipped` and any api.* action added
# later surface in `other` instead of silently vanishing from the totals.
REQUEST_PULL_ACTIONS = [
    # /api/v1/ feed fetches
    'api.blacklist', 'api.hashlist', 'api.urllist',
    # TAXII polls that actually transfer indicators. Discovery, api-root and
    # collection browsing are metadata lookups a subscriber does once at
    # setup, so they stay in `other` rather than inflating the pull line.
    'api.taxii_objects', 'api.taxii_object', 'api.taxii_manifest',
]
REQUEST_REPORT_ACTIONS = ['api.report', 'api.hash_report', 'api.url_report']
# Grouped together because the operational question is "is anyone being turned
# away?", not which mechanism did it. A 401 flood from a mis-set subscriber
# token deserves the same visibility as throttling, not a grey `other` line.
REQUEST_REJECTED_ACTIONS = ['api.rate_limit', 'api.taxii_denied']


def _request_timeline(now, days=_TIMELINE_DEFAULT_DAYS, bucket=_TIMELINE_DEFAULT_BUCKET,
                      minutes=_TIMELINE_DEFAULT_MINUTES):
    """Incoming API requests over a window, bucketed like `_timeline()`.

    Returns {labels, pull, report, rejected, other, days, minutes, bucket}.
    """
    plan = _bucket_plan(now, days, bucket, minutes, 'timestamp')
    logs = ActivityLog.objects.filter(action__startswith='api.')

    pull     = plan.counts(logs.filter(action__in=REQUEST_PULL_ACTIONS))
    report   = plan.counts(logs.filter(action__in=REQUEST_REPORT_ACTIONS))
    rejected = plan.counts(logs.filter(action__in=REQUEST_REJECTED_ACTIONS))
    total    = plan.counts(logs)
    # The three groups are disjoint, so this cannot go negative — max() only
    # guards against a future overlap being drawn as a negative spike.
    other = [max(0, t - p - r - j)
             for t, p, r, j in zip(total, pull, report, rejected)]

    return {
        'labels':   plan.labels,
        'pull':     pull,
        'report':   report,
        'rejected': rejected,
        'other':    other,
        **plan.meta(),
    }


def _timeline_params(request):
    """(days, bucket, minutes, mode) from the query string, for either
    timeline API.

    Only parsed here — `_bucket_plan()` and `_timeline()` do the clamping and
    the fallback for anything unusable.
    """
    try:
        days = int(request.GET.get('days', _TIMELINE_DEFAULT_DAYS))
    except (TypeError, ValueError):
        days = _TIMELINE_DEFAULT_DAYS
    try:
        minutes = int(request.GET.get('minutes', _TIMELINE_DEFAULT_MINUTES))
    except (TypeError, ValueError):
        minutes = _TIMELINE_DEFAULT_MINUTES
    return (days,
            request.GET.get('bucket', _TIMELINE_DEFAULT_BUCKET),
            minutes,
            request.GET.get('mode', _TIMELINE_DEFAULT_MODE))


@login_required_custom
def index(request):
    now = timezone.now()

    active_q = Q(is_active=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    # Same querysets the timeline charts count, so a card and the chart
    # beneath it can never disagree about how big a list is.
    src = _timeline_sources(now)
    stats = {
        'blacklist_total': src['ip'].count(),
        'blacklist_24h': src['ip'].filter(group__name='24h').count(),
        'blacklist_30d': src['ip'].filter(group__name='30d').count(),
        'whitelist_total': WhitelistEntry.objects.filter(is_active=True).count(),
        'hashlist_total': src['hash'].count(),
        'urllist_total':  src['url'].count(),
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
        # Both open on the last 24 hours, hourly (see _TIMELINE_DEFAULT_*).
        'timeline_init': _timeline(now),
        'request_timeline_init': _request_timeline(now),
        # For the TAXII block of the API Endpoints card.
        'taxii': _taxii_status(),
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

    src = _timeline_sources(now)
    stats = {
        'hashlist_total':  src['hash'].count(),
        'urllist_total':   src['url'].count(),
        'blacklist_total': src['ip'].count(),
        'blacklist_24h':   src['ip'].filter(group__name='24h').count(),
        'blacklist_30d':   src['ip'].filter(group__name='30d').count(),
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

    Query params (shared with request_timeline_api):
      days    — window size in days (1..366, default 1) — used when bucket
                is 'hour', 'day', or 'month'
      minutes — window size in minutes (1..180, default 60) — used only when
                bucket is 'minute'
      bucket  — 'minute' | 'hour' (default) | 'day' | 'month'
      mode    — 'total' (default) for list size, 'new' for additions per
                bucket. Ignored by request_timeline_api.
    """
    days, bucket, minutes, mode = _timeline_params(request)
    return JsonResponse(_timeline(timezone.now(), days, bucket, minutes, mode))


@login_required_custom
def request_timeline_api(request):
    """JSON endpoint for the incoming-API-request timeline.

    Same query params as timeline_api(); the series are feed pulls, reports,
    rate-limited calls and everything else the api app logged.
    """
    days, bucket, minutes, _mode = _timeline_params(request)
    return JsonResponse(_request_timeline(timezone.now(), days, bucket, minutes))


@login_required_custom
@role_required('admin', 'operator', 'viewer')
def dashboard_pdf(request):
    """Generate and stream a portrait A4 dashboard PDF."""
    now = timezone.now()
    active_q = Q(is_active=True) & (Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    src = _timeline_sources(now)
    stats = {
        'blacklist_total': src['ip'].count(),
        'blacklist_24h':   src['ip'].filter(group__name='24h').count(),
        'blacklist_30d':   src['ip'].filter(group__name='30d').count(),
        'whitelist_total': WhitelistEntry.objects.filter(is_active=True).count(),
        'hashlist_total':  src['hash'].count(),
        'urllist_total':   src['url'].count(),
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
    _days, _bucket, _minutes, _mode = _timeline_params(request)
    timeline = _timeline(now, _days, _bucket, minutes=_minutes, mode=_mode)

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
