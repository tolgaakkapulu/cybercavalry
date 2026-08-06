"""
CYBERCavalry — VirusTotal URL Scoring Service

Queries the VirusTotal v3 API for URL reputation and stores the result
(malicious engine count / total engine count) on URLEntry records.

Mirrors the structure of apps/blacklist/abuseipdb_service.py so that
bulk_refresh, update_entry_score, and the scheduler integration work
identically to the AbuseIPDB flow.

API endpoint used:
  GET https://www.virustotal.com/api/v3/urls/{hash}
  Header: x-apikey: <api_key>

Response shape (relevant fields):
  data.attributes.last_analysis_stats:
    malicious, suspicious, undetected, harmless, timeout, type-unsupported
"""

import logging
import hashlib
import concurrent.futures
import random
import urllib.request
import urllib.parse
import json
from datetime import datetime, timedelta, timezone as dt_timezone

from django.utils import timezone

logger = logging.getLogger(__name__)

_VT_URL    = 'https://www.virustotal.com/api/v3/urls/{}'
_VT_DOMAIN = 'https://www.virustotal.com/api/v3/domains/{}'


def _is_bare_domain(value):
    """True when the input is a bare host with no path (`phishing.example`,
    `sub.example.co.uk`). Path'li (`phishing.example/login`) or scheme'li
    (`https://…`) inputs return False — those keep hitting /urls/{sha256}."""
    v = (value or '').strip()
    if not v:
        return False
    if v.lower().startswith(('http://', 'https://')):
        return False
    return '/' not in v


class _VTQuotaExhausted(Exception):
    """Real daily-quota hit — the key is out for the rest of the UTC day.
    Free-tier daily cap is 500 req/day."""


class _VTRateLimited(Exception):
    """Per-minute rate limit hit (4 req/min on free tier). Transient: the
    key recovers in about a minute, so the caller should briefly skip it
    rather than burning it for the whole day."""


# Module-level registers of unavailable keys; each marker is cleared lazily
# once its expiry passes. Daily quota markers expire at the next UTC
# midnight; rate-limit markers expire after a short cooldown.
_VT_QUOTA_EXHAUSTED = {}
_VT_RATE_LIMITED = {}
_VT_RATE_LIMIT_COOLDOWN_SECS = 75   # one VT rate window + a small buffer


def _vt_key_id(api_key):
    return hashlib.sha1(api_key.encode('utf-8')).hexdigest()[:8]


def _vt_next_reset():
    now_utc = datetime.now(dt_timezone.utc)
    return now_utc.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)


def _vt_is_exhausted(api_key):
    kid = _vt_key_id(api_key)
    expiry = _VT_QUOTA_EXHAUSTED.get(kid)
    if expiry is None:
        return False
    if datetime.now(dt_timezone.utc) >= expiry:
        _VT_QUOTA_EXHAUSTED.pop(kid, None)
        return False
    return True


def _vt_mark_exhausted(api_key):
    kid = _vt_key_id(api_key)
    reset = _vt_next_reset()
    _VT_QUOTA_EXHAUSTED[kid] = reset
    logger.warning(
        "VirusTotal key %s daily quota exhausted; rotated out until %s UTC",
        kid, reset.isoformat()
    )


def _vt_is_rate_limited(api_key):
    """Is this key currently in its per-minute cooldown?"""
    kid = _vt_key_id(api_key)
    expiry = _VT_RATE_LIMITED.get(kid)
    if expiry is None:
        return False
    if datetime.now(dt_timezone.utc) >= expiry:
        _VT_RATE_LIMITED.pop(kid, None)
        return False
    return True


def _vt_mark_rate_limited(api_key):
    """Cool the key off for the per-minute window only — NOT the whole day.
    The free tier's 4 req/min limit recovers on its own in ~60 seconds.

    Also clears any stale `_VT_QUOTA_EXHAUSTED` marker for this key — earlier
    builds mis-classified per-minute throttles as daily-quota hits, and we
    want those markers to evaporate on the next live probe rather than
    waiting for UTC midnight."""
    kid = _vt_key_id(api_key)
    if kid in _VT_QUOTA_EXHAUSTED:
        _VT_QUOTA_EXHAUSTED.pop(kid, None)
        logger.info("VirusTotal key %s: cleared stale exhausted marker", kid)
    reset = datetime.now(dt_timezone.utc) + timedelta(seconds=_VT_RATE_LIMIT_COOLDOWN_SECS)
    _VT_RATE_LIMITED[kid] = reset
    logger.info(
        "VirusTotal key %s per-minute rate-limited; resting %ds",
        kid, _VT_RATE_LIMIT_COOLDOWN_SECS,
    )


def _vt_parse_keys(raw):
    """Split a stored multi-key value (newline/comma separated) into a
    deduplicated ordered list."""
    if not raw:
        return []
    out, seen = [], set()
    for chunk in str(raw).replace(',', '\n').replace('\r', '\n').split('\n'):
        k = chunk.strip()
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _get_api_keys():
    """Return the configured VirusTotal API keys in rotation order for one
    request. Fresh keys come first, transiently rate-limited keys as a
    secondary tier, daily-exhausted keys as a last-ditch fallback. Empty list
    when the integration is disabled or no key is configured.

    Within each tier the order is **randomized on every call**, so quota is
    spread evenly across keys instead of draining the first one before
    touching the second. Two concurrent lookups pick independently, giving
    us free horizontal parallelism up to N × per-minute-cap requests.
    """
    try:
        from apps.settings_app.cache import SettingsCache
        if not SettingsCache.get('threat_intel.virustotal_enabled', False):
            return []
        raw = SettingsCache.get('threat_intel.virustotal_api_key', '') or ''
    except Exception:
        return []
    keys = _vt_parse_keys(raw)
    if not keys:
        return []
    fresh = [k for k in keys
             if not _vt_is_exhausted(k) and not _vt_is_rate_limited(k)]
    rate_limited = [k for k in keys
                    if _vt_is_rate_limited(k) and not _vt_is_exhausted(k)]
    exhausted = [k for k in keys if _vt_is_exhausted(k)]
    random.shuffle(fresh)
    random.shuffle(rate_limited)
    random.shuffle(exhausted)
    return fresh + rate_limited + exhausted


def _get_api_key():
    """Back-compat shim — first available key or None. Kept so the scheduler
    and management commands that only test "is a key usable?" keep working."""
    keys = _get_api_keys()
    return keys[0] if keys else None


def _classify_429(http_error):
    """Decide whether a 429 is a transient per-minute throttle or the real
    daily quota. VT's `error.code` is `QuotaExceededError` for BOTH cases
    (verified against the live API) so the code alone is ambiguous — the
    only reliable signal is `Retry-After`: free-tier per-minute throttle
    advertises ≤ ~60s, daily quota advertises hours. When the header is
    missing we err on the transient side so we don't kill a perfectly
    good key for the rest of the day on a brief throttle."""
    try:
        retry_after = int(http_error.headers.get('Retry-After', '') or 0)
    except (TypeError, ValueError):
        retry_after = 0
    # >1h cooldown means daily quota; otherwise treat as per-minute throttle.
    return 'quota_exhausted' if retry_after > 3600 else 'rate_limited'


def _vt_request(api_key, url_value):
    """Look up a URL or bare-domain input on VirusTotal.

    Endpoint selection matches what the VT UI shows the user:
      * bare domain (no scheme, no path)  -> `/api/v3/domains/{domain}`
        (aggregate stats -- what VT UI shows when you search a domain)
      * full URL or path-carrying input   -> `/api/v3/urls/{sha256}`

    Without this split, adding a domain like `phishing.example` would only
    score the empty-path root URL (`https://phishing.example/`) and miss
    detections that come from specific paths (`/login`, `/download`, etc.);
    VT's UI aggregates those under the domain, which is why the two counts
    used to disagree.

    Returns (attrs_dict, status) where status is 'ok' | 'not_found'. Raises
    _VTQuotaExhausted / _VTRateLimited for the two 429 flavors.
    """
    if _is_bare_domain(url_value):
        vt_url = _VT_DOMAIN.format(urllib.parse.quote(url_value.strip().lower(), safe=''))
    else:
        from apps.urllist.models import url_sha256
        vt_url = _VT_URL.format(url_sha256(url_value))
    req = urllib.request.Request(
        vt_url,
        headers={'x-apikey': api_key, 'Accept': 'application/json'},
    )
    from apps.settings_app.net_util import build_ssl_context
    try:
        with urllib.request.urlopen(req, timeout=30, context=build_ssl_context()) as resp:
            data = json.loads(resp.read().decode())
        return (data.get('data', {}).get('attributes', {}) or {}, 'ok')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ({}, 'not_found')
        if e.code == 429:
            kind = _classify_429(e)
            if kind == 'quota_exhausted':
                raise _VTQuotaExhausted(f"VT key {_vt_key_id(api_key)} daily quota exhausted.") from e
            raise _VTRateLimited(f"VT key {_vt_key_id(api_key)} per-minute throttle.") from e
        raise


def fetch_url_data(url_value):
    """
    Query VirusTotal for a single URL and return the data.attributes dict.

    Iterates configured API keys in rotation order: a key that returns HTTP
    429 is flagged as exhausted for the rest of the UTC day and the next key
    is tried. Returns:
      - dict (possibly with enrichment fields) on success
      - {} when the hash is not found (404) — treated as "unknown/clean"
      - None on disabled / all keys failed / unrecoverable error
    """
    keys = _get_api_keys()
    if not keys:
        return None
    # Only try keys that aren't already flagged as rate-limited or exhausted.
    # `_get_api_keys()` returns them in [fresh, rate_limited, exhausted] order
    # for callers that want a best-effort attempt, but blindly iterating the
    # tail tiers here is the classic amplification bug: a bulk refresh over N
    # hashes turns into N × K real HTTP calls to VT for keys we already know
    # are throttled or done for the day.
    keys = [k for k in keys if not _vt_is_rate_limited(k) and not _vt_is_exhausted(k)]
    if not keys:
        logger.info("VirusTotal: no fresh keys available for %s — skipping lookup", url_value[:60])
        return None
    last_err = None
    for api_key in keys:
        try:
            attrs, status = _vt_request(api_key, url_value)
        except _VTQuotaExhausted:
            _vt_mark_exhausted(api_key)
            continue
        except _VTRateLimited:
            _vt_mark_rate_limited(api_key)
            continue
        except urllib.error.HTTPError as e:
            logger.warning("VirusTotal HTTP error for %s with key %s: %s",
                           url_value[:60], _vt_key_id(api_key), e)
            last_err = e
            continue
        except Exception as e:
            logger.warning("VirusTotal query failed for %s with key %s: %s",
                           url_value[:60], _vt_key_id(api_key), e)
            last_err = e
            continue
        if status == 'not_found':
            logger.info("VirusTotal: URL %s not found (404)", url_value[:60])
            return {}
        return attrs
    logger.warning(
        "VirusTotal: all %d configured key(s) failed for %s: %s",
        len(keys), url_value[:60], last_err
    )
    return None


def _stats_from_attrs(attrs):
    """Extract (malicious, total) from a VT attributes dict."""
    stats = (attrs or {}).get('last_analysis_stats', {}) or {}
    malicious = int(stats.get('malicious', 0))
    # Mirror VirusTotal UI: exclude 'type-unsupported' and 'timeout' from total
    total = sum(int(stats.get(k, 0)) for k in ('malicious', 'suspicious', 'undetected', 'harmless'))
    return malicious, total


def check_url(url_value):
    """
    Query VirusTotal for a single URL.
    Returns (malicious, total) tuple or None on failure/disabled.
    """
    attrs = fetch_url_data(url_value)
    if attrs is None:
        return None
    malicious, total = _stats_from_attrs(attrs)
    logger.debug("VirusTotal check %s: malicious=%d total=%d", url_value[:60], malicious, total)
    return malicious, total


def check_url_with_timeout(url_value, timeout=30):
    """
    Query VirusTotal with a hard wall-clock timeout.
    Returns (malicious, total) or None.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(check_url, url_value)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            logger.warning("VirusTotal query timed out after %ds for %s", timeout, url_value[:60])
            return None
        except Exception as e:
            logger.warning("VirusTotal query error for %s: %s", url_value[:60], e)
            return None


def fetch_url_data_with_timeout(url_value, timeout=30):
    """Like fetch_url_data but with a hard wall-clock timeout. Returns dict/{}/None."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(fetch_url_data, url_value)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            logger.warning("VirusTotal query timed out after %ds for %s", timeout, url_value[:60])
            return None
        except Exception as e:
            logger.warning("VirusTotal query error for %s: %s", url_value[:60], e)
            return None


def _epoch_to_dt(value):
    """Convert a Unix epoch (seconds) to an aware datetime, or None."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=dt_timezone.utc)
    except (ValueError, TypeError, OSError, OverflowError):
        return None


def _safe_int(value):
    """Convert numeric-ish values to int; return None for anything else."""
    if isinstance(value, bool):        # bool is an int subclass — reject.
        return None
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (ValueError, OverflowError):
            return None
    return None


def _extract_serving_ip(attrs):
    """Try to find the IP that served the URL/domain during the last VT crawl.

    Several fields can carry it depending on endpoint + response shape:
      * URL endpoint  -> `last_http_response_headers` sometimes carries an
        `x-served-by` or `server` string (rare; skip); more reliably the sibling
        `last_http_response_headers` dict is *not* the source. VT exposes the
        resolved IP under `last_analysis_results` per engine, which is noisy.
      * Domain endpoint -> `last_dns_records` (type A / AAAA) gives the
        resolved IPs directly.
    We prefer DNS A/AAAA records when present (deterministic), then fall back
    to `last_http_response_headers` if VT included a `x-cache-served-by`-like
    header. Returns '' when no reliable IP is available.
    """
    # 1) Domain endpoint — DNS A/AAAA records
    dns = attrs.get('last_dns_records') or []
    if isinstance(dns, list):
        for rec in dns:
            if not isinstance(rec, dict):
                continue
            if str(rec.get('type', '')).upper() in ('A', 'AAAA'):
                val = str(rec.get('value') or '').strip()
                if val:
                    return val[:45]
    # 2) URL endpoint — some response headers include an IP
    hdrs = attrs.get('last_http_response_headers') or {}
    if isinstance(hdrs, dict):
        for key in ('x-served-by', 'x-cache-served-by', 'x-origin-server', 'x-real-ip'):
            val = hdrs.get(key) or hdrs.get(key.title())
            if val:
                return str(val).strip()[:45]
    return ''


def _extract_popularity_rank(attrs):
    """Return the best (lowest, i.e. most popular) rank across VT's popularity
    sources — Cisco Umbrella, Alexa, Statvoo, Majestic, etc. Returns None if
    the endpoint didn't return `popularity_ranks` (URL endpoint has none)."""
    ranks = attrs.get('popularity_ranks') or {}
    if not isinstance(ranks, dict):
        return None
    best = None
    for entry in ranks.values():
        if not isinstance(entry, dict):
            continue
        r = _safe_int(entry.get('rank'))
        if r is None or r <= 0:
            continue
        if best is None or r < best:
            best = r
    return best


def _store_vt_metadata(entry, attrs, update_fields):
    """Copy VirusTotal enrichment fields from a URL- or domain-scan response
    onto the entry. The two endpoints share several fields (categories,
    reputation, votes, tags, last_analysis_stats) but each also has exclusive
    ones — URL: `last_http_response_*`, `title`, `redirection_chain`; domain:
    `whois`, `creation_date`, `registrar`, `popularity_ranks`. Every field is
    read defensively so a missing key leaves the corresponding column blank.
    """
    if not attrs:
        return
    label = (attrs.get('popular_threat_classification') or {}).get('suggested_threat_label') or ''
    # `categories` is a vendor-keyed dict; collapse the values into a
    # comma-joined, de-duplicated list of the labels themselves.
    cats_dict = attrs.get('categories') or {}
    cats = sorted({str(v).strip() for v in cats_dict.values() if v})
    submitted = attrs.get('times_submitted')

    # last_analysis_stats breakdown — one number per bucket (VT UI shows these
    # in the sunburst on the right of the report page).
    stats = attrs.get('last_analysis_stats') or {}
    if not isinstance(stats, dict):
        stats = {}

    # total_votes → community verdict
    votes = attrs.get('total_votes') or {}
    if not isinstance(votes, dict):
        votes = {}

    # VT tags → comma-joined (already a flat list in the response)
    tags_raw = attrs.get('tags') or []
    tags = [str(t).strip() for t in tags_raw if str(t or '').strip()] if isinstance(tags_raw, list) else []

    # html_meta / detected languages — either under `html_meta.language` (list)
    # or under top-level `languages` (dict[lang -> count]).
    langs = set()
    hm = attrs.get('html_meta') or {}
    if isinstance(hm, dict):
        for v in (hm.get('language') or []):
            if isinstance(v, str) and v.strip():
                langs.add(v.strip())
    lg = attrs.get('languages') or {}
    if isinstance(lg, dict):
        for k in lg.keys():
            if isinstance(k, str) and k.strip():
                langs.add(k.strip())

    # Redirect chain length (URL endpoint). Missing → None (kept nullable so
    # the template can distinguish "no data" from "0 redirects" if it wants).
    chain = attrs.get('redirection_chain') or []
    redirect_count = len(chain) if isinstance(chain, list) else None

    entry.vt_threat_label    = str(label)[:255]
    entry.vt_categories      = (', '.join(cats))[:255]
    entry.vt_final_url       = str(attrs.get('last_final_url') or '')[:MAX_META_URL]
    entry.vt_title           = str(attrs.get('title') or '')[:255]
    entry.vt_first_seen      = _epoch_to_dt(attrs.get('first_submission_date'))
    entry.vt_last_analysis   = _epoch_to_dt(attrs.get('last_analysis_date'))
    entry.vt_times_submitted = _safe_int(submitted)

    # Extended enrichment
    entry.vt_reputation      = _safe_int(attrs.get('reputation'))
    entry.vt_votes_harmless  = _safe_int(votes.get('harmless'))
    entry.vt_votes_malicious = _safe_int(votes.get('malicious'))
    entry.vt_http_code       = _safe_int(attrs.get('last_http_response_code'))
    entry.vt_content_length  = _safe_int(attrs.get('last_http_response_content_length'))
    entry.vt_redirect_count  = redirect_count
    entry.vt_serving_ip      = _extract_serving_ip(attrs)
    entry.vt_tags            = (', '.join(tags))[:255]
    entry.vt_languages       = (', '.join(sorted(langs)))[:255]
    entry.vt_harmless        = _safe_int(stats.get('harmless'))
    entry.vt_suspicious      = _safe_int(stats.get('suspicious'))
    entry.vt_undetected      = _safe_int(stats.get('undetected'))

    # Domain-endpoint-only fields
    entry.vt_registrar       = str(attrs.get('registrar') or '')[:255]
    entry.vt_creation_date   = _epoch_to_dt(attrs.get('creation_date'))
    entry.vt_popularity_rank = _extract_popularity_rank(attrs)

    update_fields += [
        'vt_threat_label', 'vt_categories', 'vt_final_url', 'vt_title',
        'vt_first_seen', 'vt_last_analysis', 'vt_times_submitted',
        'vt_reputation', 'vt_votes_harmless', 'vt_votes_malicious',
        'vt_http_code', 'vt_content_length', 'vt_redirect_count',
        'vt_serving_ip', 'vt_tags', 'vt_languages',
        'vt_harmless', 'vt_suspicious', 'vt_undetected',
        'vt_registrar', 'vt_creation_date', 'vt_popularity_rank',
    ]


# Cap for the enrichment `final_url` column so a pathological redirect chain
# doesn't blow up the row.
MAX_META_URL = 2000


def _get_threshold():
    """Return the configured VT detection threshold (int). 0 means disabled."""
    try:
        from apps.settings_app.cache import SettingsCache
        return max(0, int(SettingsCache.get('threat_intel.virustotal_detection_threshold', 5)))
    except Exception:
        return 5


def _apply_score_to_entry(entry, malicious, total, now, meta=None):
    """
    Save VT score to a URLEntry and apply threshold-based activation/deactivation.

    - vt_checked_at is always updated.
    - vt_malicious/vt_total are updated only when values change.
    - If threshold > 0: malicious >= threshold → is_active=True; else → is_active=False.
    - If threshold == 0: is_active is not touched (feature disabled).

    meta: the full VT attributes dict; enrichment fields are stored when present.
    """
    update_fields = ['vt_checked_at']
    entry.vt_checked_at = now
    _store_vt_metadata(entry, meta, update_fields)

    # Clear the "VT was unreachable" marker -- this call is proof VT answered
    # for this hash, so it belongs in the /api/v1/urllist/ feed again.
    if entry.vt_unavailable:
        entry.vt_unavailable = False
        update_fields.append('vt_unavailable')

    score_changed = (entry.vt_malicious != malicious or entry.vt_total != total)
    if score_changed:
        entry.vt_malicious = malicious
        entry.vt_total = total
        update_fields += ['vt_malicious', 'vt_total']
        logger.info(
            "VirusTotal: %s → malicious=%d/%d",
            entry.url_value[:60], malicious, total,
        )

    threshold = _get_threshold()
    if threshold > 0:
        if entry.is_pinned:
            logger.info(
                "VirusTotal: %s pinned — skipping deactivation (malicious=%d/%d, threshold=%d)",
                entry.url_value[:60], malicious, total, threshold,
            )
        else:
            should_be_active = malicious >= threshold
            if entry.is_active != should_be_active:
                entry.is_active = should_be_active
                update_fields.append('is_active')
                logger.info(
                    "VirusTotal threshold: %s %s (malicious=%d/%d, threshold=%d)",
                    entry.url_value[:60],
                    'activated' if should_be_active else 'deactivated',
                    malicious, total, threshold,
                )

    entry.save(update_fields=update_fields)
    return score_changed


def update_entry_score(entry):
    """
    Query VirusTotal for a single URLEntry and save the result.
    Returns (malicious, total) or None.
    """
    attrs = fetch_url_data(entry.url_value)
    if attrs is None:
        return None
    malicious, total = _stats_from_attrs(attrs)
    _apply_score_to_entry(entry, malicious, total, timezone.now(), meta=attrs)
    return malicious, total


def reapply_vt_threshold():
    """
    Re-evaluate all VT-scored black-list entries against the current threshold.
    Activates entries whose malicious count >= threshold, deactivates the rest.
    Returns (activated, deactivated).
    """
    from apps.urllist.models import URLEntry

    threshold = _get_threshold()
    if threshold == 0:
        return 0, 0

    entries = URLEntry.objects.filter(
        list_type=URLEntry.LIST_BLACK,
        vt_checked_at__isnull=False,
    )

    activated = deactivated = 0
    for entry in entries:
        if entry.is_pinned:
            continue
        should_be_active = entry.vt_malicious >= threshold
        if entry.is_active != should_be_active:
            entry.is_active = should_be_active
            entry.save(update_fields=['is_active'])
            if should_be_active:
                activated += 1
                logger.info("VT reapply: %s re-activated (malicious=%d, threshold=%d)",
                            entry.url_value[:60], entry.vt_malicious, threshold)
            else:
                deactivated += 1
                logger.info("VT reapply: %s deactivated (malicious=%d, threshold=%d)",
                            entry.url_value[:60], entry.vt_malicious, threshold)

    logger.info("VT threshold reapply: activated=%d deactivated=%d (threshold=%d)",
                activated, deactivated, threshold)
    return activated, deactivated


def bulk_refresh(only_unchecked=False):
    """
    Query VirusTotal for all active black-list hash entries.
    If only_unchecked=True, skip entries that already have a score.
    Returns (checked_count, skipped_count, failed_count).
    """
    from apps.urllist.models import URLEntry

    # fetch_url_data() handles the key rotation internally — here we just
    # need to confirm at least one key is configured before walking the queryset.
    if not _get_api_keys():
        return 0, 0, 0

    now = timezone.now()
    qs = URLEntry.objects.filter(is_active=True, list_type=URLEntry.LIST_BLACK, is_pinned=False)
    if only_unchecked:
        qs = qs.filter(vt_checked_at__isnull=True)

    pinned_count = URLEntry.objects.filter(is_active=True, list_type=URLEntry.LIST_BLACK, is_pinned=True).count()

    checked = failed = 0
    skipped = pinned_count
    for entry in qs:
        attrs = fetch_url_data_with_timeout(entry.url_value, timeout=30)
        if attrs is None:
            failed += 1
        else:
            malicious, total = _stats_from_attrs(attrs)
            _apply_score_to_entry(entry, malicious, total, now, meta=attrs)
            checked += 1

    logger.info(
        "VirusTotal bulk refresh: checked=%d skipped=%d failed=%d",
        checked, skipped, failed,
    )
    return checked, skipped, failed
