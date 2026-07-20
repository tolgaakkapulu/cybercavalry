import logging
import hashlib
import concurrent.futures
from datetime import datetime, timedelta, timezone as dt_timezone
from django.utils import timezone

logger = logging.getLogger(__name__)


_CHECK_URL = 'https://api.abuseipdb.com/api/v2/check'


class QuotaExhaustedError(Exception):
    """Raised when an AbuseIPDB key has hit its daily request quota (HTTP 429
    or an API error message indicating rate-limit exhaustion). Distinguishes
    quota from generic errors so the caller can rotate to the next key
    instead of giving up."""


# Module-level register of keys we already know are out of quota for the
# current AbuseIPDB billing window. Maps `_key_id(key) -> reset_utc_datetime`
# so we skip exhausted keys quickly and stop hammering them. Cleared lazily
# when a marker has passed its reset time (next UTC midnight by default).
_QUOTA_EXHAUSTED = {}


def _key_id(api_key):
    """Stable short identifier for log lines so we never write the raw key."""
    return hashlib.sha1(api_key.encode('utf-8')).hexdigest()[:8]


def _next_utc_reset():
    """AbuseIPDB's free-tier daily quota resets at 00:00 UTC — return the next
    occurrence so exhausted-key markers expire at the right time."""
    now_utc = datetime.now(dt_timezone.utc)
    next_midnight = now_utc.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    return next_midnight


def _is_exhausted(api_key):
    kid = _key_id(api_key)
    expiry = _QUOTA_EXHAUSTED.get(kid)
    if expiry is None:
        return False
    if datetime.now(dt_timezone.utc) >= expiry:
        _QUOTA_EXHAUSTED.pop(kid, None)
        return False
    return True


def _mark_exhausted(api_key):
    kid = _key_id(api_key)
    reset = _next_utc_reset()
    _QUOTA_EXHAUSTED[kid] = reset
    logger.warning(
        "AbuseIPDB key %s daily quota exhausted; rotated out until %s UTC",
        kid, reset.isoformat()
    )


def _parse_keys(raw):
    """Split a stored multi-key value into a deduplicated ordered list.

    Accepts newline, comma, or whitespace separators so users can paste any
    reasonable shape (one-per-line, comma-separated, …). Empty strings drop."""
    if not raw:
        return []
    out = []
    seen = set()
    for chunk in str(raw).replace(',', '\n').replace('\r', '\n').split('\n'):
        k = chunk.strip()
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _get_api_keys():
    """Return the list of configured AbuseIPDB API keys in rotation order
    (fresh keys first, then any keys currently flagged as quota-exhausted as
    a final fallback in case their reset already happened). Returns [] if the
    integration is disabled or no key is configured.

    Also applies the portable CA bundle so corporate SSL inspection / offline
    certifi is honoured (no-op without config).
    """
    from apps.settings_app.cache import SettingsCache
    if not SettingsCache.get('threat_intel.abuseipdb_enabled', False):
        return []
    raw = SettingsCache.get('threat_intel.abuseipdb_api_key', '') or ''
    keys = _parse_keys(raw)
    if not keys:
        logger.warning("AbuseIPDB enabled but API key not configured.")
        return []
    try:
        from apps.settings_app.net_util import apply_requests_ca_env
        apply_requests_ca_env()
    except Exception:
        pass
    fresh = [k for k in keys if not _is_exhausted(k)]
    stale = [k for k in keys if _is_exhausted(k)]
    return fresh + stale


def _get_api_key():
    """Back-compat shim: return the first available API key, or None.

    Kept so the management command, scheduler, and any other callers that
    only need "is there a usable key?" keep working without per-call changes."""
    keys = _get_api_keys()
    return keys[0] if keys else None


def _get_max_age():
    """Return the configured maxAgeInDays as an int (default 30)."""
    from apps.settings_app.cache import SettingsCache
    try:
        return int(SettingsCache.get('threat_intel.abuseipdb_max_age_days', 30))
    except (TypeError, ValueError):
        return 30


def _api_check(api_key, ip_address, max_age):
    """Call AbuseIPDB /check directly and return the data dict.

    The 'verbose' flag is required: without it the API omits countryName
    (it returns only countryCode). The abuseipdb-wrapper does not send verbose,
    so we issue the request ourselves.

    Raises QuotaExhaustedError on HTTP 429 or an API error message indicating
    rate-limit exhaustion so the caller can rotate to the next key. Raises
    ValueError for other API-reported errors.
    """
    import requests
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': str(int(max_age)),
        'verbose': '',   # presence of the flag enables the verbose response (countryName, ...)
    }
    headers = {'Accept': 'application/json', 'Key': api_key}
    resp = requests.get(_CHECK_URL, headers=headers, params=params, timeout=30)
    if resp.status_code == 429:
        raise QuotaExhaustedError(
            f"AbuseIPDB key {_key_id(api_key)} rate-limited (HTTP 429)."
        )
    try:
        decoded = resp.json()
    except ValueError:
        resp.raise_for_status()
        raise
    errors = decoded.get('errors')
    if errors:
        msg = ' '.join(str(e.get('detail', '')) for e in errors).lower()
        if 'rate limit' in msg or 'quota' in msg or 'exceeded' in msg:
            raise QuotaExhaustedError(
                f"AbuseIPDB key {_key_id(api_key)} quota exceeded: {errors}"
            )
        raise ValueError(f"AbuseIPDB API error: {errors}")
    return decoded.get('data', {}) or {}


def fetch_ip_data(ip_address):
    """Query AbuseIPDB for a single IP and return the full data dict, or None.

    Iterates the configured API keys in rotation order: on quota exhaustion
    the failing key is flagged for the rest of the day and the next key is
    tried. Returns None only when every configured key has failed (or the
    integration is disabled / unconfigured).
    """
    keys = _get_api_keys()
    if not keys:
        return None
    max_age = _get_max_age()
    last_err = None
    for api_key in keys:
        try:
            return _api_check(api_key, ip_address, max_age)
        except QuotaExhaustedError as e:
            _mark_exhausted(api_key)
            last_err = e
            continue
        except Exception as e:
            logger.warning(
                "AbuseIPDB check failed for %s with key %s: %s",
                ip_address, _key_id(api_key), e
            )
            last_err = e
            continue
    logger.warning(
        "AbuseIPDB: all %d configured key(s) failed for %s: %s",
        len(keys), ip_address, last_err
    )
    return None


def check_ip(ip_address):
    """
    Query AbuseIPDB for a single IP address.
    Returns the abuseConfidenceScore (int 0-100) or None on failure/disabled.
    """
    data = fetch_ip_data(ip_address)
    if data is None:
        return None
    score = data.get('abuseConfidenceScore')
    logger.debug(f"AbuseIPDB check {ip_address}: score={score}")
    return score


def _get_thresholds():
    """Read score thresholds from settings (with safe integer parsing)."""
    from apps.settings_app.cache import SettingsCache
    try:
        t30d = int(SettingsCache.get('threat_intel.abuseipdb_threshold_30d', 80))
    except (TypeError, ValueError):
        t30d = 80
    try:
        t24h = int(SettingsCache.get('threat_intel.abuseipdb_threshold_24h', 10))
    except (TypeError, ValueError):
        t24h = 10
    # Clamp to valid range and ensure 24h threshold < 30d threshold
    t30d = max(0, min(100, t30d))
    t24h = max(0, min(t30d - 1, t24h))
    return t24h, t30d


def _resolve_group_by_score(score):
    """
    Return the BlacklistGroup that matches the given score using configurable thresholds.
    score >= threshold_30d  → 30d group
    score >= threshold_24h  → 24h group
    score <  threshold_24h  → None (deactivate)
    """
    from apps.blacklist.models import BlacklistGroup
    t24h, t30d = _get_thresholds()
    if score >= t30d:
        group_name = '30d'
    elif score >= t24h:
        group_name = '24h'
    else:
        return None
    try:
        return BlacklistGroup.objects.get(name=group_name)
    except BlacklistGroup.DoesNotExist:
        logger.warning(f"BlacklistGroup '{group_name}' not found. Skipping group reassignment.")
        return None


def _parse_reported_at(value):
    """Parse AbuseIPDB 'lastReportedAt' (ISO 8601) into an aware datetime, or None."""
    if not value:
        return None
    try:
        from django.utils.dateparse import parse_datetime
        dt = parse_datetime(str(value))
        if dt is None:
            return None
        if timezone.is_naive(dt):
            dt = timezone.make_aware(dt, dt_timezone.utc)
        return dt
    except Exception:
        return None


def _store_metadata(entry, meta, update_fields):
    """Copy AbuseIPDB enrichment fields from the response dict onto the entry."""
    if not meta:
        return
    hostnames = meta.get('hostnames') or []
    if not isinstance(hostnames, list):
        hostnames = []
    entry.abuse_isp          = (meta.get('isp') or '')[:255]
    entry.abuse_usage_type   = (meta.get('usageType') or '')[:120]
    entry.abuse_domain       = (meta.get('domain') or '')[:255]
    entry.abuse_hostnames    = [str(h)[:255] for h in hostnames if h][:10]
    entry.abuse_country_code = (meta.get('countryCode') or '')[:2]
    entry.abuse_country_name = (meta.get('countryName') or '')[:100]
    # AbuseIPDB /check does not return ASN or city; populated only if present.
    entry.abuse_asn          = str(meta.get('asn') or meta.get('ASN') or '')[:32]
    entry.abuse_city         = (meta.get('city') or '')[:120]
    reports = meta.get('totalReports')
    entry.abuse_total_reports    = int(reports) if isinstance(reports, (int, float)) else None
    entry.abuse_last_reported_at = _parse_reported_at(meta.get('lastReportedAt'))
    update_fields += [
        'abuse_isp', 'abuse_usage_type', 'abuse_domain', 'abuse_hostnames',
        'abuse_country_code', 'abuse_country_name', 'abuse_asn', 'abuse_city',
        'abuse_total_reports', 'abuse_last_reported_at',
    ]


def _apply_score_to_entry(entry, score, now, meta=None):
    """Save score, reassign group by severity, or deactivate if score is below the 24h threshold.
    Pinned entries: score is recorded but group reassignment and deactivation are skipped.

    Expiry refresh: expires_at is reset only when the score value changes compared to the
    previously stored score, or when the entry moves to a different group.
    If the score is identical to the last recorded value, expires_at is left untouched.

    meta: the full AbuseIPDB response dict; enrichment fields are stored when present.
    """
    t24h, _ = _get_thresholds()

    prev_score = entry.abuse_confidence_score  # None if never checked before
    score_changed = (prev_score != score)

    entry.abuse_confidence_score = score
    entry.abuse_checked_at = now
    update_fields = ['abuse_confidence_score', 'abuse_checked_at']
    _store_metadata(entry, meta, update_fields)

    if entry.is_pinned:
        logger.info(
            f"AbuseIPDB: {entry.ip_address} score={score} — pinned, skipping group/status changes"
        )
    elif score < t24h:
        # Below minimum threshold — deactivate and exclude from published lists
        if entry.is_active:
            entry.is_active = False
            update_fields.append('is_active')
            logger.info(
                f"AbuseIPDB: {entry.ip_address} score={score} < {t24h} → deactivated"
            )
    else:
        target_group = _resolve_group_by_score(score)
        # Promotion override: a 24h verdict from the score check can be
        # escalated to 30d when the entry has accumulated enough API reports
        # (Settings → Threat Intel → 24h → 30d Promotion Threshold). This
        # models "the IP keeps coming back — treat it as persistent" and
        # beats the point-in-time score alone. Empty/0 threshold disables
        # the promotion entirely.
        if target_group and target_group.name == '24h':
            try:
                from apps.settings_app.cache import SettingsCache
                promo_threshold = int(
                    SettingsCache.get('threat_intel.abuseipdb_promotion_threshold', 0) or 0
                )
            except (TypeError, ValueError):
                promo_threshold = 0
            try:
                promo_window = int(
                    SettingsCache.get('threat_intel.abuseipdb_promotion_window_days', 7) or 7
                )
            except (TypeError, ValueError):
                promo_window = 7
            promo_window = max(1, min(30, promo_window))
            recent_hits = entry.count_recent_hits_within(promo_window)
            if promo_threshold > 0 and recent_hits >= promo_threshold:
                from apps.blacklist.models import BlacklistGroup as _BLG
                thirty_day = _BLG.objects.filter(name='30d').first()
                if thirty_day is not None:
                    logger.info(
                        f"AbuseIPDB: {entry.ip_address} score={score} → 24h by score,"
                        f" but recent_hits({promo_window}d)={recent_hits} ≥ threshold {promo_threshold}"
                        f" → promoted to 30d"
                    )
                    target_group = thirty_day
        if target_group:
            group_changed = target_group.pk != entry.group_id
            if group_changed:
                from apps.blacklist.models import BlacklistEntry as _BLE
                duplicate_exists = _BLE.objects.filter(
                    cidr=entry.cidr, group=target_group
                ).exclude(pk=entry.pk).exists()
                if duplicate_exists:
                    logger.info(
                        f"AbuseIPDB: {entry.ip_address} score={score} → would move to"
                        f" '{target_group.name}' but duplicate already exists; skipping group change"
                    )
                    group_changed = False
                else:
                    old_group = entry.group.name if entry.group_id else '?'
                    entry.group = target_group
                    update_fields.append('group')
                    logger.info(
                        f"AbuseIPDB: {entry.ip_address} score={score} → moved from '{old_group}' to '{target_group.name}'"
                    )

            # Refresh expiry only when score or group has changed
            if score_changed or group_changed:
                old_expires_at = entry.expires_at
                entry.set_expiry_from_group()
                if entry.expires_at != old_expires_at:
                    update_fields.append('expires_at')
                    logger.info(
                        f"AbuseIPDB: {entry.ip_address} score={score} → expires_at extended to {entry.expires_at}"
                    )

    entry.save(update_fields=update_fields)


def check_ip_with_timeout(ip_address, timeout=30):
    """
    Query AbuseIPDB with a hard timeout (seconds).
    Returns the abuseConfidenceScore or None if disabled/timeout/error.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(check_ip, ip_address)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            logger.warning(f"AbuseIPDB query timed out after {timeout}s for {ip_address}")
            return None
        except Exception as e:
            logger.warning(f"AbuseIPDB query error for {ip_address}: {e}")
            return None


def fetch_ip_data_with_timeout(ip_address, timeout=30):
    """
    Like fetch_ip_data but with a hard wall-clock timeout. Returns the full
    AbuseIPDB attributes dict (score + ISP + country + hostnames + …) or None
    on disabled/timeout/error.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(fetch_ip_data, ip_address)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            logger.warning(f"AbuseIPDB query timed out after {timeout}s for {ip_address}")
            return None
        except Exception as e:
            logger.warning(f"AbuseIPDB query error for {ip_address}: {e}")
            return None


def update_entry_score(entry):
    """
    Query AbuseIPDB for a single BlacklistEntry, save the score,
    and reassign to the appropriate group based on severity.
    Returns the score or None.
    """
    data = fetch_ip_data(entry.ip_address)
    if data is None:
        return None
    score = data.get('abuseConfidenceScore')
    if score is not None:
        _apply_score_to_entry(entry, score, timezone.now(), meta=data)
    return score


def reapply_thresholds(promotion_only=False):
    """
    Re-evaluate blacklist entries against the current thresholds.

    promotion_only=False (default): full sweep — reactivates/deactivates
    entries based on score vs the 24h/30d bands AND reassigns groups. Call
    this when the score thresholds (24h/30d) themselves change.

    promotion_only=True: only the 24h ↔ 30d group reassignment based on
    the promotion rule (recent hits within window vs threshold). Runs
    ONLY over currently-active entries and NEVER toggles is_active — a
    promotion knob shouldn't wake up previously-deactivated rows; that
    belongs to a score-threshold change. Call this when only the
    promotion_threshold or promotion_window_days settings change.

    Returns (reactivated, deactivated, reassigned) counts. In
    promotion_only mode, reactivated and deactivated are always 0.
    """
    from apps.blacklist.models import BlacklistEntry, BlacklistGroup
    from django.utils import timezone

    t24h, t30d = _get_thresholds()
    now = timezone.now()

    # Read the promotion threshold + window once for the whole pass. Threshold
    # 0/empty means the feature is disabled — entries whose score maps to 24h
    # stay in 24h even if their recent count is high, so a disabled threshold
    # on this pass will DEMOTE previously-promoted entries back down to 24h.
    # Non-zero threshold + recent count over it promotes 24h-scored entries.
    from apps.settings_app.cache import SettingsCache
    try:
        promo_threshold = int(
            SettingsCache.get('threat_intel.abuseipdb_promotion_threshold', 0) or 0
        )
    except (TypeError, ValueError):
        promo_threshold = 0
    try:
        promo_window = int(
            SettingsCache.get('threat_intel.abuseipdb_promotion_window_days', 7) or 7
        )
    except (TypeError, ValueError):
        promo_window = 7
    promo_window = max(1, min(30, promo_window))

    # Pre-load groups to avoid per-entry DB hits
    groups = {g.name: g for g in BlacklistGroup.objects.all()}
    group_30d = groups.get('30d')
    group_24h = groups.get('24h')

    entries = BlacklistEntry.objects.filter(
        abuse_confidence_score__isnull=False
    ).select_related('group')

    reactivated = deactivated = reassigned = 0

    for entry in entries:
        score = entry.abuse_confidence_score
        update_fields = []

        # Pinned entries are exempt from all automatic changes
        if entry.is_pinned:
            continue

        # Promotion-only mode never touches dormant rows — an admin adjusting
        # the promotion threshold doesn't expect deactivated entries to wake
        # up. Score-threshold changes are the only path that can reactivate.
        if promotion_only and not entry.is_active:
            continue

        if score >= t30d:
            target_group = group_30d
        elif score >= t24h:
            target_group = group_24h
            # Promotion override — only applied on the 24h branch. When
            # promo_threshold is 0/empty this is a no-op, which is how a
            # disabled threshold demotes previously-promoted entries: they
            # fall back to the score-based 24h verdict.
            if promo_threshold > 0 and entry.count_recent_hits_within(promo_window) >= promo_threshold and group_30d:
                target_group = group_30d
        else:
            target_group = None

        # Promotion-only mode also skips the "score fell out of coverage"
        # branch — that's a score-threshold concern, not the promotion rule.
        if promotion_only and target_group is None:
            continue

        if target_group is None:
            if entry.is_active:
                entry.is_active = False
                update_fields.append('is_active')
                deactivated += 1
        else:
            if not promotion_only and not entry.is_active:
                entry.is_active = True
                update_fields.append('is_active')
                reactivated += 1

            if entry.group_id != target_group.pk:
                duplicate_exists = BlacklistEntry.objects.filter(
                    cidr=entry.cidr, group=target_group
                ).exclude(pk=entry.pk).exists()
                if not duplicate_exists:
                    entry.group = target_group
                    update_fields.append('group')
                    reassigned += 1
                else:
                    logger.info(
                        f"AbuseIPDB reapply: {entry.ip_address} → would move to"
                        f" '{target_group.name}' but duplicate exists; skipping"
                    )

            if update_fields:
                entry.set_expiry_from_group()
                update_fields.append('expires_at')

        if update_fields:
            entry.save(update_fields=update_fields)

    logger.info(
        f"AbuseIPDB threshold reapply: reactivated={reactivated}, "
        f"deactivated={deactivated}, reassigned={reassigned} "
        f"(thresholds: 24h={t24h}, 30d={t30d})"
    )
    return reactivated, deactivated, reassigned


def bulk_refresh(only_unchecked=False):
    """
    Query AbuseIPDB for all active blacklist entries.
    If only_unchecked=True, skip entries that already have a score.
    Returns (checked_count, skipped_count, failed_count).

    Rotates through every configured API key as quotas exhaust mid-run so a
    free-tier 1000/day cap on the first key does not stop the whole sweep —
    remaining entries are processed by the next key. The run only aborts
    when EVERY configured key is out of quota (or fails for another reason).
    """
    from apps.blacklist.models import BlacklistEntry

    keys = _get_api_keys()
    if not keys:
        return 0, 0, 0

    max_age = _get_max_age()
    now = timezone.now()

    # Pinned entries are excluded from auto-scoring; count them as skipped for the summary
    pinned_count = BlacklistEntry.objects.filter(is_active=True, is_pinned=True).count()

    qs = BlacklistEntry.objects.filter(is_active=True, is_pinned=False).select_related('group')
    if only_unchecked:
        qs = qs.filter(abuse_checked_at__isnull=True)

    checked = failed = 0
    skipped = pinned_count
    key_idx = 0   # cursor over the rotation list; advanced on quota errors
    aborted = False
    for entry in qs:
        # Each entry: try the current key, rotate forward on quota errors,
        # stop the whole run only when every key is out of quota.
        while True:
            while key_idx < len(keys) and _is_exhausted(keys[key_idx]):
                key_idx += 1
            if key_idx >= len(keys):
                aborted = True
                break
            api_key = keys[key_idx]
            try:
                data = _api_check(api_key, entry.ip_address, max_age)
            except QuotaExhaustedError:
                _mark_exhausted(api_key)
                key_idx += 1
                continue  # retry SAME entry with next key
            except Exception as e:
                logger.warning(
                    "AbuseIPDB bulk check failed for %s with key %s: %s",
                    entry.ip_address, _key_id(api_key), e
                )
                failed += 1
                break  # give up on this entry, move to next
            score = data.get('abuseConfidenceScore')
            if score is not None:
                _apply_score_to_entry(entry, score, now, meta=data)
                checked += 1
            else:
                skipped += 1
            break  # success path — exit retry-loop, move to next entry
        if aborted:
            logger.warning(
                "AbuseIPDB bulk refresh: all %d key(s) out of quota, aborting early",
                len(keys)
            )
            break

    logger.info(
        "AbuseIPDB bulk refresh: checked=%d, skipped=%d, failed=%d "
        "(keys configured=%d, exhausted=%d)",
        checked, skipped, failed, len(keys),
        sum(1 for k in keys if _is_exhausted(k))
    )
    return checked, skipped, failed
