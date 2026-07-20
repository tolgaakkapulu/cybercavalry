"""Quota status probes for AbuseIPDB and VirusTotal.

Used by the Actions → Quota Alert scheduler and the test-mail endpoint. Each
probe returns a normalized snapshot: `{'provider', 'configured', 'used',
'limit', 'usage_pct', 'error'}`. Interpretation:

  * `configured=False`            → provider disabled or no key at all
  * `limit=0`, `configured=True`  → the provider didn't expose a quota number
                                    (either an error or a plan with no cap)
  * `usage_pct`                   → integer 0–100 for threshold comparison

Deliberately duplicates a slim probe of the existing view logic so the check
can run from a scheduler thread without going through Django's request/view
stack. The 3rd-party HTTP shape is unchanged.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from apps.settings_app.cache import SettingsCache
from apps.settings_app.net_util import build_ssl_context

logger = logging.getLogger(__name__)


def _empty(provider: str, error: str = '') -> dict:
    return {
        'provider':   provider,
        'configured': False,
        'used':       0,
        'limit':      0,
        'remaining':  0,
        'usage_pct':  0,
        'error':      error,
    }


def check_abuseipdb_quota() -> dict:
    """Probe every configured AbuseIPDB key with the loopback IP and sum
    the daily quota headers (X-RateLimit-Limit / Remaining). Loopback
    queries are free of quota consumption on AbuseIPDB, so this is safe to
    run every hour."""
    if not SettingsCache.get('threat_intel.abuseipdb_enabled', False):
        return _empty('AbuseIPDB', 'AbuseIPDB is disabled in Settings.')

    raw = (SettingsCache.get('threat_intel.abuseipdb_api_key', '') or '').strip()
    from apps.blacklist.abuseipdb_service import _parse_keys
    keys = _parse_keys(raw)
    if not keys:
        return _empty('AbuseIPDB', 'No API key configured.')

    ctx = build_ssl_context()
    per_key_default = 1000  # free-tier daily cap for keys that couldn't report
    total_limit = total_used = total_remaining = 0
    keys_probed = 0

    for key in keys:
        url = ('https://api.abuseipdb.com/api/v2/check?'
               + urllib.parse.urlencode({'ipAddress': '127.0.0.1', 'maxAgeInDays': '1'}))
        req = urllib.request.Request(url, headers={'Key': key, 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                resp.read()
            daily_limit = int(hdrs.get('x-ratelimit-limit', 0) or 0)
            remaining   = int(hdrs.get('x-ratelimit-remaining', 0) or 0)
            used        = max(daily_limit - remaining, 0) if daily_limit else 0
            total_limit     += daily_limit
            total_used      += used
            total_remaining += remaining
            keys_probed += 1
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                # Exhausted — assume the free-tier daily cap for accounting.
                total_limit += per_key_default
                total_used  += per_key_default
                keys_probed += 1
            elif exc.code == 401:
                logger.warning("AbuseIPDB quota check: key rejected (401).")
            else:
                logger.warning("AbuseIPDB quota check HTTP %s", exc.code)
        except Exception as exc:
            logger.warning("AbuseIPDB quota check failed: %s", exc)

    if keys_probed == 0:
        return _empty('AbuseIPDB', 'All AbuseIPDB probes failed.')

    usage_pct = int(round(total_used / total_limit * 100)) if total_limit else 0
    return {
        'provider':   'AbuseIPDB',
        'configured': True,
        'used':       total_used,
        'limit':      total_limit,
        'remaining':  total_remaining,
        'usage_pct':  usage_pct,
        'error':      '',
    }


def check_virustotal_quota() -> dict:
    """Probe ONE VirusTotal key with the EICAR file hash, read either the
    response headers or `/users/me` for the daily quota, and extrapolate the
    per-account totals from the number of configured keys.

    Rationale: this runs on a scheduler (hourly by default) so probing every
    key each pass is a real quota leak — three keys × 24 checks/day is up to
    144 silent VT calls, dwarfing user-visible traffic. Probing a single
    representative key gives us the same alerting fidelity for a fraction of
    the cost. Keys that are already in-memory-flagged as rate-limited or
    exhausted are skipped so the probe doesn't hit a wall for no reason."""
    if not SettingsCache.get('threat_intel.virustotal_enabled', False):
        return _empty('VirusTotal', 'VirusTotal is disabled in Settings.')

    raw = (SettingsCache.get('threat_intel.virustotal_api_key', '') or '').strip()
    from apps.hashlist.virustotal_service import (
        _vt_parse_keys, _vt_is_rate_limited, _vt_is_exhausted, _vt_mark_exhausted,
    )
    keys = _vt_parse_keys(raw)
    if not keys:
        return _empty('VirusTotal', 'No API key configured.')

    total_keys = len(keys)
    per_key_default = 500  # free-tier daily cap for keys that couldn't report

    # Fast path — if every key is already flagged in-memory as daily-quota
    # exhausted, we don't need to touch VT at all. Return a synthetic "100%"
    # snapshot so the alert wires downstream still fire. This also handles
    # the case where VT's 429 didn't send a distinctive Retry-After header
    # and the classifier would otherwise misread it as per-minute throttle.
    if all(_vt_is_exhausted(k) for k in keys):
        limit = per_key_default * total_keys
        return {
            'provider':   'VirusTotal',
            'configured': True,
            'used':       limit,
            'limit':      limit,
            'remaining':  0,
            'usage_pct':  100,
            'error':      '',
        }

    # Prefer a key that isn't currently flagged; if all are flagged we accept
    # the first one so the monitor still reports the last known state instead
    # of silently returning "unknown".
    probe_key = next(
        (k for k in keys if not _vt_is_rate_limited(k) and not _vt_is_exhausted(k)),
        keys[0],
    )

    ctx = build_ssl_context()
    total_limit = total_used = total_remaining = 0
    keys_probed = 0

    def _safe_int(v):
        try:
            return int(v) if v is not None else 0
        except (ValueError, TypeError):
            return 0

    for key in [probe_key]:
        try:
            eicar_md5 = '44d88612fea8a8f36de82e1278abb02f'
            url = f'https://www.virustotal.com/api/v3/files/{eicar_md5}'
            req = urllib.request.Request(url, headers={'x-apikey': key, 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                resp.read()
            daily_limit     = (_safe_int(hdrs.get('x-apirate-limit'))
                               or _safe_int(hdrs.get('x-ratelimit-limit')))
            daily_remaining = (_safe_int(hdrs.get('x-apirate-remaining'))
                               or _safe_int(hdrs.get('x-ratelimit-remaining')))
            daily_used      = max(0, daily_limit - daily_remaining) if daily_limit else 0
            # Fall back to /users/me if headers were empty.
            if daily_limit == 0:
                try:
                    me_url = 'https://www.virustotal.com/api/v3/users/me'
                    mreq = urllib.request.Request(me_url, headers={'x-apikey': key, 'Accept': 'application/json'})
                    with urllib.request.urlopen(mreq, timeout=8, context=ctx) as mresp:
                        mdata = json.loads(mresp.read().decode())
                    quotas = mdata.get('data', {}).get('attributes', {}).get('quotas', {})
                    daily_quota = quotas.get('api_requests_daily', {})
                    if isinstance(daily_quota, dict) and daily_quota.get('allowed'):
                        daily_limit     = _safe_int(daily_quota.get('allowed'))
                        daily_used      = _safe_int(daily_quota.get('used'))
                        daily_remaining = max(0, daily_limit - daily_used)
                except Exception:
                    pass
            total_limit     += daily_limit
            total_used      += daily_used
            total_remaining += daily_remaining
            keys_probed += 1
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                # VT sends 429 for both real daily-quota exhaustion and the
                # transient per-minute throttle. Distinguish by, in priority
                # order: (1) `x-ratelimit-remaining: 0` header, (2) a
                # QuotaExceededError code in the JSON body, (3) a long
                # Retry-After (>1h). Free-tier daily quota often ships
                # WITHOUT a distinctive Retry-After, so header (1) is the
                # most reliable signal — checking Retry-After alone silently
                # miscategorises real exhaustion as a per-minute throttle
                # and the alert never fires.
                hdrs_l = {k.lower(): v for k, v in (exc.headers or {}).items()}
                h_remaining_raw = (hdrs_l.get('x-ratelimit-remaining')
                                   or hdrs_l.get('x-apirate-remaining'))
                h_remaining_is_zero = (
                    h_remaining_raw is not None
                    and str(h_remaining_raw).strip() == '0'
                )
                try:
                    retry_after = int(hdrs_l.get('retry-after', '') or 0)
                except (TypeError, ValueError):
                    retry_after = 0
                is_daily_exhausted = h_remaining_is_zero or retry_after > 3600
                if not is_daily_exhausted:
                    try:
                        body = exc.read().decode('utf-8', errors='replace')
                        parsed = json.loads(body) if body else {}
                        code = (parsed.get('error', {}) or {}).get('code', '')
                        if code == 'QuotaExceededError':
                            is_daily_exhausted = True
                    except Exception:
                        pass
                if is_daily_exhausted:
                    # Cache the exhaustion in-memory so subsequent probes
                    # skip this key via the fast path at the top of the
                    # function until the daily reset.
                    _vt_mark_exhausted(key)
                    total_limit += per_key_default
                    total_used  += per_key_default
                    keys_probed += 1
                else:
                    # per-minute throttle — key still healthy; count its capacity.
                    total_limit += per_key_default
                    keys_probed += 1
            elif exc.code == 401:
                logger.warning("VirusTotal quota check: key rejected (401).")
            else:
                logger.warning("VirusTotal quota check HTTP %s", exc.code)
        except Exception as exc:
            logger.warning("VirusTotal quota check failed: %s", exc)

    if keys_probed == 0:
        return _empty('VirusTotal', 'All VirusTotal probes failed.')

    # Scale the single-key probe up to the full key pool. This assumes each
    # key sits on the same plan (same daily cap) — which is the common case
    # for a free-tier stack. Alert semantics stay identical to the previous
    # per-key-probe behaviour: usage_pct is (sum of used / sum of caps).
    if total_keys > 1:
        total_limit     *= total_keys
        total_used      *= total_keys
        total_remaining *= total_keys

    usage_pct = int(round(total_used / total_limit * 100)) if total_limit else 0
    return {
        'provider':   'VirusTotal',
        'configured': True,
        'used':       total_used,
        'limit':      total_limit,
        'remaining':  total_remaining,
        'usage_pct':  usage_pct,
        'error':      '',
    }


def collect_quota_status() -> list[dict]:
    """Snapshot both providers' quota states in one call.

    Order is stable (AbuseIPDB first) so the mail template can index by
    position without magic string lookups.
    """
    return [check_abuseipdb_quota(), check_virustotal_quota()]
