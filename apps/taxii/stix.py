"""Blacklist rows → STIX 2.0 indicators.

Three feeds are published, one per platform blacklist, each selected by a
collection's `feed` value:

    url   URLEntry        → [domain-name:value = '…']  /  [url:value = '…']
    ip    BlacklistEntry  → [ipv4-addr:value = '…']    /  [ipv6-addr:value = '…']
    hash  HashEntry       → [file:hashes.'SHA-256' = '…']

Every feed's queryset is deliberately the *same predicate* its firewall
counterpart under `/api/v1/` uses, so the two consumers can never disagree
about what is currently blocked. If you change one, change the other.

Four consumer constraints shape everything here:

1. **Deep Discovery Director's filter.** Its docs state that over TAXII 2.0
   it ingests only `indicator` objects, and drops any labelled
   `anomalous-activity`, `anonymization`, `benign` or `compromised`, or
   marked `revoked`. STIX 2.0 makes `indicator.labels` a REQUIRED field
   drawn from `indicator-label-ov`, so `malicious-activity` is the only
   value that both satisfies the schema and survives DDD's filter. We
   never emit `revoked` — deactivated rows simply leave the feed.

2. **STIX 2.0, not 2.1.** Easy to get wrong: in 2.0 `spec_version` lives on
   the *bundle* only (SDOs gained it in 2.1), and `pattern_type` /
   `indicator_types` do not exist in 2.0 at all — they are 2.1 additions.
   Required indicator fields in 2.0: type, id, created, modified, labels,
   pattern, valid_from. There is no `confidence` property either, so the
   VirusTotal / AbuseIPDB verdicts go into `description` instead, where
   every consumer can at least read them.

3. **Indicator ids must be stable.** Each is `uuid5` over a per-feed
   identity string, so a subscriber that re-polls sees the same id and
   updates in place rather than accumulating duplicates. The URL feed's
   identity is its `url_hash` and must stay exactly that — changing it
   would orphan every indicator an existing subscriber already holds.

4. **Not every row is publishable.** A hash whose algorithm cannot be
   determined would produce an indicator no consumer can match, so those
   rows are filtered out rather than emitted with a guessed algorithm.

URL pattern choice mirrors how that list is actually used — mostly whole
malicious domains and subdomains, occasionally a specific path:

    phishing.example          → [domain-name:value = 'phishing.example']
    phishing.example/login    → [url:value = 'https://phishing.example/login']

`normalize_url()` strips the scheme on the way in, so a path-bearing entry
gets `https://` put back for the URL pattern (STIX `url:value` expects an
RFC 3986 URI). A bare host becomes a domain-name observable so the whole
host is covered rather than just its root document.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import timezone as dt_timezone

from django.db.models import Q
from django.utils import timezone

#: Stable namespace for uuid5 indicator ids. Fixed for the lifetime of the
#: project — see constraint 3 above. Never change this value.
INDICATOR_NAMESPACE = uuid.UUID('6f3d1c4a-9b2e-4d58-8a77-1e5c0b9f2a31')

#: The only label that is both valid in STIX 2.0's indicator-label-ov and
#: not on DDD's drop list.
INDICATOR_LABELS = ['malicious-activity']

STIX_MEDIA_TYPE = 'application/vnd.oasis.stix+json; version=2.0'


def stix_timestamp(dt) -> str:
    """STIX/TAXII timestamp: RFC 3339, UTC, millisecond precision, `Z`.
    Matches the spec's own examples (`2016-02-21T05:01:01.000Z`)."""
    if dt is None:
        return ''
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, dt_timezone.utc)
    dt = dt.astimezone(dt_timezone.utc)
    return f'{dt.strftime("%Y-%m-%dT%H:%M:%S")}.{dt.microsecond // 1000:03d}Z'


def _escape_pattern_literal(value: str) -> str:
    """Escape a STIX-patterning single-quoted string literal.

    Backslash first, then quote — reversing the order would double-escape
    the backslashes we just introduced.
    """
    return value.replace('\\', '\\\\').replace("'", "\\'")


def _later(base, *candidates):
    """The latest of `candidates` that is after `base`, else `base`.

    STIX forbids `modified` earlier than `created`, and enrichment
    timestamps can predate the row when an entry is re-imported.
    """
    best = base
    for c in candidates:
        if c and best and c > best:
            best = c
    return best


# ── URL feed ──────────────────────────────────────────────────────────────

def _has_port(host: str) -> bool:
    """True for `example.com:8443`, false for a bare host or an IPv6
    literal like `::1` (whose trailing segment is not all digits)."""
    if ':' not in host:
        return False
    return host.rsplit(':', 1)[-1].isdigit()


def pattern_for(url_value: str) -> str:
    """Build the STIX pattern for a stored `url_value`.

    Bare host → domain-name observable (covers every path under it).
    Anything with a path, query or explicit port → url observable.
    """
    from apps.urllist.models import _split_bare

    value = (url_value or '').strip()
    host, path = _split_bare(value)

    is_url = bool(path) or '?' in value or _has_port(host)
    if is_url:
        # Scheme was stripped at ingest; STIX url:value wants a full URI.
        return f"[url:value = '{_escape_pattern_literal('https://' + value)}']"
    return f"[domain-name:value = '{_escape_pattern_literal(host.lower())}']"


class _UrlFeed:
    """URL Blacklist → domain-name / url indicators."""

    feed = 'url'
    model = 'URLEntry'

    def queryset(self):
        """Deliberately the same predicate as `/api/v1/urllist/`.

        `vt_unavailable` rows are held back (VT was unreachable, so there is
        no verdict to stand behind) and `vt_not_found` rows are already
        excluded by `is_active=False`. Ordered ascending by date added, as
        §3.3 requires for the objects and manifest endpoints.
        """
        from apps.urllist.models import URLEntry
        return (
            URLEntry.objects
            .filter(is_active=True, list_type='black', vt_unavailable=False)
            .order_by('added_at', 'id')
        )

    def identity(self, entry) -> str:
        # Bare url_hash, with no prefix — this is what already shipped, and
        # prefixing it now would change every existing indicator's id.
        return entry.url_hash

    def pattern(self, entry) -> str:
        return pattern_for(entry.url_value)

    def name(self, entry) -> str:
        return f'Malicious: {entry.hostname or entry.url_value}'[:250]

    def modified(self, entry):
        return _later(entry.added_at, entry.vt_last_analysis)

    def description(self, entry) -> str:
        bits = []
        if entry.reason:
            bits.append(entry.reason.strip())
        if entry.vt_total:
            bits.append(f'VirusTotal: {entry.vt_malicious or 0}/{entry.vt_total} engines malicious')
        if entry.vt_threat_label:
            bits.append(f'Threat label: {entry.vt_threat_label}')
        if entry.vt_categories:
            bits.append(f'Categories: {entry.vt_categories}')
        bits.append(f'Source: {entry.get_source_display()}')
        return ' · '.join(bits)


# ── IP feed ───────────────────────────────────────────────────────────────

def _whitelisted_pks(qs) -> list:
    """PKs in `qs` that overlap a whitelist CIDR.

    The whitelist test is an IP-network *overlap*, which no portable SQL
    expression captures — the firewall feed resolves it in Python too
    (`filter_whitelisted`). Reducing it to a pk exclusion keeps
    `published_queryset` returning a real queryset, which the TAXII views
    need for `added_after`, Range slicing and `count()`.
    """
    from apps.blacklist.utils import get_whitelisted_cidrs

    networks = []
    for cidr in (get_whitelisted_cidrs() or []):
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    if not networks:
        return []

    out = []
    for pk, cidr in qs.values_list('pk', 'cidr'):
        try:
            target = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            # Unparseable row: the firewall feed keeps it rather than
            # silently dropping a block, so this feed does the same.
            continue
        # Comparing an IPv4 network with an IPv6 one raises TypeError, so
        # the version guard is load-bearing, not an optimisation.
        if any(target.version == n.version and target.overlaps(n) for n in networks):
            out.append(pk)
    return out


def _ip_pattern_value(entry) -> tuple[str, str]:
    """`(observable_type, value)` for an IP row.

    STIX 2.0 lets `ipv4-addr:value` hold either an address or a CIDR block.
    A full-length prefix is emitted as a bare address because that is what
    consumers match against most reliably; a real block keeps its prefix.
    """
    raw = (entry.cidr or '').strip() or str(entry.ip_address)
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        # Fall back to the stored address; `ip_address` is a validated
        # GenericIPAddressField, so it is the trustworthy half of the row.
        try:
            addr = ipaddress.ip_address(str(entry.ip_address))
        except ValueError:
            return 'ipv4-addr', raw
        return ('ipv6-addr' if addr.version == 6 else 'ipv4-addr'), str(addr)

    obs = 'ipv6-addr' if net.version == 6 else 'ipv4-addr'
    host_prefix = 128 if net.version == 6 else 32
    value = str(net.network_address) if net.prefixlen == host_prefix else str(net)
    return obs, value


class _IpFeed:
    """IP Blacklist → ipv4-addr / ipv6-addr indicators."""

    feed = 'ip'
    model = 'BlacklistEntry'

    def queryset(self):
        """Deliberately the same predicate as `/api/v1/blacklist/`:
        active, in a published group, not expired, and not overlapping the
        IP Whitelist."""
        from apps.blacklist.models import BlacklistEntry

        qs = (
            BlacklistEntry.objects
            .filter(is_active=True, group__is_published=True)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
            .select_related('group')
            .order_by('added_at', 'id')
        )
        excluded = _whitelisted_pks(qs)
        return qs.exclude(pk__in=excluded) if excluded else qs

    def identity(self, entry) -> str:
        # The CIDR, so a /24 block and the /32 of its base address stay
        # distinct indicators.
        return f'ip:{(entry.cidr or str(entry.ip_address)).strip().lower()}'

    def pattern(self, entry) -> str:
        obs, value = _ip_pattern_value(entry)
        return f"[{obs}:value = '{_escape_pattern_literal(value)}']"

    def name(self, entry) -> str:
        _, value = _ip_pattern_value(entry)
        return f'Malicious IP: {value}'[:250]

    def modified(self, entry):
        return _later(entry.added_at, entry.last_seen_at, entry.abuse_checked_at)

    def description(self, entry) -> str:
        bits = []
        if entry.reason:
            bits.append(entry.reason.strip())
        if entry.abuse_confidence_score is not None:
            bits.append(f'AbuseIPDB confidence: {entry.abuse_confidence_score}/100')
        if entry.abuse_isp:
            bits.append(f'ISP: {entry.abuse_isp}')
        country = entry.abuse_country_name or entry.abuse_country_code
        if country:
            bits.append(f'Country: {country}')
        if entry.abuse_asn:
            bits.append(f'ASN: {entry.abuse_asn}')
        if entry.hit_count:
            bits.append(f'Reports: {entry.hit_count}')
        group = getattr(entry.group, 'label', '') or getattr(entry.group, 'name', '')
        if group:
            bits.append(f'Group: {group}')
        bits.append(f'Source: {entry.get_source_display()}')
        return ' · '.join(bits)


# ── Hash feed ─────────────────────────────────────────────────────────────

#: Stored `hash_type` → STIX 2.0 `hash-algorithm-ov` name. The hyphenated
#: spellings are the vocabulary's, not ours.
HASH_ALGORITHMS = {
    'md5':    'MD5',
    'sha1':   'SHA-1',
    'sha256': 'SHA-256',
    'sha512': 'SHA-512',
}

#: Hex length → algorithm, for rows stored before the type was recorded
#: (`hash_type='unknown'`).
HASH_LENGTH_ALGORITHMS = {32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512'}


def hash_algorithm(entry) -> str | None:
    """STIX algorithm name for a hash row, or None if undeterminable.

    The stored type wins; otherwise the hex length decides. None means the
    row cannot be published — an indicator naming the wrong algorithm would
    simply never match anything at the consumer.
    """
    algo = HASH_ALGORITHMS.get((entry.hash_type or '').strip().lower())
    if algo:
        return algo
    return HASH_LENGTH_ALGORITHMS.get(len((entry.hash_value or '').strip()))


class _HashFeed:
    """Hash Blacklist → file:hashes indicators."""

    feed = 'hash'
    model = 'HashEntry'

    def queryset(self):
        """Deliberately the same predicate as `/api/v1/hashlist/`, minus
        rows whose algorithm cannot be determined.

        Note that Deep Discovery Director ingests only SHA-1 and SHA-256
        suspicious objects; MD5 and SHA-512 indicators are valid STIX and
        are published, and DDD filters them on its side. That is the
        subscriber's policy to apply, not ours to pre-empt.
        """
        from django.db.models.functions import Length

        from apps.hashlist.models import HashEntry
        return (
            HashEntry.objects
            .filter(is_active=True, list_type='black', vt_unavailable=False)
            .annotate(_hash_len=Length('hash_value'))
            .filter(Q(hash_type__in=list(HASH_ALGORITHMS))
                    | Q(_hash_len__in=list(HASH_LENGTH_ALGORITHMS)))
            .order_by('added_at', 'id')
        )

    def identity(self, entry) -> str:
        return f'hash:{(entry.hash_value or "").strip().lower()}'

    def pattern(self, entry) -> str:
        algo = hash_algorithm(entry) or 'SHA-256'
        value = (entry.hash_value or '').strip().lower()
        return (f"[file:hashes.'{algo}' = "
                f"'{_escape_pattern_literal(value)}']")

    def name(self, entry) -> str:
        algo = hash_algorithm(entry) or 'hash'
        return f'Malicious file ({algo}): {(entry.hash_value or "").strip()}'[:250]

    def modified(self, entry):
        return _later(entry.added_at, entry.vt_last_analysis, entry.vt_checked_at)

    def description(self, entry) -> str:
        bits = []
        if entry.reason:
            bits.append(entry.reason.strip())
        if entry.vt_total:
            bits.append(f'VirusTotal: {entry.vt_malicious or 0}/{entry.vt_total} engines malicious')
        if entry.vt_threat_label:
            bits.append(f'Threat label: {entry.vt_threat_label}')
        if entry.vt_type_description:
            bits.append(f'File type: {entry.vt_type_description}')
        if entry.vt_meaningful_name:
            bits.append(f'Name: {entry.vt_meaningful_name}')
        if entry.vt_size_display:
            bits.append(f'Size: {entry.vt_size_display}')
        bits.append(f'Source: {entry.get_source_display()}')
        return ' · '.join(bits)


# ── Feed registry ─────────────────────────────────────────────────────────
#
# Adding a feed is: a class above, two entries here, and a choice on
# `TaxiiCollection.FEED_CHOICES` (plus its FEED_DEFAULTS title).

_ADAPTERS = {a.feed: a for a in (_UrlFeed(), _IpFeed(), _HashFeed())}

#: Model class name → adapter. `indicator_id()` and `entry_to_indicator()`
#: are handed a row with no feed argument (the views resolve ids across a
#: whole queryset), so the row's own model is what identifies its feed.
_ADAPTERS_BY_MODEL = {a.model: a for a in _ADAPTERS.values()}


def adapter_for_feed(feed: str):
    try:
        return _ADAPTERS[feed]
    except KeyError:
        raise ValueError(f'No TAXII feed registered as {feed!r}') from None


def _adapter_for_entry(entry):
    name = type(entry).__name__
    try:
        return _ADAPTERS_BY_MODEL[name]
    except KeyError:
        raise ValueError(f'No TAXII feed publishes {name} rows') from None


def published_queryset(feed: str = 'url'):
    """Rows published by a collection, selected by its `feed` value."""
    return adapter_for_feed(feed).queryset()


def indicator_id(entry) -> str:
    """Deterministic `indicator--<uuid5>` for any publishable row."""
    adapter = _adapter_for_entry(entry)
    return f'indicator--{uuid.uuid5(INDICATOR_NAMESPACE, adapter.identity(entry))}'


def date_added(entry):
    """When the object entered the collection.

    TAXII's `added_after` is explicitly unrelated to timestamps inside the
    STIX object (§3.5.1), so this is its own notion: the row's `added_at`.
    Also the sort key for the objects and manifest endpoints, which the
    spec requires to be ascending by date added (§3.3).
    """
    return entry.added_at


def entry_to_indicator(entry) -> dict:
    """One blacklist row → one STIX 2.0 indicator SDO."""
    adapter = _adapter_for_entry(entry)
    created_ts = stix_timestamp(entry.added_at)

    return {
        'type':       'indicator',
        'id':         indicator_id(entry),
        'created':    created_ts,
        'modified':   stix_timestamp(adapter.modified(entry)),
        'valid_from': created_ts,
        # REQUIRED in STIX 2.0, and the one value DDD will not drop.
        'labels':     list(INDICATOR_LABELS),
        'pattern':    adapter.pattern(entry),
        'name':       adapter.name(entry),
        'description': adapter.description(entry),
    }


def build_bundle(entries) -> dict:
    """Wrap indicators in a STIX 2.0 bundle.

    TAXII 2.0 §3.7 defines no envelope of its own — "objects are the direct
    payload of HTTP messages" — and for STIX 2 content "the root object
    MUST be a STIX bundle". An empty result is an empty bundle, not an
    error. Note `spec_version` sits here on the bundle, which is correct
    for 2.0 (in 2.1 it moved onto each object instead).
    """
    return {
        'type':         'bundle',
        'id':           f'bundle--{uuid.uuid4()}',
        'spec_version': '2.0',
        'objects':      [entry_to_indicator(e) for e in entries],
    }


def manifest_entry(entry) -> dict:
    """One row of the manifest endpoint (§5.6).

    `versions` holds the object's STIX `modified` values newest-first; we
    publish a single version per indicator, so it is a one-item list.
    """
    adapter = _adapter_for_entry(entry)
    return {
        'id':          indicator_id(entry),
        'date_added':  stix_timestamp(date_added(entry)),
        'versions':    [stix_timestamp(adapter.modified(entry))],
        'media_types': [STIX_MEDIA_TYPE],
    }
