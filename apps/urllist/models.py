import hashlib
import ipaddress
import logging
import re
from urllib.parse import urlparse, urlunparse

from django.db import models
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)

# ── Registrable-domain extractor ───────────────────────────────────────────
# `tldextract` uses the Mozilla Public Suffix List to correctly split any
# hostname into subdomain / registered-domain / suffix. Without it we'd get
# `co.uk` back for `example.co.uk`, or `com.tr` for `foo.com.tr`, because a
# naive last-two-labels split can't know which suffixes are "public" (owned
# by a registry rather than a registrant).
#
# The library is a hard requirement (see requirements.txt), but we still
# guard the import so a fresh checkout that hasn't run `pip install -r`
# doesn't 500 on every URL save — the fallback keeps the old FQDN behaviour
# and logs a warning. Configured with `suffix_list_urls=()` +
# `fallback_to_snapshot=True` so airgapped deploys never make a network
# call at first use; the bundled PSL snapshot is authoritative.
try:
    import tldextract as _tldextract
    _TLD_EXTRACT = _tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
except Exception:                                            # pragma: no cover
    _TLD_EXTRACT = None
    logger.warning(
        "tldextract is not installed — URL hostnames will fall back to the "
        "full FQDN. Run `pip install -r requirements.txt` to enable PSL-based "
        "registrable-domain extraction."
    )


def registrable_domain(host):
    """Return the registrable domain (eTLD+1) for a hostname.

    Examples:
      shtedsa.qrbyw.xyz   -> qrbyw.xyz
      login.example.co.uk -> example.co.uk
      example.com         -> example.com
      qrbyw.xyz           -> qrbyw.xyz

    Returns the input unchanged when the PSL library is missing or the host
    doesn't parse cleanly (e.g. an IP address, a punycoded oddity, or a
    single-label internal name that has no public suffix)."""
    host = (host or '').strip().lower()
    if not host or _TLD_EXTRACT is None:
        return host
    try:
        parts = _TLD_EXTRACT(host)
    except Exception:                                        # pragma: no cover
        return host
    # `registered_domain` is empty when the input is an IP, a bare TLD, or
    # otherwise has no valid "domain + suffix" pair — return the original
    # host in that case so we never write an empty hostname to the DB.
    return parts.registered_domain or host


# Max stored URL length. RFC leaves this open-ended, but browsers commonly
# cap around 2000, and firewalls/SIEMs that consume the feed struggle with
# anything larger. Trim before insert if longer.
MAX_URL_LENGTH = 2000

# Bare-domain regex (RFC 1035 / 1123 label): 1–63 chars per label, letters /
# digits / hyphens; at least one dot; two-letter or longer TLD. Case-insensitive
# match required by callers. Deliberately loose — punycoded hosts (xn--…) pass,
# IP addresses fail (they'd need the http:// prefix path). Matches
# `example.com`, `sub.example.co.uk`, `xn--nxasmq6b.example`; rejects `foo`,
# `example.` and `-bad.example`.
_DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',
    re.IGNORECASE,
)


def _split_bare(value):
    """Split a bare-domain input into (host, path). `example.com/foo/bar` →
    ('example.com', '/foo/bar'); `example.com` → ('example.com', '')."""
    slash = value.find('/')
    if slash == -1:
        return value, ''
    return value[:slash], value[slash:]


def _is_valid_host(host):
    """True when `host` is a DNS label OR an IPv4/IPv6 address. `host` may
    include a `:port` suffix on IPv4/DNS forms; strip it before validating.
    IPv6 addresses arrive with square brackets when they came through a
    scheme-form URL (`[::1]`); those brackets are stripped so
    `ipaddress.ip_address()` accepts them."""
    if not host:
        return False
    h = host
    # Strip a trailing port from `host:port` — but only when we can be
    # confident it IS a port, not an IPv6 chunk. IPv6 without brackets is
    # ambiguous here, so require the brackets on the caller side.
    if h.startswith('[') and ']' in h:
        # `[::1]:8080` → host=`::1`
        end = h.index(']')
        h = h[1:end]
    elif h.count(':') == 1:
        # `example.com:8080` or `1.2.3.4:8080`
        h_no_port, _, port = h.rpartition(':')
        if port.isdigit():
            h = h_no_port
    if _DOMAIN_RE.match(h):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_url(value):
    """Accept full URLs (http:// or https://) AND bare hosts with an optional
    path — the URL blacklist is consumed by firewalls / proxies / secure web
    gateways, most of which take either form. Bare IPv4/IPv6 addresses are
    accepted too, because after scheme-strip normalisation an input like
    `http://1.2.3.4/admin` becomes `1.2.3.4/admin` and still needs to
    re-validate on subsequent `normalize_url()` calls. Rejects garbage
    (empty, over-length, no dot in the host, etc.)."""
    if not value:
        return False
    v = value.strip()
    if not v or len(v) > MAX_URL_LENGTH:
        return False
    # Full URL path
    if v.lower().startswith(('http://', 'https://')):
        try:
            p = urlparse(v)
        except (ValueError, TypeError):
            return False
        return p.scheme in ('http', 'https') and bool(p.netloc)
    # Bare host [+ optional path] — extract host and validate it
    host, _path = _split_bare(v)
    return _is_valid_host(host)


def normalize_url(value):
    """Return the canonical BARE form used for de-dup and VirusTotal lookup.

    Rules:
      * strip surrounding whitespace
      * `http://` and `https://` schemes are STRIPPED — everything ends up
        in the same shape a firewall / proxy would filter on. `http://x.com`
        and `https://x.com` and bare `x.com` are one stored value: `x.com`.
      * host lowercased (case-insensitive per RFC)
      * default port stripped (:80 for schemes we can identify, :443 for
        https)
      * collapse duplicate slashes in path
      * drop trailing slash on empty/root path
      * drop userinfo (`user:pass@`) and fragment (`#…`) — never routed
      * query string preserved verbatim (some sites route on it)

    Bare IP addresses (IPv4/IPv6) pass through, so `http://1.2.3.4/admin`
    becomes `1.2.3.4/admin` and stays valid on subsequent normalisations.
    """
    if not is_valid_url(value):
        raise ValueError(f"Invalid URL: {value}")
    v = value.strip()

    # Scheme-carrying input: parse, drop scheme + userinfo + fragment, keep
    # host [+ non-default port] + path + query. Everything flows into the
    # same shape as bare-domain input below.
    if v.lower().startswith(('http://', 'https://')):
        p = urlparse(v)
        scheme = p.scheme.lower()
        host = (p.hostname or '').lower()
        port = p.port
        if (scheme == 'http' and port == 80) or (scheme == 'https' and port == 443):
            netloc = host
        elif port:
            netloc = f'{host}:{port}'
        else:
            netloc = host
        path = re.sub(r'/{2,}', '/', p.path or '')
        if path == '/':
            path = ''
        result = netloc + path
        if p.query:
            result += '?' + p.query
        return result

    # Bare-domain input: just clean casing / duplicate slashes.
    host, path = _split_bare(v)
    host = host.lower()
    if path:
        path = re.sub(r'/{2,}', '/', path)
        if path == '/':
            path = ''
    return host + path


def url_sha256(value):
    """SHA-256 of the URL used as the DEDUP identifier on URLEntry rows.

    Hashes the URL **exactly as it will be stored** — i.e. the output of
    `normalize_url(value)`. That means:

      * `example.com`         → hash of `example.com`         (bare)
      * `http://example.com`  → hash of `http://example.com`  (http scheme)
      * `https://example.com` → hash of `https://example.com` (https scheme)

    Three inputs, three distinct rows — matches the user's stored view
    ("what I sent is what I see"). An earlier version of this function
    canonicalised bare + https:// to the same hash so it doubled as the
    VirusTotal lookup ID; that made bare and https:// collide in the DB,
    where whichever was inserted first won and later attempts silently
    returned the earlier row. VT lookups now use `url_vt_id()` below.
    """
    return hashlib.sha256(normalize_url(value).encode('utf-8')).hexdigest()


def url_vt_id(value):
    """SHA-256 of the URL used for the VirusTotal `/api/v3/urls/{id}` lookup.

    VT's URL identifier is the SHA-256 of the URL string **exactly as VT
    stores it**. Two rules matter here that our storage-side normalizer
    doesn't apply — they exist purely to make the VT query hit the right
    object and never touch `url_value`:

      1. Every URL VT knows about has a scheme; bare domains get
         `https://` prepended before hashing.
      2. VT stores root-path URLs with a trailing slash (`https://x.com/`
         not `https://x.com`). Our `normalize_url()` strips that slash for
         storage cleanliness, so we put it back here — otherwise VT would
         404 and the entry would land with a bogus 0/0 score.
    """
    from urllib.parse import urlparse
    normalized = normalize_url(value)
    if not normalized.lower().startswith(('http://', 'https://')):
        normalized = 'https://' + normalized
    p = urlparse(normalized)
    if not p.path:
        normalized = normalized + '/'
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


class URLEntry(models.Model):
    LIST_BLACK = 'black'
    LIST_WHITE = 'white'
    LIST_CHOICES = [(LIST_BLACK, 'Blacklist'), (LIST_WHITE, 'Whitelist')]

    SOURCE_MANUAL = 'manual'
    SOURCE_API = 'api'
    SOURCE_IMPORT = 'import'
    SOURCE_CHOICES = [
        (SOURCE_MANUAL, 'Manual'),
        (SOURCE_API, 'API'),
        (SOURCE_IMPORT, 'Import'),
    ]

    # url_value stores the normalized URL. TextField because 2000 chars
    # doesn't fit CharField cleanly across every backend without silently
    # truncating.
    url_value  = models.TextField()
    # SHA-256 of the normalized url_value. Used for uniqueness + indexing
    # (indexing TextField is either impossible or slow on most backends).
    url_hash   = models.CharField(max_length=64, db_index=True)
    # Convenience column so the list page can filter/group by host without
    # re-parsing the URL on every row render.
    hostname   = models.CharField(max_length=253, db_index=True, blank=True, default='')

    list_type  = models.CharField(max_length=10, choices=LIST_CHOICES, default=LIST_BLACK, db_index=True)
    reason     = models.TextField(blank=True)
    source     = models.CharField(max_length=10, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    added_by   = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    added_at   = models.DateTimeField(auto_now_add=True)
    is_active  = models.BooleanField(default=True, db_index=True)
    is_pinned  = models.BooleanField(default=False, help_text="Pinned entries are exempt from automatic score-based deactivation")
    # VirusTotal
    vt_malicious   = models.IntegerField(null=True, blank=True, help_text="Number of engines detecting as malicious")
    vt_total       = models.IntegerField(null=True, blank=True, help_text="Total number of engines scanned")
    vt_checked_at  = models.DateTimeField(null=True, blank=True, help_text="Last VirusTotal query time")
    vt_unavailable = models.BooleanField(
        default=False,
        db_index=True,
        help_text=(
            "True when VirusTotal was queried but did not return a result "
            "(timeout, quota exhausted, network error). Such entries stay "
            "is_active=True for admin visibility but are excluded from the "
            "downstream /api/v1/urllist/ feed until a valid score arrives."
        ),
    )
    vt_not_found = models.BooleanField(
        default=False,
        db_index=True,
        help_text=(
            "True when VirusTotal responded 404 for this URL/domain — the URL "
            "is not indexed by VT at all (never scanned, never submitted). "
            "Distinct from vt_unavailable (transient reachability failure) and "
            "from a legitimate 0/N score (VT scanned it and found nothing). "
            "Entries with this flag show a 'Not in VT' badge instead of the "
            "misleading 0/0 score and are deactivated (excluded from the "
            "downstream feed) until VT eventually indexes and scores them."
        ),
    )
    # VirusTotal enrichment metadata (shown in the URL tooltip)
    vt_threat_label     = models.CharField(max_length=255, blank=True, default='')
    vt_categories       = models.CharField(max_length=255, blank=True, default='',
                                           help_text="Comma-joined categories reported by VT engines (e.g. phishing, malware)")
    vt_final_url        = models.TextField(blank=True, default='',
                                           help_text="Final URL after redirects, as observed by VT")
    vt_title            = models.CharField(max_length=255, blank=True, default='',
                                           help_text="HTML <title> observed by VT during its last scan")
    vt_first_seen       = models.DateTimeField(null=True, blank=True)
    vt_last_analysis    = models.DateTimeField(null=True, blank=True)
    vt_times_submitted  = models.IntegerField(null=True, blank=True)
    # Extended enrichment — populated from either /urls/{id} or /domains/{d}
    # responses; whichever fields the endpoint returned are stored, the rest
    # stay blank. All optional so a URL without HTTP data still displays cleanly.
    vt_reputation       = models.IntegerField(null=True, blank=True,
                                              help_text="Community-driven reputation score; negative = suspicious")
    vt_votes_harmless   = models.IntegerField(null=True, blank=True,
                                              help_text="Community votes marking the URL/domain harmless")
    vt_votes_malicious  = models.IntegerField(null=True, blank=True,
                                              help_text="Community votes marking the URL/domain malicious")
    vt_http_code        = models.IntegerField(null=True, blank=True,
                                              help_text="Last HTTP response code observed by VT (URL endpoint only)")
    vt_content_length   = models.BigIntegerField(null=True, blank=True,
                                                 help_text="Response body size (bytes) from the last VT crawl")
    vt_redirect_count   = models.IntegerField(null=True, blank=True,
                                              help_text="Number of redirects in the redirection_chain")
    vt_serving_ip       = models.CharField(max_length=45, blank=True, default='',
                                           help_text="IP that served the URL during the last VT crawl")
    vt_tags             = models.CharField(max_length=255, blank=True, default='',
                                           help_text="Comma-joined VT-provided tags (e.g. suspicious-tld, malware)")
    vt_languages        = models.CharField(max_length=255, blank=True, default='',
                                           help_text="Comma-joined page languages detected by VT")
    vt_harmless         = models.IntegerField(null=True, blank=True,
                                              help_text="Engines that voted harmless in the last analysis")
    vt_suspicious       = models.IntegerField(null=True, blank=True,
                                              help_text="Engines that voted suspicious in the last analysis")
    vt_undetected       = models.IntegerField(null=True, blank=True,
                                              help_text="Engines that returned undetected in the last analysis")
    # Domain-endpoint-only fields (blank when the entry was scored via /urls/)
    vt_registrar        = models.CharField(max_length=255, blank=True, default='',
                                           help_text="Domain registrar from whois (domain endpoint only)")
    vt_creation_date    = models.DateTimeField(null=True, blank=True,
                                               help_text="Domain creation date from whois")
    vt_popularity_rank  = models.IntegerField(null=True, blank=True,
                                              help_text="Best (lowest) popularity rank across VT sources (Cisco/Alexa/etc.)")

    class Meta:
        unique_together = ('url_hash', 'list_type')
        ordering = ['-added_at']
        indexes = [
            models.Index(fields=['is_active', 'list_type']),
        ]

    def __str__(self):
        display = self.url_value if len(self.url_value) <= 60 else self.url_value[:57] + '...'
        return f"{display} ({self.list_type})"

    def save(self, *args, **kwargs):
        # Keep the normalized form + sha256 + hostname in sync any time
        # url_value changes. Callers can bypass by pre-populating these
        # fields explicitly, which the bulk-insert paths do for speed.
        if self.url_value:
            try:
                normalized = normalize_url(self.url_value)
                self.url_value = normalized
                self.url_hash = url_sha256(normalized)
                # Bare-domain inputs stay bare, so urlparse().hostname returns
                # None; fall back to splitting on the first slash.
                if normalized.lower().startswith(('http://', 'https://')):
                    fqdn = urlparse(normalized).hostname or ''
                else:
                    fqdn, _ = _split_bare(normalized)
                # Store the REGISTRABLE DOMAIN (eTLD+1) rather than the full
                # FQDN so `shtedsa.qrbyw.xyz`, `login.qrbyw.xyz`, and
                # `verify.qrbyw.xyz` all collapse to `qrbyw.xyz` — that's the
                # unit an analyst filters and groups by when hunting for a
                # phishing operation reusing many subdomains under one name.
                self.hostname = registrable_domain(fqdn)[:253]
            except ValueError:
                pass
        super().save(*args, **kwargs)

    @property
    def vt_categories_list(self):
        """Split the comma-joined categories back into a list for template display."""
        return [c.strip() for c in (self.vt_categories or '').split(',') if c.strip()]

    @property
    def has_vt_intel(self):
        """True when VirusTotal enrichment data exists to show in the tooltip.
        The list stays in sync with what the tooltip renders so an entry with
        only, say, a reputation score still surfaces the intel indicator."""
        return bool(self.vt_checked_at and (
            self.vt_threat_label or self.vt_categories or self.vt_final_url
            or self.vt_title or self.vt_first_seen or self.vt_times_submitted
            or self.vt_reputation is not None
            or self.vt_votes_harmless is not None or self.vt_votes_malicious is not None
            or self.vt_http_code is not None or self.vt_content_length is not None
            or self.vt_redirect_count is not None or self.vt_serving_ip
            or self.vt_tags or self.vt_languages
            or self.vt_registrar or self.vt_creation_date
            or self.vt_popularity_rank is not None
        ))
