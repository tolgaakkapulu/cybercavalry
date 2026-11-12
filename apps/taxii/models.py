"""TAXII collections — the subscribable feeds this server publishes.

Replaces what used to be three flat settings (`taxii.api_root`,
`taxii.collection_title`, `taxii.collection_id`). Those could only ever
express ONE feed, which was a dead end: TAXII's own model is one API root
holding many collections, and "URL blacklist" / "hash blacklist" /
"IP blacklist" are naturally three collections, not three servers.

Axis to grow along:
  * **collections** — add a row per feed a subscriber should be able to
    pick. This is almost always what you want.
  * **api_root** — an administrative/trust grouping. Only worth more than
    one value if different subscribers must not even see each other's
    collection list (multi-tenancy).
"""
from __future__ import annotations

import uuid

from django.contrib.auth.models import User
from django.db import models


class TaxiiCollection(models.Model):
    #: Which blacklist this collection publishes. Adding a feed type is a
    #: choice here plus one mapper in `stix.py` — see `stix.published_queryset`.
    FEED_URL  = 'url'
    FEED_IP   = 'ip'
    FEED_HASH = 'hash'
    FEED_CHOICES = [
        (FEED_URL,  'URL Blacklist'),
        (FEED_IP,   'IP Blacklist'),
        (FEED_HASH, 'Hash Blacklist'),
    ]

    #: Offered in the Add form's API Root dropdown alongside the roots
    #: already in use. TAXII's model is one root holding many collections,
    #: so `default` is the normal answer and the per-list names exist only
    #: for the case where subscribers must be kept apart.
    SUGGESTED_ROOTS = ['default', 'urllist', 'blacklist', 'hashlist']

    #: Root name → the feed it obviously means, mirroring the platform's own
    #: URL segments (/urllist/, /blacklist/, /hashlist/). Used only to
    #: pre-select the Add form's Feed dropdown; it is a starting point the
    #: operator can override, never a constraint — nothing stops a `urllist`
    #: root from also carrying the hash feed. `default` is deliberately
    #: absent: a catch-all root implies nothing about which list it serves.
    ROOT_FEED_HINTS = {
        'urllist':   FEED_URL,
        'blacklist': FEED_IP,
        'hashlist':  FEED_HASH,
    }

    #: Starting title/description the Add Collection form pre-fills when a feed
    #: is picked. Only a convenience — the operator can overwrite both, and
    #: editing them later never affects what the feed publishes. Keep a key
    #: here for every FEED_CHOICES entry so the form always has something to
    #: offer; `_feed_default` falls back to the display label if one is missing.
    FEED_DEFAULTS = {
        FEED_URL: {
            'title': 'Malicious URLs & Domains',
            'description': 'Active malicious URLs, domains and subdomains from the '
                           'URL Blacklist, published as STIX 2.0 indicators.',
        },
        FEED_IP: {
            'title': 'Malicious IP Addresses',
            'description': 'Active blacklisted IP addresses and CIDR blocks, '
                           'whitelist-filtered and published as STIX 2.0 indicators.',
        },
        FEED_HASH: {
            'title': 'Malicious File Hashes',
            'description': 'Active blacklisted file hashes from the Hash Blacklist, '
                           'published as STIX 2.0 indicators.',
        },
    }

    # Generated, never typed. A subscriber stores this id after Discover and
    # re-polls that exact value, so it must not change once published.
    collection_id = models.UUIDField(
        default=uuid.uuid4, unique=True, editable=False,
        help_text='Collection UUID advertised over TAXII. Generated automatically; '
                  'changing it would force every subscriber to re-discover.',
    )
    api_root = models.SlugField(
        max_length=64, default='default',
        help_text='Administrative grouping — the collection is served under '
                  '/taxii/<api_root>/. Use one value unless you need subscribers '
                  'to see separate collection lists.',
    )
    title = models.CharField(
        max_length=255,
        help_text='Name subscribers see when they browse this server.',
    )
    description = models.TextField(
        blank=True, default='',
        help_text='Shown alongside the title in the subscriber UI.',
    )
    feed = models.CharField(
        max_length=8, choices=FEED_CHOICES, default=FEED_URL,
        help_text='Which platform blacklist this collection publishes.',
    )
    is_active = models.BooleanField(
        default=True, db_index=True,
        help_text='Inactive collections disappear from discovery and return 404, '
                  'without losing the UUID — so you can pause a feed and resume it '
                  'later without the subscriber having to re-discover.',
    )

    added_by   = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # Two collections in the same root publishing the same feed would be
        # indistinguishable to a subscriber choosing between them.
        unique_together = ('api_root', 'feed')
        ordering = ['api_root', 'title']
        verbose_name = 'TAXII Collection'
        verbose_name_plural = 'TAXII Collections'

    def __str__(self):
        return f'{self.title} ({self.api_root}/{self.get_feed_display()})'

    @property
    def uuid_str(self) -> str:
        return str(self.collection_id)

    def to_resource(self, stix_media_type: str) -> dict:
        """TAXII 2.0 §5.2.1 collection resource.

        `id` / `title` / `can_read` / `can_write` are required; `description`
        and `media_types` optional. `can_write` is always false — this server
        is a producer, it does not accept Add Objects.
        """
        return {
            'id':          self.uuid_str,
            'title':       self.title,
            'description': self.description or f'{self.get_feed_display()} published as STIX 2.0 indicators.',
            'can_read':    True,
            'can_write':   False,
            'media_types': [stix_media_type],
        }

    @classmethod
    def feed_catalog(cls) -> list[dict]:
        """Every publishable feed with its default title/description, for the
        Add Collection form's dropdown."""
        return [
            {
                'value': value,
                'label': label,
                'title': cls.FEED_DEFAULTS.get(value, {}).get('title', label),
                'description': cls.FEED_DEFAULTS.get(value, {}).get('description', ''),
            }
            for value, label in cls.FEED_CHOICES
        ]

    @classmethod
    def taken_feeds_by_root(cls) -> dict[str, list[str]]:
        """`{api_root: [feed, ...]}` — the (root, feed) pairs already in use.

        `unique_together` rejects a second one, so the Add form consults this
        to hide the combinations that would bounce. Includes PAUSED
        collections on purpose: the row still occupies the pair, and the whole
        point of pausing is that resuming must stay possible.
        """
        out: dict[str, list[str]] = {}
        for root, feed in cls.objects.values_list('api_root', 'feed'):
            out.setdefault(root, []).append(feed)
        return out

    @classmethod
    def known_roots(cls) -> list[str]:
        """Distinct api_root values, active or not — the Add form offers these
        so an operator picks an existing grouping instead of inventing a near
        duplicate (`urllist` vs `url-list`), which would silently split the
        collection list a subscriber sees."""
        return list(
            cls.objects.values_list('api_root', flat=True).distinct().order_by('api_root')
        )

    @classmethod
    def preferred_feed_for(cls, api_root: str, taken: list | None = None) -> str:
        """Which feed the Add form should start on for `api_root`.

        The root's own name wins when that feed is still free; otherwise the
        first feed not yet published under the root, since offering a
        combination `unique_together` would reject is a dead end.
        """
        used = set(taken or [])
        hinted = cls.ROOT_FEED_HINTS.get((api_root or '').strip().lower())
        if hinted and hinted not in used:
            return hinted
        return next((v for v, _ in cls.FEED_CHOICES if v not in used), '')

    @classmethod
    def suggested_roots(cls) -> list[str]:
        """`SUGGESTED_ROOTS` minus the ones already in use, so the Add form
        can show "in use" and "suggested" as separate groups without
        repeating a value in both."""
        known = set(cls.known_roots())
        return [r for r in cls.SUGGESTED_ROOTS if r not in known]

    @classmethod
    def active_roots(cls) -> list[str]:
        """Distinct api_root values that currently have at least one active
        collection — this is what discovery advertises."""
        return list(
            cls.objects.filter(is_active=True)
            .values_list('api_root', flat=True)
            .distinct()
            .order_by('api_root')
        )
