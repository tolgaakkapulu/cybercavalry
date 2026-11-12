"""Server-wide TAXII settings.

Deliberately small. Anything that varies per feed — the api root, the
collection title, its UUID — lives on `TaxiiCollection` instead, and
credentials live on the platform's own API-token accounts. What's left
here are the three knobs that genuinely apply to the whole server.
"""
from __future__ import annotations

from apps.settings_app.cache import SettingsCache

# ── Media types, verbatim from TAXII 2.0 CS01 §1.4.7 ──────────────────────
# The `version` parameter follows the subtype after a semicolon. Responses
# MUST carry the right one (§3.1); objects/manifest payloads are STIX, so
# they use the STIX media type rather than the TAXII one.
TAXII_CONTENT_TYPE = 'application/vnd.oasis.taxii+json; version=2.0'
STIX_CONTENT_TYPE  = 'application/vnd.oasis.stix+json; version=2.0'

#: Must appear in the api-root's `versions` list per §4.2.1.
TAXII_VERSION = 'taxii-2.0'

#: Advertised in the api-root. Applies to REQUEST bodies only — we are
#: read-only, so this is informational.
MAX_CONTENT_LENGTH = 104_857_600


def enabled() -> bool:
    return bool(SettingsCache.get('taxii.enabled', False))


def require_source_ip() -> bool:
    """When on (default), a caller must ALSO be in Settings → Source IPs on
    top of its API token — defence in depth. Turn off only if the
    subscriber's egress address is not stable."""
    return bool(SettingsCache.get('taxii.require_source_ip', True))


def page_size_default() -> int:
    """Items returned when the client sends no `Range` header. TAXII 2.0
    lets a server return a partial set unasked (§3.4.3), so capping here
    keeps a large blacklist from becoming one enormous response."""
    try:
        return max(1, min(10_000, int(SettingsCache.get('taxii.page_size_default', 500) or 500)))
    except (TypeError, ValueError):
        return 500
