"""TAXII 2.0 endpoints.

    GET /taxii/                                              discovery      §4.1
    GET /taxii/<root>/                                       api root       §4.2
    GET /taxii/<root>/collections/                           collections    §5.1
    GET /taxii/<root>/collections/<id>/                      collection     §5.2
    GET /taxii/<root>/collections/<id>/objects/              objects        §5.3
    GET /taxii/<root>/collections/<id>/objects/<obj-id>/      object         §5.5
    GET /taxii/<root>/collections/<id>/manifest/             manifest       §5.6

Read-only: Add Objects (POST) and the Status endpoint are producer-side
features we have no use for, so they are not implemented. `can_write` on
the collection advertises that honestly.

No Accept-header policing: §3.1 says a server MUST NOT answer 406/415 for
the media types an endpoint defines, so we accept whatever the client
sends and simply return the correct Content-Type.
"""
from __future__ import annotations

import json
import logging
import re
from functools import wraps

from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.views.decorators.http import require_GET

from . import conf, stix
from .auth import TaxiiAuthError, authenticate, REALM
from .pagination import (
    RangeNotSatisfiable, apply_date_added_headers, apply_range_headers, parse_range,
)

logger = logging.getLogger(__name__)


# ── Response helpers ──────────────────────────────────────────────────────

def _taxii_json(payload: dict, status: int = 200) -> HttpResponse:
    """A TAXII-media-type JSON response (discovery, api-root, collections,
    manifest). Object payloads use `_stix_json` instead."""
    return HttpResponse(
        json.dumps(payload),
        status=status,
        content_type=conf.TAXII_CONTENT_TYPE,
    )


def _stix_json(payload: dict, status: int = 200) -> HttpResponse:
    return HttpResponse(
        json.dumps(payload),
        status=status,
        content_type=conf.STIX_CONTENT_TYPE,
    )


def _error(title: str, status: int, description: str = '',
           www_authenticate: bool = False) -> HttpResponse:
    """TAXII `error` object (§3.6.1): `title` required, the rest optional.
    `http_status` is a string per the spec's own field table."""
    body: dict = {'title': title, 'http_status': str(status)}
    if description:
        body['description'] = description
    resp = _taxii_json(body, status=status)
    if www_authenticate:
        resp['WWW-Authenticate'] = f'Basic realm="{REALM}"'
    return resp


def _not_found(what: str = 'Resource') -> HttpResponse:
    # §4.1.1/§5.1.1 etc. use 404 for both "absent" and "caller may not see
    # it", so we deliberately do not distinguish the two here.
    return _error('Not Found', 404, f'{what} does not exist.')


def _request_detail(request):
    """Request context for the ActivityLog detail dict.

    Deliberately the same shape the api app records for its own endpoints
    (method / path / body / user_agent) so a TAXII row and a
    `GET /api/v1/urllist/` row read alike on the Activity Log page.
    """
    qs = request.META.get('QUERY_STRING', '')
    return {
        'method':     request.method,
        'path':       request.path,
        'body':       ('?' + qs[:512]) if qs else '-',
        'user_agent': (request.META.get('HTTP_USER_AGENT', '') or '')[:200],
    }


def _log(request, profile, action, *, target_id='', **extra):
    """Record one TAXII request in the ActivityLog.

    The rotating file log is not enough on its own: the console reads the
    ActivityLog, and both Settings → Activity Log's "API" filter and the
    dashboard's Request Timeline select rows by the `api.` prefix. A poll
    that reached only the file log is invisible to the operator, which is
    exactly what happened before these rows existed.

    `ActivityLog.log` swallows its own failures, so a logging problem can
    never break a subscriber's poll.
    """
    from apps.api.auth import get_client_ip
    from apps.settings_app.models import ActivityLog

    detail = _request_detail(request)
    detail.update(extra)
    ActivityLog.log(
        profile.user if profile else None,
        action, 'TaxiiCollection', target_id,
        detail, get_client_ip(request),
    )


def _taxii_endpoint(name):
    """Shared endpoint preamble — feature toggle, auth, activity logging.

    A view may enrich its own log row through `request.taxii_detail` (and
    `request.taxii_target`), because only the view knows how much it served
    and from which collection.

    Denials are logged as well, and in practice matter more than the
    successes: "my subscriber stopped polling" is answered by a 401 from an
    expired token or a 403 from an IP that fell off the allowlist, not by
    the absence of a success row.

    A disabled server answers 404 rather than 403 so it stays
    indistinguishable from "no TAXII here" to an unauthenticated scanner,
    and writes nothing — there is no subscriber activity to record.
    """
    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not conf.enabled():
                return _not_found('TAXII server')
            try:
                profile = authenticate(request)
            except TaxiiAuthError as exc:
                _log(request, None, 'api.taxii_denied',
                     endpoint=name, status=exc.status, reason=exc.title)
                return _error(exc.title, exc.status, exc.description,
                              www_authenticate=exc.www_authenticate)

            request.taxii_profile = profile
            request.taxii_detail = {}
            request.taxii_target = ''
            resp = view(request, *args, **kwargs)
            _log(request, profile, f'api.taxii_{name}',
                 target_id=request.taxii_target,
                 endpoint=name, status=resp.status_code,
                 **request.taxii_detail)
            return resp
        return wrapped
    return decorate


def _resolve_root(root: str) -> str | None:
    """Confirm `root` is an api root with at least one active collection.
    Returns the normalised value, or None when it is not served."""
    from .models import TaxiiCollection
    name = (root or '').strip('/')
    if name and TaxiiCollection.objects.filter(api_root=name, is_active=True).exists():
        return name
    return None


def _resolve_collection(root: str, cid: str):
    """Fetch the active collection `cid` within `root`, or None.

    A bad UUID string is a miss rather than an error — a subscriber that
    kept a stale id should get a clean 404 and re-discover, not a 500.
    """
    from .models import TaxiiCollection
    try:
        return TaxiiCollection.objects.get(
            api_root=(root or '').strip('/'),
            collection_id=(cid or '').strip('/'),
            is_active=True,
        )
    except (TaxiiCollection.DoesNotExist, ValidationError, ValueError):
        return None


def _api_root_url(request, root: str) -> str:
    from django.urls import reverse
    return request.build_absolute_uri(
        reverse('taxii:api_root', kwargs={'root': root})
    )


# ── Endpoints ─────────────────────────────────────────────────────────────

@require_GET
@_taxii_endpoint('discovery')
def discovery(request):
    """§4.1 — the one URL an operator pastes into Deep Discovery Director's
    "Discovery URL" field. `title` is the only required field."""

    # platform_name() already swallows its own failures and falls back to
    # the canonical default, so no try/except needed around it.
    from apps.settings_app.branding import platform_name
    from .models import TaxiiCollection

    roots = TaxiiCollection.active_roots()
    root_urls = [_api_root_url(request, r) for r in roots]

    body = {
        'title':       f'{platform_name()} TAXII Server',
        'description': 'Publishes platform blacklists as STIX 2.0 indicators over TAXII 2.0.',
        'api_roots':   root_urls,
    }
    # §4.1.1: `default` must be one of `api_roots`; omit it entirely when
    # there is nothing to point at rather than advertise a dead URL.
    if root_urls:
        body['default'] = root_urls[0]
    return _taxii_json(body)


@require_GET
@_taxii_endpoint('api_root')
def api_root(request, root):
    """§4.2 — title, versions and max_content_length are all required, and
    `versions` MUST contain `taxii-2.0`."""
    name = _resolve_root(root)
    if name is None:
        return _not_found('API root')

    from .models import TaxiiCollection
    count = TaxiiCollection.objects.filter(api_root=name, is_active=True).count()
    return _taxii_json({
        'title':              f'{name} ({count} collection{"s" if count != 1 else ""})',
        'description':        'Read-only API root. Collections publish platform blacklists '
                              'as STIX 2.0 indicators.',
        'versions':           [conf.TAXII_VERSION],
        'max_content_length': conf.MAX_CONTENT_LENGTH,
    })


@require_GET
@_taxii_endpoint('collections')
def collections(request, root):
    """§5.1 — paginated, no filtering. When the list is empty the
    `collections` key MUST be omitted entirely, leaving `{}`."""
    name = _resolve_root(root)
    if name is None:
        return _not_found('API root')

    from .models import TaxiiCollection
    qs = TaxiiCollection.objects.filter(api_root=name, is_active=True)
    total = qs.count()
    try:
        first, last_excl, is_partial = parse_range(
            request.META.get('HTTP_RANGE'), total, conf.page_size_default(),
        )
    except RangeNotSatisfiable as exc:
        return _error('Range Not Satisfiable', 416,
                      f'Requested range starts beyond the {exc.total} available items.')

    page = list(qs[first:last_excl])
    payload = (
        {'collections': [c.to_resource(stix.STIX_MEDIA_TYPE) for c in page]}
        if page else {}
    )
    resp = _taxii_json(payload)
    apply_range_headers(resp, first, last_excl, total, is_partial)
    return resp


@require_GET
@_taxii_endpoint('collection')
def collection(request, root, cid):
    """§5.2 — single collection resource. No pagination, no filtering."""
    coll = _resolve_collection(root, cid)
    if coll is None:
        return _not_found('Collection')
    request.taxii_target = str(coll.collection_id)
    request.taxii_detail.update({'root': coll.api_root, 'feed': coll.feed})
    return _taxii_json(coll.to_resource(stix.STIX_MEDIA_TYPE))


class BadFilter(Exception):
    """A supported filter was given a value we cannot act on → 400."""


#: A `+` in a query string decodes to a space, so an unencoded ISO offset
#: like `+00:00` reaches us as ` 00:00`. Matches that trailing remnant.
_OFFSET_SPACE_RE = re.compile(r' (\d{2}:?\d{2})$')


def _parse_added_after(raw: str):
    """Parse the `added_after` filter into an aware datetime.

    Repairs the `+`-became-a-space case first. That wrinkle matters more
    than it looks: if we silently ignored an unparseable value, a client
    asking for a delta would be handed the ENTIRE collection and have no
    way to tell. So anything we still cannot parse raises instead, and the
    caller turns it into a 400 the operator can actually see.
    """
    from datetime import timezone as _dtz

    from django.utils import timezone as _tz
    from django.utils.dateparse import parse_datetime

    candidates = [raw]
    repaired = _OFFSET_SPACE_RE.sub(r'+\1', raw)
    if repaired != raw:
        candidates.append(repaired)

    for cand in candidates:
        try:
            parsed = parse_datetime(cand)
        except ValueError:
            parsed = None
        if parsed is not None:
            if _tz.is_naive(parsed):
                parsed = _tz.make_aware(parsed, _dtz.utc)
            return parsed

    raise BadFilter(
        f"added_after is not a valid timestamp: {raw[:60]!r}. "
        f"Expected RFC 3339, e.g. 2026-11-09T00:00:00.000Z"
    )


def _filtered_queryset(request, coll):
    """Apply the §3.5 filters the objects/manifest endpoints support.

    `added_after` is the one that matters in practice — Deep Discovery
    Director's "Start-polling lookback" setting is what drives it, and it
    is how an incremental poll avoids re-pulling the whole blacklist.
    """
    qs = stix.published_queryset(coll.feed)

    added_after = (request.GET.get('added_after') or '').strip()
    if added_after:
        # Exclusive, per "after".
        qs = qs.filter(added_at__gt=_parse_added_after(added_after))

    # match[type] — we only ever publish indicators, so a filter that
    # excludes them empties the result rather than erroring. §3.5.1 says an
    # unknown-but-valid STIX type MUST NOT error.
    match_type = (request.GET.get('match[type]') or '').strip()
    if match_type:
        wanted = {t.strip() for t in match_type.split(',') if t.strip()}
        if 'indicator' not in wanted:
            qs = qs.none()

    # match[id] — filter to specific indicator ids. Our ids are uuid5 of
    # url_hash, so there is no reverse index; resolving in Python is fine
    # because a client asking for specific ids asks for a handful.
    match_id = (request.GET.get('match[id]') or '').strip()
    if match_id:
        wanted_ids = {i.strip() for i in match_id.split(',') if i.strip()}
        keep = [e.pk for e in qs if stix.indicator_id(e) in wanted_ids]
        qs = qs.filter(pk__in=keep)

    return qs


def _paged(request, qs):
    """Resolve the Range header against `qs`. Returns
    `(entries, first, last_exclusive, total, is_partial)` or raises
    RangeNotSatisfiable."""
    total = qs.count()
    first, last_exclusive, is_partial = parse_range(
        request.META.get('HTTP_RANGE'), total, conf.page_size_default(),
    )
    entries = list(qs[first:last_exclusive]) if total else []
    return entries, first, last_exclusive, total, is_partial


@require_GET
@_taxii_endpoint('objects')
def objects(request, root, cid):
    """§5.3 — the actual indicators, as a STIX 2.0 bundle."""
    coll = _resolve_collection(root, cid)
    if coll is None:
        return _not_found('Collection')

    try:
        qs = _filtered_queryset(request, coll)
        entries, first, last_excl, total, is_partial = _paged(request, qs)
    except BadFilter as exc:
        return _error('Bad Request', 400, str(exc))
    except RangeNotSatisfiable as exc:
        return _error('Range Not Satisfiable', 416,
                      f'Requested range starts beyond the {exc.total} available items.')

    resp = _stix_json(stix.build_bundle(entries))
    apply_range_headers(resp, first, last_excl, total, is_partial)
    apply_date_added_headers(
        resp,
        stix.stix_timestamp(stix.date_added(entries[0])) if entries else None,
        stix.stix_timestamp(stix.date_added(entries[-1])) if entries else None,
    )
    logger.info(
        'TAXII objects [%s/%s]: served %d/%d indicator(s)%s',
        coll.api_root, coll.feed, len(entries), total,
        ' (partial)' if is_partial else '',
    )
    # Same numbers the file log just reported, so the Activity Log row and
    # the log line cannot disagree about what this poll received.
    request.taxii_target = str(coll.collection_id)
    request.taxii_detail.update({
        'root': coll.api_root, 'feed': coll.feed,
        'served': len(entries), 'total': total,
        'partial': is_partial,
    })
    return resp


@require_GET
@_taxii_endpoint('object')
def object_by_id(request, root, cid, oid):
    """§5.5 — a single object by its STIX id, still wrapped in a bundle."""
    coll = _resolve_collection(root, cid)
    if coll is None:
        return _not_found('Collection')

    wanted = oid.strip('/')
    match = next(
        (e for e in stix.published_queryset(coll.feed) if stix.indicator_id(e) == wanted),
        None,
    )
    if match is None:
        return _not_found('Object')

    resp = _stix_json(stix.build_bundle([match]))
    apply_date_added_headers(
        resp,
        stix.stix_timestamp(stix.date_added(match)),
        stix.stix_timestamp(stix.date_added(match)),
    )
    request.taxii_target = str(coll.collection_id)
    request.taxii_detail.update({'root': coll.api_root, 'feed': coll.feed,
                                 'object': wanted})
    return resp


@require_GET
@_taxii_endpoint('manifest')
def manifest(request, root, cid):
    """§5.6 — id / date_added / versions / media_types per object. Lets a
    client see what changed without downloading every indicator."""
    coll = _resolve_collection(root, cid)
    if coll is None:
        return _not_found('Collection')

    try:
        qs = _filtered_queryset(request, coll)
        entries, first, last_excl, total, is_partial = _paged(request, qs)
    except BadFilter as exc:
        return _error('Bad Request', 400, str(exc))
    except RangeNotSatisfiable as exc:
        return _error('Range Not Satisfiable', 416,
                      f'Requested range starts beyond the {exc.total} available items.')

    # Same omit-when-empty rule as the collections endpoint.
    payload = {'objects': [stix.manifest_entry(e) for e in entries]} if entries else {}
    resp = _taxii_json(payload)
    apply_range_headers(resp, first, last_excl, total, is_partial)
    apply_date_added_headers(
        resp,
        stix.stix_timestamp(stix.date_added(entries[0])) if entries else None,
        stix.stix_timestamp(stix.date_added(entries[-1])) if entries else None,
    )
    logger.info(
        'TAXII manifest [%s/%s]: served %d/%d entry(ies)%s',
        coll.api_root, coll.feed, len(entries), total,
        ' (partial)' if is_partial else '',
    )
    request.taxii_target = str(coll.collection_id)
    request.taxii_detail.update({
        'root': coll.api_root, 'feed': coll.feed,
        'served': len(entries), 'total': total,
        'partial': is_partial,
    })
    return resp
