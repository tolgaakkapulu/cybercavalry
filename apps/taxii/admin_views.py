"""Collection management UI, mounted under Settings.

Django's own admin is disabled in this project, so collections get a small
CRUD page modelled on Settings → Source IPs. Admin-only: a collection
defines what a subscriber can pull, which is an access-control decision.
"""
from __future__ import annotations

import logging
import re

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.decorators import login_required_custom, role_required
from apps.settings_app.models import ActivityLog
from .models import TaxiiCollection

logger = logging.getLogger(__name__)


def _redirect():
    return redirect('taxii_admin:collection_list')


#: An api_root becomes a URL segment (`/taxii/<root>/`), so it must match what
#: SlugField allows. Anything else would store fine and then never resolve —
#: the subscriber gets 404 from a collection the UI shows as Active.
_ROOT_RE = re.compile(r'[-a-zA-Z0-9_]+')

NEW_ROOT = '__new__'


def _add_form_context(request, *, api_root='', feed='', title='', description='',
                      root_mode=''):
    """Everything the Add form needs, including the values just submitted.

    On a validation error the view re-renders with these instead of bouncing
    to the list, so a typo in one field does not discard the other three.
    """
    known = TaxiiCollection.known_roots()
    suggested = TaxiiCollection.suggested_roots()
    taken = TaxiiCollection.taken_feeds_by_root()
    catalog = TaxiiCollection.feed_catalog()
    all_feeds = {f['value'] for f in catalog}

    if not root_mode:
        if api_root and api_root in known + suggested:
            root_mode = api_root
        elif api_root:
            root_mode = NEW_ROOT
        else:
            # Default to the first known root that still has a free feed; if
            # every existing root is full, open the form on "new root" so the
            # operator is not greeted by a dead end.
            root_mode = next(
                (r for r in known if set(taken.get(r, [])) != all_feeds),
                NEW_ROOT,
            )

    if not feed:
        # Resolved server-side so the dropdown is already on a legal choice
        # before any JavaScript runs, and on the one the root's name implies.
        resolved_root = '' if root_mode == NEW_ROOT else root_mode
        feed = TaxiiCollection.preferred_feed_for(
            resolved_root, taken.get(resolved_root, []),
        )

    # Title and description are rendered server-side too, so the form is
    # already complete on first paint instead of filling in once Alpine
    # boots. `*_touched` keeps the distinction the auto-fill depends on:
    # a value the operator typed is never overwritten when the feed
    # changes, a value we pre-filled is.
    defaults = TaxiiCollection.FEED_DEFAULTS.get(feed, {})
    title_touched, description_touched = bool(title), bool(description)
    title = title or defaults.get('title', '')
    description = description or defaults.get('description', '')

    return {
        'mode': 'add',
        'known_roots': known,
        'suggested_roots': suggested,
        'feeds': catalog,
        'selected_feed': feed,
        'selected_title': title,
        'selected_description': description,
        'new_root_sentinel': NEW_ROOT,
        'form_data': {
            'taken': taken,
            # root name → the feed it implies; see ROOT_FEED_HINTS.
            'hints': dict(TaxiiCollection.ROOT_FEED_HINTS),
            'feeds': catalog,
            'newRootSentinel': NEW_ROOT,
            'rootMode': root_mode,
            'newRoot': api_root if root_mode == NEW_ROOT else '',
            'feed': feed,
            'title': title,
            'description': description,
            'titleTouched': title_touched,
            'descTouched': description_touched,
        },
    }


@login_required_custom
@role_required('admin')
def collection_list(request):
    from . import conf
    return render(request, 'taxii/collection_list.html', {
        'collections':   TaxiiCollection.objects.all(),
        'taxii_enabled': conf.enabled(),
        'feed_choices':  TaxiiCollection.FEED_CHOICES,
    })


@login_required_custom
@role_required('admin')
def collection_add(request):
    if request.method != 'POST':
        return render(request, 'taxii/collection_form.html',
                      _add_form_context(request))

    # The API root comes from a dropdown of roots already in use, plus a
    # "New API root" option that reveals a text box. Resolve the two into one
    # value here rather than trusting the browser to send only the right one.
    root_mode = (request.POST.get('api_root') or '').strip()
    if root_mode == NEW_ROOT:
        api_root = (request.POST.get('api_root_new') or '').strip().strip('/')
    else:
        api_root = root_mode.strip('/')
    # Lower-cased because the value lands in a URL path, and Django's path
    # matching is case-sensitive: storing `URLList` would advertise a route
    # that only resolves for a subscriber that reproduces the capitals.
    api_root = api_root.lower()

    title = (request.POST.get('title') or '').strip()
    feed  = (request.POST.get('feed') or '').strip()
    desc  = (request.POST.get('description') or '').strip()

    valid_feeds = {k for k, _ in TaxiiCollection.FEED_CHOICES}
    error = None
    if not api_root:
        error = 'API root is required.'
    elif not _ROOT_RE.fullmatch(api_root):
        error = ('API root may only contain letters, numbers, hyphens and '
                 'underscores — it becomes part of the URL subscribers poll.')
    elif feed not in valid_feeds:
        error = 'Pick a feed for this collection.'
    elif not title:
        error = 'Title is required.'
    elif TaxiiCollection.objects.filter(api_root=api_root, feed=feed).exists():
        # unique_together would raise; a readable message beats a 500.
        error = (f'API root "{api_root}" already publishes this feed. Two '
                 f'collections carrying the same feed in the same root would be '
                 f'indistinguishable to a subscriber choosing between them.')

    if error:
        messages.error(request, error)
        return render(request, 'taxii/collection_form.html',
                      _add_form_context(request, api_root=api_root, feed=feed,
                                        title=title, description=desc,
                                        root_mode=root_mode))

    coll = TaxiiCollection.objects.create(
        api_root=api_root, title=title, feed=feed,
        description=desc, added_by=request.user,
    )
    ActivityLog.log(request.user, 'taxii.collection_add', 'TaxiiCollection',
                    str(coll.pk),
                    {'collection_id': coll.uuid_str, 'api_root': api_root,
                     'feed': feed, 'title': title},
                    getattr(request, 'client_ip', ''))
    messages.success(
        request,
        f'Collection "{title}" created with UUID {coll.uuid_str}.',
    )
    return _redirect()


@login_required_custom
@role_required('admin')
def collection_edit(request, pk):
    coll = get_object_or_404(TaxiiCollection, pk=pk)
    if request.method == 'POST':
        title = (request.POST.get('title') or '').strip()
        desc  = (request.POST.get('description') or '').strip()
        if not title:
            messages.error(request, 'Title is required.')
        else:
            old_title = coll.title
            coll.title = title
            coll.description = desc
            coll.save(update_fields=['title', 'description', 'updated_at'])
            ActivityLog.log(request.user, 'taxii.collection_edit', 'TaxiiCollection',
                            str(coll.pk),
                            {'collection_id': coll.uuid_str,
                             'old_title': old_title, 'new_title': title},
                            getattr(request, 'client_ip', ''))
            messages.success(request, 'Collection updated.')
        return _redirect()

    # api_root / feed / UUID are intentionally not editable: changing any of
    # them breaks the address a subscriber already discovered. Delete and
    # recreate if the shape really has to change.
    return render(request, 'taxii/collection_form.html', {
        'collection': coll,
        'feed_choices': TaxiiCollection.FEED_CHOICES,
        'mode': 'edit',
    })


@login_required_custom
@role_required('admin')
def collection_toggle(request, pk):
    """Pause / resume without losing the UUID, so a subscriber does not have
    to re-discover when the feed comes back."""
    coll = get_object_or_404(TaxiiCollection, pk=pk)
    if request.method == 'POST':
        coll.is_active = not coll.is_active
        coll.save(update_fields=['is_active', 'updated_at'])
        action = 'activated' if coll.is_active else 'paused'
        ActivityLog.log(request.user, 'taxii.collection_toggle', 'TaxiiCollection',
                        str(coll.pk),
                        {'collection_id': coll.uuid_str, 'is_active': coll.is_active},
                        getattr(request, 'client_ip', ''))
        messages.success(request, f'Collection "{coll.title}" {action}.')
    return _redirect()


@login_required_custom
@role_required('admin')
def collection_delete(request, pk):
    coll = get_object_or_404(TaxiiCollection, pk=pk)
    if request.method == 'POST':
        snapshot = {'collection_id': coll.uuid_str, 'api_root': coll.api_root,
                    'feed': coll.feed, 'title': coll.title}
        coll.delete()
        ActivityLog.log(request.user, 'taxii.collection_delete', 'TaxiiCollection',
                        None, snapshot, getattr(request, 'client_ip', ''))
        messages.success(
            request,
            f'Collection "{snapshot["title"]}" deleted. Any subscriber polling '
            f'UUID {snapshot["collection_id"]} will now get 404 and must re-discover.',
        )
    return _redirect()
