"""Shared page-size helper for the IP / hash / whitelist tables and the
activity log.

Default comes from the ``general.items_per_page`` setting (50 if unset);
each request may override it via ``?page_size=N`` clamped to a fixed
allow-list so the picker UI in pagination.html and the backend stay in
lock-step.
"""
from apps.settings_app.cache import SettingsCache

PAGE_SIZE_OPTIONS = [10, 25, 50, 100, 250, 500]


def _default_page_size():
    try:
        v = int(SettingsCache.get('general.items_per_page', 50))
    except (TypeError, ValueError):
        v = 50
    return v if v in PAGE_SIZE_OPTIONS else 50


def get_page_size(request):
    """Resolve the page size for the current request.

    Returns one of PAGE_SIZE_OPTIONS (silently falling back to the saved
    default for any unknown / malformed query value)."""
    default = _default_page_size()
    raw = request.GET.get('page_size')
    if raw is None:
        return default
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return v if v in PAGE_SIZE_OPTIONS else default
