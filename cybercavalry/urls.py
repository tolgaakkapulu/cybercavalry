from django.contrib import admin
from django.contrib.admin import AdminSite
from django.conf import settings
from django.urls import path, re_path, include
from django.shortcuts import redirect
from django.http import Http404
from django.views.static import serve as _media_serve


def _favicon(request):
    """Redirect /favicon.ico to the configured brand logo (or the default)."""
    try:
        from apps.settings_app.cache import SettingsCache
        from apps.settings_app.branding import logo_url, LOGO_KEY
        return redirect(logo_url(SettingsCache.get(LOGO_KEY, '') or ''))
    except Exception:
        from django.templatetags.static import static as static_url
        return redirect(static_url('img/logo.svg'))


# ── Restricted Admin Site ────────────────────────────────────────────────────
# Overrides has_permission so that only active superusers may access the admin,
# regardless of is_staff.  Applied by swapping the class of the global singleton
# — all already-registered models are preserved.
class _RestrictedAdminSite(AdminSite):
    """Only active superusers may enter the admin interface."""

    def has_permission(self, request):
        return request.user.is_active and request.user.is_superuser


admin.site.__class__ = _RestrictedAdminSite

# ── Admin URL path ───────────────────────────────────────────────────────────
# Loaded from settings (which reads from .env) so the real path never appears
# in version-controlled source code.
_ADMIN_PATH = getattr(settings, 'ADMIN_PATH', 'cybercavalry-management-console/')


def _deny_admin(request):
    raise Http404


urlpatterns = [
    path(_ADMIN_PATH, admin.site.urls),
    path('admin/', _deny_admin),           # return 404 at the well-known path
    # Tarayicilarin default /favicon.ico istegini secili brand logosuna yonlendir
    path('favicon.ico', _favicon),
    path('', lambda request: redirect('dashboard:index'), name='home'),
    path('accounts/', include('apps.accounts.urls')),
    path('blacklist/', include('apps.blacklist.urls')),
    path('whitelist/', include('apps.whitelist.urls')),
    path('hashlist/', include('apps.hashlist.urls')),
    path('urllist/',  include('apps.urllist.urls')),
    path('dashboard/', include('apps.dashboard.urls')),
    path('api/v1/', include('apps.api.urls')),
    path('settings/', include('apps.settings_app.urls')),
    # Serve uploaded branding media (public; logo/favicon/background appear pre-auth).
    re_path(r'^media/(?P<path>.*)$', _media_serve, {'document_root': settings.MEDIA_ROOT}),
]

# Custom error pages — active only when DEBUG=False
# Renders templates/errors/{400,403,404,500}.html
handler400 = 'cybercavalry.error_views.handler400'
handler403 = 'cybercavalry.error_views.handler403'
handler404 = 'cybercavalry.error_views.handler404'
handler500 = 'cybercavalry.error_views.handler500'
