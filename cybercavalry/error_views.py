from django.http import HttpResponse
from django.template.loader import get_template


def _brand_name():
    """Configured platform name; delegates to the central branding helper
    (which has its own DB-failure fallback)."""
    try:
        from apps.settings_app.branding import platform_name
        return platform_name()
    except Exception:
        return 'CYBERCavalry'


def _render(template_name, status):
    """
    Render an error template without running context processors.
    Using get_template().render(ctx) avoids any context-processor failure
    (e.g. database unavailable) that would cause Django to fall back to
    its built-in plain-text error responses; the platform name is resolved
    separately with its own fallback so error titles still reflect the brand.
    """
    try:
        html = get_template(template_name).render({'platform_name': _brand_name()})
    except Exception:
        html = ''
    return HttpResponse(html, status=status)


def handler400(request, exception=None):
    return _render('errors/400.html', 400)


def handler403(request, exception=None):
    return _render('errors/403.html', 403)


def handler404(request, exception=None):
    return _render('errors/404.html', 404)


def handler500(request):
    return _render('errors/500.html', 500)
