def _read_platform_version():
    """Return the platform version from <BASE_DIR>/VERSION, with safe fallback.
    The file is written by `manage.py make_release` (auto-bumped each release)."""
    try:
        from pathlib import Path
        from django.conf import settings as _s
        raw = (Path(_s.BASE_DIR) / 'VERSION').read_text(encoding='utf-8').strip()
        import re
        if re.match(r'^\d+\.\d+\.\d+$', raw):
            return raw
    except Exception:
        pass
    return '1.0.0'


def platform_settings(request):
    """Inject basic platform info into all templates."""
    try:
        from apps.settings_app.cache import SettingsCache
        platform_primary        = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
        platform_suffix         = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
        session_timeout_minutes = int(SettingsCache.get('security.session_timeout', 15) or 15)
        platform_email          = SettingsCache.get('general.platform_email', '') or ''
        try:
            dashboard_refresh = int(SettingsCache.get('general.dashboard_refresh_seconds', 60) or 60)
        except (TypeError, ValueError):
            dashboard_refresh = 60
        dashboard_refresh = max(5, min(3600, dashboard_refresh))   # clamp to a sane range
        from apps.settings_app.branding import (
            logo_url, background_url, brand_value_to_url,
            LOGO_KEY, BACKGROUND_KEY, LOGIN_KEY,
        )
        brand_logo_url       = logo_url(SettingsCache.get(LOGO_KEY, '') or '')
        brand_background_url = background_url(SettingsCache.get(BACKGROUND_KEY, '') or '')
        # Login slot has NO default fallback — fresh installs leave it
        # empty so the login footer stays unchanged until an admin uploads
        # a logo from Settings → General.
        brand_login_url      = brand_value_to_url(SettingsCache.get(LOGIN_KEY, '') or '')
        # Brand accent colour — Settings → General override of --brand-suffix
        # and its translucent glow. We validate the hex shape and recompute
        # the matching rgba(...) variants here so the template only has to
        # paste the values into a <style> block.
        import re as _re
        brand_color = (SettingsCache.get('general.brand_color', '#ee5356') or '#ee5356').strip()
        if not _re.match(r'^#[0-9a-fA-F]{6}$', brand_color):
            brand_color = '#ee5356'
        _r, _g, _b = int(brand_color[1:3], 16), int(brand_color[3:5], 16), int(brand_color[5:7], 16)
        brand_color_glow_dark  = f'rgba({_r},{_g},{_b},0.18)'   # :root + dark theme
        brand_color_glow_light = f'rgba({_r},{_g},{_b},0.12)'   # light theme (subtler)
        # Admin-configurable default theme; users can still toggle per-browser via localStorage.
        default_theme = (SettingsCache.get('general.default_theme', 'light') or 'light').strip().lower()
        if default_theme not in ('light', 'dark'):
            default_theme = 'light'
    except Exception:
        from django.templatetags.static import static as _static
        platform_primary        = 'CYBER'
        platform_suffix         = 'Cavalry'
        session_timeout_minutes = 15
        platform_email          = ''
        dashboard_refresh       = 60
        try:
            brand_logo_url       = _static('img/logo.svg')
            brand_background_url = _static('img/background.svg')
        except Exception:
            brand_logo_url       = '/static/img/logo.svg'
            brand_background_url = '/static/img/background.svg'
        brand_login_url = ''
        default_theme = 'light'
        brand_color = '#ee5356'
        brand_color_glow_dark  = 'rgba(238,83,86,0.18)'
        brand_color_glow_light = 'rgba(238,83,86,0.12)'
    return {
        'platform_name':            platform_primary + platform_suffix,
        'platform_name_primary':    platform_primary,
        'platform_name_suffix':     platform_suffix,
        'session_timeout_minutes':  session_timeout_minutes,
        'dashboard_refresh_seconds': dashboard_refresh,
        'platform_version': _read_platform_version(),
        'csp_nonce':                getattr(request, 'csp_nonce', ''),
        'platform_email':           platform_email,
        'brand_logo_url':           brand_logo_url,
        'brand_favicon_url':        brand_logo_url,   # favicon reuses the logo
        'brand_login_url':          brand_login_url,  # '' until an admin uploads one
        'brand_background_url':     brand_background_url,
        'default_theme':            default_theme,
        'brand_color':              brand_color,
        'brand_color_glow_dark':    brand_color_glow_dark,
        'brand_color_glow_light':   brand_color_glow_light,
    }
