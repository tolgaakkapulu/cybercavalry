"""
Brand image handling — favicon/logo and background uploaded from Settings → General.

Files are stored under MEDIA_ROOT/branding/ with a fixed, key-derived filename
(no user-controlled path component → no traversal). The Setting value holds the
relative media path (e.g. 'branding/brand_logo.png'); empty means "use default".
"""
import os

from django.conf import settings
from django.templatetags.static import static

# Setting keys for the configurable images. The favicon reuses the main
# logo; the login image is a small optional override shown above the email
# row on the login screen (left empty by default so fresh installs render
# the login card unchanged).
LOGO_KEY       = 'general.brand_logo'
LOGIN_KEY      = 'general.brand_login'
BACKGROUND_KEY = 'general.brand_background'
BRAND_KEYS = (LOGO_KEY, LOGIN_KEY, BACKGROUND_KEY)

# Default logo (also the default favicon) and default background — bundled static
# assets. Used when the admin hasn't uploaded a replacement.
DEFAULT_LOGO_STATIC       = 'img/logo.svg'
DEFAULT_BACKGROUND_STATIC = 'img/background.svg'

ALLOWED_EXTS = {'.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico'}
MAX_BYTES = 3 * 1024 * 1024   # 3 MB
_SUBDIR = 'branding'


def _abs(rel):
    return os.path.join(settings.MEDIA_ROOT, *rel.split('/'))


def brand_value_to_url(value):
    """Relative media path stored on the Setting → served URL, or '' if unset/missing."""
    if value and os.path.exists(_abs(value)):
        return settings.MEDIA_URL + value
    return ''


def logo_url(value):
    """Logo/favicon URL: the uploaded image, else the bundled default."""
    return brand_value_to_url(value) or static(DEFAULT_LOGO_STATIC)


def background_url(value):
    """Background URL: the uploaded image, else the bundled default."""
    return brand_value_to_url(value) or static(DEFAULT_BACKGROUND_STATIC)


def save_brand_image(key, uploaded):
    """Validate and store an uploaded brand image.

    Returns (relative_path, None) on success or (None, error_message) on failure.
    The saved filename is derived solely from the setting key, so the upload
    cannot influence the path.
    """
    base = key.rsplit('.', 1)[-1]                      # brand_logo / brand_background
    ext = os.path.splitext(uploaded.name)[1].lower()
    if ext not in ALLOWED_EXTS:
        return None, f'Unsupported file type "{ext or uploaded.name}". Allowed: {", ".join(sorted(ALLOWED_EXTS))}.'
    if uploaded.size > MAX_BYTES:
        return None, f'File too large ({uploaded.size // 1024} KB). Maximum is {MAX_BYTES // (1024 * 1024)} MB.'

    os.makedirs(_abs(_SUBDIR), exist_ok=True)
    # Drop any previously stored file for this key (any extension).
    for e in ALLOWED_EXTS:
        old = _abs(f'{_SUBDIR}/{base}{e}')
        if os.path.exists(old):
            try:
                os.remove(old)
            except OSError:
                pass

    rel = f'{_SUBDIR}/{base}{ext}'
    with open(_abs(rel), 'wb') as fh:
        for chunk in uploaded.chunks():
            fh.write(chunk)
    return rel, None


def platform_name():
    """Single source of truth for the displayed platform name.

    Reads `general.platform_name + general.platform_name_suffix` from the
    settings cache. The literal fallback ('CYBERCavalry') is the canonical
    default of the underlying Setting rows ('CYBER' + 'Cavalry') and is only
    used when SettingsCache itself is unreachable (cold start, DB outage).
    """
    try:
        from apps.settings_app.cache import SettingsCache
        primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
        suffix = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
        return f'{primary}{suffix}'
    except Exception:
        return 'CYBERCavalry'


def brand_filename_prefix():
    """Lowercase, filename-safe slug of the configured platform name.

    Combines `general.platform_name` + `general.platform_name_suffix`, strips
    non-alphanumeric characters, and lowercases. Used as the prefix of every
    user-downloaded artifact (PDF / CSV / DB backup) so file names track the
    rebranded platform. Falls back to 'cybercavalry' if settings are
    unreachable or sanitization leaves an empty string.
    """
    try:
        from apps.settings_app.cache import SettingsCache
        primary = SettingsCache.get('general.platform_name', 'CYBER') or 'CYBER'
        suffix = SettingsCache.get('general.platform_name_suffix', 'Cavalry') or 'Cavalry'
        raw = f'{primary}{suffix}'
    except Exception:
        raw = 'CYBERCavalry'
    slug = ''.join(c for c in raw.lower() if c.isalnum())
    return slug or 'cybercavalry'


def uploaded_logo_path():
    """Absolute filesystem path of the uploaded logo if present, else None.

    Used by the PDF generator to render the configured logo on report covers.
    """
    try:
        from apps.settings_app.cache import SettingsCache
        val = SettingsCache.get(LOGO_KEY, '') or ''
    except Exception:
        val = ''
    if val:
        p = _abs(val)
        if os.path.exists(p):
            return p
    return None


def uploaded_login_path():
    """Absolute filesystem path of the uploaded login/sidebar image, else None.

    Used by the PDF generator to stamp the optional small mark above the
    confidentiality footer on every report page. Returns None when no image
    has been uploaded — callers should skip drawing in that case.
    """
    try:
        from apps.settings_app.cache import SettingsCache
        val = SettingsCache.get(LOGIN_KEY, '') or ''
    except Exception:
        val = ''
    if val:
        p = _abs(val)
        if os.path.exists(p):
            return p
    return None


def clear_brand_image(value):
    """Delete the stored file for a setting value (best-effort)."""
    if value and os.path.exists(_abs(value)):
        try:
            os.remove(_abs(value))
        except OSError:
            pass
