"""
CYBERCavalry — Security Headers Middleware

Adds HTTP security response headers that Django's built-in SecurityMiddleware
does not cover:

  Content-Security-Policy  — restricts which resources the browser may load,
                             mitigating XSS and data-injection attacks.
  Referrer-Policy          — controls how much referrer information is included
                             in outgoing requests, preventing URL leakage.

Headers already handled by Django's SecurityMiddleware (via settings):
  X-Content-Type-Options   → SECURE_CONTENT_TYPE_NOSNIFF = True
  X-Frame-Options          → X_FRAME_OPTIONS = 'DENY'
  Strict-Transport-Security → SECURE_HSTS_SECONDS / SECURE_HSTS_*

CSP nonce strategy (CWE-79 / unsafe-inline mitigation):
  A cryptographically random nonce is generated per request and attached to
  the response CSP header as 'nonce-<value>'.  Every inline <script> block
  in the templates must carry the matching nonce attribute:

      <script nonce="{{ csp_nonce }}">...</script>

  The nonce is exposed to templates via the 'csp_nonce' context variable,
  provided by apps.settings_app.context_processors.platform_settings.

  'unsafe-inline' is intentionally removed from script-src.  Only scripts
  that carry the correct nonce will be executed by the browser; any script
  injected by an XSS payload will be blocked because it cannot know the
  per-request nonce value.

  'unsafe-eval' remains in script-src because the bundled Alpine.js build
  evaluates inline x-* directive expressions via AsyncFunction (constructed
  as Object.getPrototypeOf(async function(){}).constructor).  Removing it
  breaks all Alpine-powered UI.  The primary XSS mitigation — blocking
  injected inline scripts — is achieved by the nonce alone.
"""

import base64
import logging
import os

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware:
    """
    Injects a per-request nonce into the CSP and exposes it as
    request.csp_nonce for use in templates.
    """

    _REFERRER_POLICY = "strict-origin-when-cross-origin"
    # Disable powerful browser features the app never uses (defense in depth).
    _PERMISSIONS_POLICY = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
        "accelerometer=(), gyroscope=(), magnetometer=(), interest-cohort=()"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Generate a cryptographically random 128-bit nonce for this request.
        nonce = base64.b64encode(os.urandom(16)).decode('ascii')
        request.csp_nonce = nonce

        response = self.get_response(request)

        csp = (
            "default-src 'self'; "
            # 'unsafe-eval' is required by the bundled Alpine.js build, which uses
            # Object.getPrototypeOf(async function(){}).constructor to evaluate
            # inline x-* directive expressions.  Removing it breaks Alpine entirely.
            # 'unsafe-inline' is blocked — only scripts carrying the per-request
            # nonce are executed, which is the primary XSS mitigation.
            f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.setdefault("Content-Security-Policy", csp)
        response.setdefault("Referrer-Policy", self._REFERRER_POLICY)
        response.setdefault("Permissions-Policy", self._PERMISSIONS_POLICY)
        return response


class AdminIPRestrictionMiddleware:
    """
    Blocks access to the Django admin interface from unauthorized IP addresses.

    Any request whose path starts with the configured admin path is checked
    against ADMIN_ALLOWED_IPS.  Requests from unlisted IPs receive a 404
    response — identical to what a non-existent path would return — so no
    information about the admin path is leaked to an attacker.

    Configuration (settings / .env):
      ADMIN_PATH          — admin URL prefix, e.g. 'cybercavalry-management-console/'
                            Must match the path used in urls.py.
      ADMIN_ALLOWED_IPS   — list of IPv4/IPv6 addresses permitted to access
                            the admin.  Default: ['127.0.0.1', '::1']
                            Set to an empty list to disable the restriction.

    IP resolution:
      REMOTE_ADDR is used unconditionally.  X-Forwarded-For is intentionally
      ignored here — trusting a client-supplied header for admin access would
      allow trivial bypass via header spoofing.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        from django.conf import settings
        raw_path = getattr(settings, 'ADMIN_PATH', 'cybercavalry-management-console/')
        # Normalise: ensure leading slash, no double slashes
        self._admin_prefix = '/' + raw_path.lstrip('/')
        self._allowed_ips  = set(getattr(settings, 'ADMIN_ALLOWED_IPS', ['127.0.0.1', '::1']))

    def __call__(self, request):
        from django.http import Http404
        if request.path.startswith(self._admin_prefix):
            # Use REMOTE_ADDR directly — never trust XFF for privilege gates.
            client_ip = request.META.get('REMOTE_ADDR', '')
            if self._allowed_ips and client_ip not in self._allowed_ips:
                logger.warning(
                    "Admin access denied: IP %s is not in ADMIN_ALLOWED_IPS "
                    "(path=%s)", client_ip, request.path
                )
                raise Http404
        return self.get_response(request)


class SessionTimeoutMiddleware:
    """
    Reads security.session_timeout from DB settings and applies it
    as the session expiry for every authenticated request.
    Falls back to Django's SESSION_COOKIE_AGE if the setting is missing.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                from apps.settings_app.cache import SettingsCache
                minutes = int(SettingsCache.get('security.session_timeout', 15) or 15)
            except Exception:
                minutes = 15
            request.session.set_expiry(minutes * 60)
        return self.get_response(request)
