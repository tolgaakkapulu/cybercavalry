from __future__ import annotations

import ipaddress
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

# Path prefixes that are never logged
_SKIP_PREFIXES = ('/static/', '/media/', '/favicon', '/api/v1/')

# URL name → readable action
_PAGE_ACTIONS = {
    'dashboard:index':              'page.dashboard',
    'blacklist:list':               'page.blacklist',
    'blacklist:create':             'page.blacklist.add_form',
    'blacklist:edit':               'page.blacklist.edit_form',
    'blacklist:bulk_create':        'page.blacklist.bulk_add_form',
    'whitelist:list':               'page.whitelist',
    'whitelist:create':             'page.whitelist.add_form',
    'whitelist:edit':               'page.whitelist.edit_form',
    'accounts:user_list':           'page.users',
    'accounts:user_create':         'page.users.create_form',
    'accounts:user_set_role':       'page.users.set_role_form',
    'accounts:profile':             'page.profile',
    'settings_app:index':           'page.settings',
    'settings_app:source_ip_list':  'page.settings.source_ips',
    'settings_app:activity_log':    'page.activity_log',
    'settings_app:role_matrix':     'page.role_matrix',
}


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def get_client_ip(request) -> str:
    """
    Return the real client IP address.

    Security model (CWE-346):
      - REMOTE_ADDR is the only unconditionally trusted value (actual TCP peer).
      - X-Forwarded-For is client-controlled and can be spoofed.
      - XFF is only trusted when REMOTE_ADDR belongs to TRUSTED_PROXIES.
        Even then, we walk the XFF chain from right to left and return the
        first IP that is NOT itself a trusted proxy — the rightmost untrusted
        hop, which is the true client origin as seen by the proxy chain.

    Configuration:
      Set TRUSTED_PROXIES = ['<proxy-ip>', ...] in settings when a reverse
      proxy (Nginx, Caddy, etc.) sits in front of this application.
      Leave it empty (the default) for direct HTTPS deployments.
    """
    remote_addr = request.META.get('REMOTE_ADDR', '')

    trusted_proxies = getattr(settings, 'TRUSTED_PROXIES', [])
    if not trusted_proxies:
        # No proxy configured — always use the real TCP connection source.
        return remote_addr

    # Build a set of trusted proxy networks for fast lookup.
    trusted_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in trusted_proxies:
        try:
            trusted_nets.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            logger.warning("TRUSTED_PROXIES contains invalid entry: %r", entry)

    def _is_trusted(ip_str: str) -> bool:
        addr = _parse_ip(ip_str)
        if addr is None:
            return False
        return any(addr in net for net in trusted_nets)

    # Only trust XFF when the direct connection comes from a known proxy.
    if not _is_trusted(remote_addr):
        return remote_addr

    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if not xff:
        return remote_addr

    # Walk from right to left; return the first non-trusted address.
    candidates = [ip.strip() for ip in xff.split(',')]
    for ip_str in reversed(candidates):
        if not _is_trusted(ip_str):
            addr = _parse_ip(ip_str)
            return str(addr) if addr else remote_addr

    # All IPs in XFF are trusted proxies (unusual); fall back to REMOTE_ADDR.
    return remote_addr


class AuditMiddleware:
    """
    - Attaches client_ip to every request.
    - Writes authenticated users' page navigations (GET 200) and
      login/logout events to the ActivityLog.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.client_ip = get_client_ip(request)
        response = self.get_response(request)

        # Authenticated users only
        if not getattr(request, 'user', None) or not request.user.is_authenticated:
            return response

        # Skip static / media / API paths
        if any(request.path.startswith(p) for p in _SKIP_PREFIXES):
            return response

        # Only successful GETs are logged as page navigations
        if request.method == 'GET' and response.status_code == 200:
            self._log_page(request)

        return response

    def _log_page(self, request):
        from django.urls import resolve, Resolver404
        from apps.settings_app.models import ActivityLog
        try:
            match = resolve(request.path)
            ns = match.app_name or ''
            url_name = f"{ns}:{match.url_name}" if ns else match.url_name
            action = _PAGE_ACTIONS.get(url_name, f'page.{match.url_name}')

            detail = {'path': request.path}
            if match.kwargs:
                detail['params'] = {k: str(v) for k, v in match.kwargs.items()}
            if request.GET:
                detail['query'] = dict(request.GET.lists())

            ActivityLog.log(
                user=request.user,
                action=action,
                target_model='Page',
                target_id=request.path,
                detail=detail,
                ip_address=request.client_ip,
            )
        except Exception:
            pass  # An audit-log failure must never block the main request
