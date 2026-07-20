import ipaddress
import logging
import time as _time
from django.core.cache import cache

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get client IP from REMOTE_ADDR."""
    return request.META.get('REMOTE_ADDR', '')


def authenticate_token(request):
    """
    Validate Authorization: Token <token> + X-Username: <username> headers.

    - Token must belong to the user specified in X-Username (token owner == X-Username).
    - That user must be active and have the 'api_user' role.
    - Source IP is checked separately via check_source_ip().

    Returns the user's UserProfile on success, None on failure.
    """
    from apps.accounts.models import UserProfile

    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Token '):
        logger.debug("authenticate_token: missing or malformed Authorization header")
        return None

    raw_token = auth_header[6:].strip()
    if not raw_token:
        logger.debug("authenticate_token: empty token")
        return None

    username = request.META.get('HTTP_X_USERNAME', '').strip()
    if not username:
        logger.debug("authenticate_token: missing X-Username header")
        return None

    # Find the token owner
    token_profile = UserProfile.get_by_token(raw_token)
    if token_profile is None:
        logger.warning("authenticate_token: token not found in database")
        return None

    # Token must belong to the user specified in X-Username
    if token_profile.user.username != username:
        logger.warning(
            f"authenticate_token: token belongs to '{token_profile.user.username}' "
            f"but X-Username is '{username}' — mismatch rejected"
        )
        return None

    # That user must be active
    if not token_profile.user.is_active:
        logger.warning(f"authenticate_token: '{username}' account is inactive")
        return None

    # That user must have api_user role
    if token_profile.role is None or token_profile.role.name != 'api_user':
        logger.warning(
            f"authenticate_token: '{username}' does not have api_user role "
            f"(role={getattr(token_profile.role, 'name', None)})"
        )
        return None

    return token_profile


def check_source_ip(request):
    """
    Check if request source IP is in the AllowedSourceIP list.
    Returns True if allowed, False otherwise.
    """
    from apps.settings_app.models import AllowedSourceIP

    client_ip = get_client_ip(request)
    if not client_ip:
        return False

    allowed_cidrs = list(
        AllowedSourceIP.objects.filter(is_active=True).values_list('cidr', flat=True)
    )

    if not allowed_cidrs:
        # No restrictions configured — deny all for safety
        return False

    try:
        client_addr = ipaddress.ip_address(client_ip)
        for cidr in allowed_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if client_addr in network:
                    return True
            except ValueError:
                pass
    except ValueError:
        pass

    return False


def check_rate_limit(token_hash: str, limit_rpm: int = 60, client_ip: str = '') -> bool:
    """
    Fixed-window rate limiter.

    - Per-token : limit_rpm requests per 60-second window
    - Per-IP    : 3 × limit_rpm requests per 60-second window (all tokens combined)

    Stores (count, window_start) pairs in cache so that:
      - The window start time is authoritative — expiry is checked in Python,
        not relying on cache TTL alone.
      - cache.incr() is NOT used because Django's Redis backend resets the key's
        TTL on every incr call (SET without EX), causing windows to never expire.

    NOTE: get+set is not atomic under very high concurrency; slight over-counting
    is acceptable for rate limiting. For multi-worker deployments configure a
    shared backend (Redis / Memcached) via settings.CACHES.

    Returns True if the request is allowed, False if rate limited.
    """
    limit_rpm = max(1, int(limit_rpm or 60))

    def _check(key: str, limit: int, window: int) -> bool:
        """
        Returns True if the request is within the rate limit, False otherwise.
        Only increments the counter for allowed requests.
        """
        now = _time.time()
        data = cache.get(key)

        if data is None:
            # New window — first request
            cache.set(key, (1, now), window)
            return True

        count, start = data
        elapsed = now - start

        if elapsed >= window:
            # Window has expired — start a fresh window
            cache.set(key, (1, now), window)
            return True

        if count >= limit:
            # Over limit — do not increment, just reject
            return False

        # Within window and under limit — increment
        new_count = count + 1
        remaining = max(1, int(window - elapsed))
        cache.set(key, (new_count, start), remaining)
        return True

    # ── Per-token 60-second window ───────────────────────────────
    if not _check(f'rl_token:{token_hash}', limit_rpm, 60):
        return False

    # ── Per-IP 60-second window ──────────────────────────────────
    if client_ip:
        if not _check(f'rl_ip:{client_ip}', limit_rpm * 3, 60):
            return False

    return True
