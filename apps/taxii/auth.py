"""TAXII authentication — HTTP Basic carrying a platform API token.

TAXII 2.0 CS01 §1.4.6 makes HTTP Basic (RFC 7617) the mandatory-to-implement
scheme, so Basic is what we must speak. What goes in the password field is
our choice, and it is deliberately **the account's API token, not its login
password**:

  * LDAP-backed accounts have no usable local password at all.
  * A token is one indexed SHA-256 lookup (`UserProfile.get_by_token`);
    a password is a deliberately-slow PBKDF2 verification on every poll.
  * Password-policy rotation would silently kill the feed 90 days in, with
    nothing but a stale blacklist to show for it.
  * Failed Basic attempts would otherwise feed the login lockout counter
    and could lock a human out of the console.
  * Tokens already carry their own lifecycle — minted and revoked per
    account from Accounts → User Management, independently of anyone's
    password.

So a subscriber sends:

    Authorization: Basic base64("<username>:<api-token>")

which is the same shape GitHub used for personal access tokens. The account
must be active and hold the `api_user` role, exactly as the existing
token-authenticated POST endpoints require.
"""
from __future__ import annotations

import base64
import binascii
import logging

from . import conf

logger = logging.getLogger(__name__)

REALM = 'CYBERCavalry TAXII'


class TaxiiAuthError(Exception):
    """Raised with the HTTP status the spec wants for this failure mode."""

    def __init__(self, status: int, title: str, description: str = '', www_authenticate: bool = False):
        super().__init__(title)
        self.status = status
        self.title = title
        self.description = description
        self.www_authenticate = www_authenticate


def _parse_basic(header: str) -> tuple[str, str] | None:
    """Decode `Authorization: Basic <b64>` into (username, secret).

    Returns None when the header is absent, not Basic, or malformed —
    callers treat all three as "no usable credentials" → 401.
    """
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != 'basic':
        return None
    try:
        raw = base64.b64decode(parts[1].strip(), validate=True).decode('utf-8')
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if ':' not in raw:
        return None
    username, _, secret = raw.partition(':')
    return username, secret


def authenticate(request):
    """Validate a TAXII request. Returns the authenticated `UserProfile`,
    or raises `TaxiiAuthError`.

    The source-IP gate runs first so an unauthorised network never gets to
    probe credentials, and a wrong-network caller sees 403 ("your IP")
    rather than 401 ("your token") — a materially more useful distinction
    when an operator is debugging a subscriber that stopped polling.
    """
    from apps.accounts.models import UserProfile
    from apps.api.auth import get_client_ip

    if conf.require_source_ip():
        from apps.api.auth import check_source_ip
        if not check_source_ip(request):
            logger.warning('TAXII: source IP %s not in allowlist', get_client_ip(request))
            raise TaxiiAuthError(
                403, 'Forbidden',
                'Source IP is not in the allowed list. Add it under '
                'Settings → Source IPs, or turn off "Also Require Source IP".',
            )

    supplied = _parse_basic(request.META.get('HTTP_AUTHORIZATION', ''))
    if supplied is None:
        raise TaxiiAuthError(
            401, 'Unauthorized',
            'HTTP Basic authentication required. Send the account username and '
            'its API token as the password.',
            www_authenticate=True,
        )

    username, token = supplied

    # Indexed SHA-256 lookup, so a bad token costs one query and leaks no
    # timing signal about which part was wrong.
    profile = UserProfile.get_by_token(token) if token else None
    if profile is None:
        logger.warning('TAXII: unknown API token presented from %s (user=%r)',
                       get_client_ip(request), username[:40])
        raise TaxiiAuthError(401, 'Unauthorized', 'Invalid credentials.',
                             www_authenticate=True)

    # The token must belong to the username that was sent — otherwise a
    # leaked token would authenticate as any account the caller names.
    if profile.user.username != username:
        logger.warning(
            'TAXII: token belongs to %r but username sent was %r — rejected',
            profile.user.username, username[:40],
        )
        raise TaxiiAuthError(401, 'Unauthorized', 'Invalid credentials.',
                             www_authenticate=True)

    if not profile.user.is_active:
        logger.warning('TAXII: account %r is inactive', username[:40])
        raise TaxiiAuthError(403, 'Forbidden', 'Account is disabled.')

    # Same role gate the token-authenticated POST endpoints use.
    role_name = getattr(profile.role, 'name', None)
    if role_name != 'api_user':
        logger.warning('TAXII: account %r lacks the api_user role (role=%r)',
                       username[:40], role_name)
        raise TaxiiAuthError(
            403, 'Forbidden',
            'Account does not hold the API User role required for TAXII access.',
        )

    return profile
