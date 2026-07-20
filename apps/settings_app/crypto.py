"""
Symmetric encryption for secret Setting values.
Algorithm : AES-256-GCM (authenticated encryption)
Key       : 32-byte SHA-256 digest of Django SECRET_KEY
Nonce     : 12-byte random per encryption (prepended to ciphertext)
Tag       : 16-byte GCM auth tag (appended to ciphertext)
Storage   : enc:<base64url(nonce || ciphertext || tag)>
"""

import base64
import hashlib
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

logger = logging.getLogger(__name__)

_PREFIX = 'enc:'
_NONCE_LEN = 12   # 96-bit nonce (NIST recommended for GCM)
_TAG_LEN   = 16   # 128-bit authentication tag


def _key() -> bytes:
    """
    Derive the 256-bit field-encryption key.

    Prefers a dedicated, persistent FIELD_ENCRYPTION_KEY (set in .env) so that
    rotating SECRET_KEY (sessions/CSRF) does NOT destroy stored encrypted secrets.
    Falls back to SECRET_KEY for backward compatibility with installs that
    encrypted secrets before FIELD_ENCRYPTION_KEY existed — those keep working
    until FIELD_ENCRYPTION_KEY is set and secrets are re-saved.
    """
    field_key = (getattr(settings, 'FIELD_ENCRYPTION_KEY', '') or '').strip()
    base = field_key if field_key else settings.SECRET_KEY
    return hashlib.sha256(base.encode('utf-8')).digest()


def encrypt(plaintext: str) -> str:
    """Encrypt plaintext and return  enc:<base64url(nonce||ciphertext||tag)>."""
    if not plaintext:
        return plaintext
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(_key())
    # encrypt() returns ciphertext + tag concatenated
    ct_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    blob = base64.urlsafe_b64encode(nonce + ct_tag).decode('utf-8')
    return _PREFIX + blob


def is_encrypted(value: str) -> bool:
    """Return True if `value` carries the encryption prefix."""
    return bool(value) and value.startswith(_PREFIX)


def decrypt(value: str, key_hint: str = '') -> str:
    """Decrypt a stored value. Returns plain-text; handles unencrypted legacy values.

    `key_hint` is the Setting key (e.g. "threat_intel.abuseipdb_api_key") used
    only in the error log so an operator can tell *which* secret needs to be
    re-entered when the field-encryption key has changed.
    """
    if not value or not value.startswith(_PREFIX):
        return value  # legacy plain-text or empty — return as-is
    try:
        blob = base64.urlsafe_b64decode(value[len(_PREFIX):].encode('utf-8'))
        nonce  = blob[:_NONCE_LEN]
        ct_tag = blob[_NONCE_LEN:]
        aesgcm = AESGCM(_key())
        return aesgcm.decrypt(nonce, ct_tag, None).decode('utf-8')
    except Exception:
        # Fail closed. A value carrying the enc: prefix that will not decrypt is
        # corrupt, tampered, or encrypted under a different key. NEVER return the
        # ciphertext — doing so would transmit the enc: blob as a live credential
        # (API key / LDAP bind password) to upstream services and logs. Return
        # empty so callers treat it as "not configured" and fail safely.
        suffix = f' (key: {key_hint})' if key_hint else ''
        logger.error(
            "Secret decryption failed%s — wrong field-encryption key, tampering, "
            "or corruption. Returning empty value; re-enter the secret in Settings, "
            "or run `manage.py reset_corrupt_secrets` to clear all undecryptable rows.",
            suffix,
        )
        return ''
