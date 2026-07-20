"""
Outbound HTTPS trust helpers for threat-intel integrations.

Two HTTP clients are used across the project:
  * urllib  — VirusTotal (settings views + virustotal_service)
  * requests — AbuseIPDB via abuseipdb_wrapper

Both must verify TLS consistently on Windows (dev) and RHEL (prod), including
corporate SSL-inspection (MITM) environments. Trust is the UNION of:
  1. system CA store        (RHEL: update-ca-trust; Windows: cert store)
  2. certifi bundle         (public CAs + intermediates — fixes Windows gaps)
  3. THREAT_INTEL_CA_BUNDLE (optional corporate/proxy root CA)

Set THREAT_INTEL_SSL_VERIFY=False (in .env) only as a last resort.
"""
from __future__ import annotations

import logging
import os
import ssl

from django.conf import settings

logger = logging.getLogger(__name__)


def _corporate_ca() -> str:
    """Return a configured corporate CA bundle path if it exists, else ''."""
    ca = (getattr(settings, 'THREAT_INTEL_CA_BUNDLE', '') or '').strip()
    return ca if (ca and os.path.exists(ca)) else ''


def verify_enabled() -> bool:
    return bool(getattr(settings, 'THREAT_INTEL_SSL_VERIFY', True))


def build_ssl_context() -> ssl.SSLContext:
    """
    Portable SSL context for urllib-based outbound calls.

    Combines the system trust store (loaded by create_default_context),
    the certifi bundle, and an optional corporate CA — all merged, so no
    single source overrides another.
    """
    if not verify_enabled():
        logger.warning(
            "THREAT_INTEL_SSL_VERIFY=False — outbound TLS verification disabled (insecure)."
        )
        return ssl._create_unverified_context()  # noqa: S323 — explicit opt-in

    ctx = ssl.create_default_context()  # system + OS cert store

    # Add certifi (public CAs / intermediates; especially helps on Windows).
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:  # noqa: BLE001 — certifi optional
        pass

    # Add corporate / proxy CA on top (MITM SSL inspection).
    ca = _corporate_ca()
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load THREAT_INTEL_CA_BUNDLE %s: %s", ca, exc)

    return ctx


def requests_verify():
    """
    Value to pass as `requests`' verify= (also used by abuseipdb_wrapper if it
    forwards it). Returns:
      * a corporate CA bundle path if configured,
      * True  → use requests' bundled certifi (default),
      * False → disabled (last resort).
    """
    if not verify_enabled():
        return False
    return _corporate_ca() or True


def apply_requests_ca_env() -> None:
    """
    Best-effort trust config for `requests`-based clients we cannot pass
    verify= into directly (e.g. abuseipdb_wrapper). Honoured via env vars
    that `requests`/urllib read at call time.

    Called right before constructing such a client.
    """
    if not verify_enabled():
        # requests verification can't be reliably disabled via env vars; the
        # corporate-CA path below is the supported route for MITM environments.
        return

    ca = _corporate_ca()
    if ca:
        # Point requests (REQUESTS_CA_BUNDLE) and OpenSSL (SSL_CERT_FILE) at it.
        os.environ['REQUESTS_CA_BUNDLE'] = ca
        os.environ.setdefault('SSL_CERT_FILE', ca)
