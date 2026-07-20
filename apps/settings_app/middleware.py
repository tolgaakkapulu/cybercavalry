"""HTTP access-log middleware — writes a one-line summary of every finished
request to the `access` logger (routed to `logs/access.log` by Django
LOGGING). Syslog forwarding for the same line is wired at the LOGGING
config level via `SyslogAccessHandler`, so we don't emit here directly.

Runs under gunicorn / uvicorn in production too, not just `runserver`.
"""
from __future__ import annotations

import logging
import time


_access_logger = logging.getLogger('access')


class SyslogAccessLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        started = time.monotonic()
        response = self.get_response(request)
        try:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            ip = _client_ip(request)
            user = getattr(getattr(request, 'user', None), 'username', '') or '-'
            line = (
                f'ip={ip} user={user} method={request.method} '
                f'path={request.get_full_path()} '
                f'status={response.status_code} elapsed_ms={elapsed_ms}'
            )
            # Single sink: the `access` logger. LOGGING config routes it to
            # access.log AND (opt-in) to syslog via SyslogAccessHandler.
            if response.status_code >= 400:
                _access_logger.warning(line)
            else:
                _access_logger.info(line)
        except Exception:
            pass  # access-log forwarding must never break the response
        return response


def _client_ip(request) -> str:
    """Best-effort client IP — respects `X-Forwarded-For` when the request
    already carries a `client_ip` attribute set upstream by the auth layer;
    falls back to REMOTE_ADDR."""
    ip = getattr(request, 'client_ip', '')
    if ip:
        return ip
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '-') or '-'
