"""RFC 3164 / 5424 syslog forwarder for CYBERCavalry.

Reads configuration from Settings → Actions → Syslog on every emit so admins
can flip the toggles without a service restart. Three streams are supported
independently:

  * activity — written from `ActivityLog.log()` after the DB row is saved
  * error    — driven by a `logging.Handler` that we attach to the root
               Python logger when at least one stream is enabled
  * access   — emitted by the request middleware for every finished response

To minimise blast radius, `emit()` never raises. Socket errors are logged
once per minute at WARNING level and dropped silently otherwise so a broken
collector cannot cripple the request path.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Literal

from apps.settings_app.cache import SettingsCache

logger = logging.getLogger(__name__)

# RFC 3164 facility (16 = local0) and severity map.
# We keep the wire format simple: <PRI>message
# PRI = facility * 8 + severity
_FACILITY_LOCAL0 = 16
_SEVERITY = {
    'debug':    7,
    'info':     6,
    'notice':   5,
    'warning':  4,
    'error':    3,
    'critical': 2,
    'alert':    1,
    'emerg':    0,
}


# One shared UDP socket / TCP connection to avoid the sub-millisecond
# hand-shake overhead on every activity-log write. Rebuilt when settings
# change (see `invalidate()`).
_state_lock = threading.Lock()
_state: dict = {
    'host':       None,
    'port':       None,
    'protocol':   None,
    'sock':       None,
    'last_error_ts': 0.0,
}


def _current_config() -> dict:
    def _bool(key, default=False):
        return bool(SettingsCache.get(key, default))
    def _int(key, default):
        try:
            return int(SettingsCache.get(key, default) or default)
        except (TypeError, ValueError):
            return default
    def _str(key, default=''):
        return (SettingsCache.get(key, default) or default).strip()
    return {
        'enabled':      _bool('actions.syslog_enabled'),
        'host':         _str('actions.syslog_host'),
        'port':         _int('actions.syslog_port', 514),
        'protocol':     _str('actions.syslog_protocol', 'udp').lower(),
        'send_activity': _bool('actions.syslog_send_activity'),
        'send_error':    _bool('actions.syslog_send_error'),
        'send_access':   _bool('actions.syslog_send_access'),
    }


def stream_enabled(stream: Literal['activity', 'error', 'access']) -> bool:
    """Return True iff syslog is on AND this specific stream is toggled on.
    Used as the fast-path guard by every caller before formatting a message."""
    cfg = _current_config()
    if not cfg['enabled'] or not cfg['host']:
        return False
    return {
        'activity': cfg['send_activity'],
        'error':    cfg['send_error'],
        'access':   cfg['send_access'],
    }.get(stream, False)


def _ensure_socket(cfg: dict):
    """Return the shared socket, opening it if the config has changed."""
    signature = (cfg['host'], cfg['port'], cfg['protocol'])
    if _state.get('sock') and (
        _state['host'], _state['port'], _state['protocol']
    ) == signature:
        return _state['sock']

    # Close previous connection cleanly (best-effort).
    prev = _state.get('sock')
    if prev is not None:
        try:
            prev.close()
        except Exception:
            pass

    if cfg['protocol'] == 'tcp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((cfg['host'], cfg['port']))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

    _state.update({'host': cfg['host'], 'port': cfg['port'],
                   'protocol': cfg['protocol'], 'sock': sock})
    return sock


def _wire(pri: int, msg: str) -> bytes:
    """Build a minimal RFC 3164-style datagram."""
    host = socket.gethostname().split('.', 1)[0] or 'cybercavalry'
    ts = time.strftime('%b %d %H:%M:%S', time.localtime())
    line = f'<{pri}>{ts} {host} cybercavalry: {msg}'
    if len(line) > 1024:
        line = line[:1024]
    return line.encode('utf-8', errors='replace')


def emit(stream: Literal['activity', 'error', 'access'],
         message: str,
         severity: str = 'info') -> None:
    """Send `message` to the configured collector on behalf of `stream`.

    Silently returns when syslog is off or the stream isn't selected. Never
    raises — a broken collector cannot break the caller.
    """
    cfg = _current_config()
    if not cfg['enabled'] or not cfg['host']:
        return
    stream_on = {
        'activity': cfg['send_activity'],
        'error':    cfg['send_error'],
        'access':   cfg['send_access'],
    }.get(stream, False)
    if not stream_on:
        return

    pri = _FACILITY_LOCAL0 * 8 + _SEVERITY.get(severity.lower(), 6)
    wire = _wire(pri, message)

    with _state_lock:
        try:
            sock = _ensure_socket(cfg)
            if cfg['protocol'] == 'tcp':
                sock.sendall(wire + b'\n')
            else:
                sock.sendto(wire, (cfg['host'], cfg['port']))
        except Exception as exc:
            # Rate-limit the noise: log at WARNING at most once per minute.
            now = time.time()
            if now - _state.get('last_error_ts', 0.0) > 60:
                logger.warning("Syslog send failed to %s:%s (%s): %s",
                               cfg['host'], cfg['port'], cfg['protocol'], exc)
                _state['last_error_ts'] = now
            # Drop the shared socket so the next call re-connects.
            try:
                if _state.get('sock') is not None:
                    _state['sock'].close()
            except Exception:
                pass
            _state['sock'] = None


def invalidate() -> None:
    """Force the shared socket to be rebuilt on the next `emit()`.
    Call this from `settings_save` when any `actions.syslog_*` setting flips."""
    with _state_lock:
        try:
            if _state.get('sock') is not None:
                _state['sock'].close()
        except Exception:
            pass
        _state['sock'] = None
        _state['host'] = None
        _state['port'] = None
        _state['protocol'] = None


def test_connection() -> tuple[bool, str]:
    """Send a single probe message using the current settings. Used by the
    "Test Syslog" button — the response tells the admin whether the
    collector accepts the packet without waiting for a real event."""
    cfg = _current_config()
    if not cfg['host']:
        return False, 'Syslog host is empty. Fill in the Syslog tab first.'
    invalidate()
    try:
        pri = _FACILITY_LOCAL0 * 8 + _SEVERITY['info']
        wire = _wire(pri, 'CYBERCavalry syslog test message')
        sock = _ensure_socket(cfg)
        if cfg['protocol'] == 'tcp':
            sock.sendall(wire + b'\n')
        else:
            sock.sendto(wire, (cfg['host'], cfg['port']))
        return True, f'Test message sent to {cfg["host"]}:{cfg["port"]} via {cfg["protocol"].upper()}.'
    except Exception as exc:
        return False, f'Syslog send failed: {exc}'


def _record_severity(record: logging.LogRecord) -> str:
    if record.levelno >= logging.CRITICAL:
        return 'critical'
    if record.levelno >= logging.ERROR:
        return 'error'
    if record.levelno >= logging.WARNING:
        return 'warning'
    return 'info'


class _BaseSyslogHandler(logging.Handler):
    """Common shell for the three syslog handlers wired into Django LOGGING.

    Each subclass sets `stream` to `'activity' | 'error' | 'access'`. Every
    `emit()` re-reads the live Settings → Actions → Syslog toggle so an
    admin flipping the checkbox in the UI takes effect on the next log
    record — no restart required. Never raises: handlers must not break the
    caller (stdlib contract).
    """
    stream: str = ''

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if not self.stream or not stream_enabled(self.stream):
                return
            msg = self.format(record)
            emit(self.stream, msg, severity=_record_severity(record))
        except Exception:
            pass


class SyslogMainHandler(_BaseSyslogHandler):
    """Mirrors `cybercavalry.log` writes to syslog under the 'activity'
    stream (Forward Activity Logs checkbox)."""
    stream = 'activity'


class SyslogErrorHandler(_BaseSyslogHandler):
    """Mirrors `error.log` writes to syslog under the 'error' stream
    (Forward Error Logs checkbox)."""
    stream = 'error'


class SyslogAccessHandler(_BaseSyslogHandler):
    """Mirrors `access.log` writes to syslog under the 'access' stream
    (Forward Access Logs checkbox)."""
    stream = 'access'
