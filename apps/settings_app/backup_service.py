"""
Database backup service.

Creates timestamped, cumulative copies of the SQLite database into a
configured directory and applies an optional retention policy.

Settings (category 'backup'):
  backup.enabled         (bool) — daily auto-backup on/off
  backup.directory       (str)  — target dir; blank → <BASE_DIR>/backups
  backup.time            (str)  — HH:MM daily run time (used by scheduler)
  backup.retention_days  (int)  — delete backups older than N days; 0 = keep all
  backup.max_count       (int)  — keep at most N most-recent backups; 0 = unlimited

Backups are SQLite-consistent: the online backup API is used so a copy can be
taken safely even while the app is writing.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from django.conf import settings as dj_settings

logger = logging.getLogger(__name__)

# Matches backups written under any platform name — keeps listing and
# retention working across rebrands (old "cybercavalry_*.db" files alongside
# new "<configured>_*.db" files).
_FILENAME_GLOB = '*_*.db'


def _default_backup_dir() -> Path:
    return Path(dj_settings.BASE_DIR) / 'backups'


def get_backup_dir() -> Path:
    """
    Resolve the configured backup directory (falls back to <BASE_DIR>/backups).

    Hardening: relative paths are confined under BASE_DIR (prevents ambiguous /
    surprising write locations), and the result is resolved so any '..' traversal
    is normalized away before we mkdir/write/prune in it.
    """
    from apps.settings_app.cache import SettingsCache
    raw = (SettingsCache.get('backup.directory', '') or '').strip()
    if not raw:
        return _default_backup_dir().resolve()
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = Path(dj_settings.BASE_DIR) / p
    return p.resolve()


def _sqlite_path() -> Path | None:
    """Return the SQLite DB file path, or None if the default DB is not SQLite."""
    db = dj_settings.DATABASES.get('default', {})
    engine = db.get('ENGINE', '')
    if 'sqlite' not in engine:
        return None
    return Path(db['NAME'])


def _apply_retention(backup_dir: Path, retention_days: int) -> int:
    """Delete backups older than retention_days. Returns number of files removed."""
    if retention_days <= 0:
        return 0
    cutoff = datetime.now() - timedelta(days=retention_days)
    removed = 0
    for f in backup_dir.glob(_FILENAME_GLOB):
        try:
            if datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                f.unlink()
                removed += 1
        except OSError as exc:
            logger.warning("Backup retention: could not remove %s: %s", f, exc)
    return removed


def _apply_max_count(backup_dir: Path, max_count: int) -> int:
    """Keep only the `max_count` most-recent backups. 0/negative → no limit.
    Returns number of files removed."""
    if max_count <= 0:
        return 0
    try:
        files = sorted(backup_dir.glob(_FILENAME_GLOB),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError as exc:
        logger.warning("Backup max-count: could not list %s: %s", backup_dir, exc)
        return 0
    extras = files[max_count:]
    removed = 0
    for f in extras:
        try:
            f.unlink()
            removed += 1
        except OSError as exc:
            logger.warning("Backup max-count: could not remove %s: %s", f, exc)
    return removed


def run_backup(user=None, trigger='manual', ip_address=''):
    """
    Create one timestamped backup of the SQLite database.

    Returns a dict:
      {'success': bool, 'path': str|None, 'size_bytes': int,
       'removed': int, 'message': str}

    Never raises — failures are logged and reported in the return value.
    """
    from apps.settings_app.cache import SettingsCache
    from apps.settings_app.models import ActivityLog

    started = datetime.now()

    src = _sqlite_path()
    if src is None:
        msg = ('Automatic backup supports SQLite only. The default database is not '
               'SQLite — use the native dump tool of your engine (e.g. pg_dump).')
        logger.error("DB backup: %s", msg)
        ActivityLog.log(user, 'backup.error', 'Database', 'db',
                        {'error': msg, 'trigger': trigger}, ip_address)
        return {'success': False, 'path': None, 'size_bytes': 0, 'removed': 0, 'message': msg}

    if not src.exists():
        msg = f'Database file not found: {src}'
        logger.error("DB backup: %s", msg)
        ActivityLog.log(user, 'backup.error', 'Database', 'db',
                        {'error': msg, 'trigger': trigger}, ip_address)
        return {'success': False, 'path': None, 'size_bytes': 0, 'removed': 0, 'message': msg}

    backup_dir = get_backup_dir()
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        msg = f'Cannot create backup directory {backup_dir}: {exc}'
        logger.error("DB backup: %s", msg)
        ActivityLog.log(user, 'backup.error', 'Database', 'db',
                        {'error': msg, 'trigger': trigger}, ip_address)
        return {'success': False, 'path': None, 'size_bytes': 0, 'removed': 0, 'message': msg}

    stamp = started.strftime('%Y%m%d_%H%M%S')
    from apps.settings_app.branding import brand_filename_prefix
    dest = backup_dir / f'{brand_filename_prefix()}_{stamp}.db'

    try:
        # SQLite online backup — consistent even under concurrent writes.
        src_conn = sqlite3.connect(f'file:{src}?mode=ro', uri=True)
        dst_conn = sqlite3.connect(str(dest))
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()
    except Exception as exc:  # noqa: BLE001 — report any backup failure
        logger.error("DB backup failed: %s", exc, exc_info=True)
        # Clean up a partial file
        try:
            if dest.exists():
                dest.unlink()
        except OSError:
            pass
        ActivityLog.log(user, 'backup.error', 'Database', 'db',
                        {'error': str(exc), 'trigger': trigger}, ip_address)
        return {'success': False, 'path': None, 'size_bytes': 0, 'removed': 0,
                'message': f'Backup failed: {exc}'}

    size = dest.stat().st_size

    try:
        retention = int(SettingsCache.get('backup.retention_days', 30) or 0)
    except (TypeError, ValueError):
        retention = 30
    try:
        max_count = int(SettingsCache.get('backup.max_count', 0) or 0)
    except (TypeError, ValueError):
        max_count = 0
    removed_age   = _apply_retention(backup_dir, retention)
    removed_count = _apply_max_count(backup_dir, max_count)
    removed = removed_age + removed_count

    elapsed = round((datetime.now() - started).total_seconds(), 2)
    msg = (f'Backup created: {dest.name} ({size / 1024:.0f} KB)'
           + (f', {removed} old backup(s) pruned' if removed else ''))
    logger.info("DB backup: %s [%ss, trigger=%s]", msg, elapsed, trigger)

    ActivityLog.log(user, 'backup.created', 'Database', dest.name, {
        'file': str(dest),
        'size_bytes': size,
        'removed': removed,
        'removed_by_age': removed_age,
        'removed_by_count': removed_count,
        'retention_days': retention,
        'max_count': max_count,
        'elapsed_seconds': elapsed,
        'trigger': trigger,
    }, ip_address)

    return {'success': True, 'path': str(dest), 'size_bytes': size,
            'removed': removed, 'message': msg}


def list_backups():
    """Return a list of existing backups (newest first) for UI display."""
    backup_dir = get_backup_dir()
    if not backup_dir.exists():
        return []
    items = []
    for f in backup_dir.glob(_FILENAME_GLOB):
        try:
            st = f.stat()
            items.append({
                'name': f.name,
                'size_bytes': st.st_size,
                'modified': datetime.fromtimestamp(st.st_mtime),
            })
        except OSError:
            continue
    items.sort(key=lambda x: x['modified'], reverse=True)
    return items
