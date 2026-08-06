"""
AbuseIPDB background scheduler.

Started once from BlacklistConfig.ready(). Reads schedule settings from the DB
on every trigger so changes take effect without a server restart (after Save).

Also runs a periodic cleanup job every 15 minutes to deactivate expired blacklist
entries and write a full audit log for each one.
"""
import logging
import threading

logger = logging.getLogger(__name__)

_scheduler = None
_lock = threading.RLock()  # RLock: same thread can re-acquire (avoids deadlock from start→reschedule)
_JOB_ID         = 'abuseipdb_auto_refresh'
_CLEANUP_JOB_ID = 'blacklist_cleanup_expired'
_VT_JOB_ID      = 'virustotal_auto_refresh'
_BACKUP_JOB_ID  = 'db_backup'
_QUOTA_JOB_ID       = 'actions_quota_alert'
_RATE_LIMIT_JOB_ID  = 'actions_rate_limit_alert'
_SILENCE_JOB_ID     = 'actions_silence_alert'

# Management commands that should NOT start the scheduler
_SKIP_COMMANDS = {
    'makemigrations', 'migrate', 'collectstatic', 'shell',
    'createsuperuser', 'seed_initial_data', 'cleanup_expired',
    'scheduled_abuse_refresh', 'backup_db',
}


def _run_cleanup_expired():
    """
    Deactivates blacklist entries whose expires_at is in the past.
    Logs full entry details to both the Python logger and ActivityLog.
    Runs every 15 minutes via APScheduler.
    """
    from django.utils import timezone
    from apps.blacklist.models import BlacklistEntry
    from apps.settings_app.models import ActivityLog

    now = timezone.now()
    expired_qs = BlacklistEntry.objects.filter(
        is_active=True,
        expires_at__lt=now,
    ).select_related('group', 'added_by')

    expired_entries = list(expired_qs)
    count = len(expired_entries)

    if count == 0:
        return

    # One ActivityLog row per entry — easier to filter/search than a single
    # bulk row carrying all of them inside a JSON list.
    for e in expired_entries:
        logger.warning(
            "Blacklist entry expired and deactivated: cidr=%s group=%s "
            "added_by=%s added_at=%s expires_at=%s hit_count=%d source=%s reason=%r",
            e.cidr,
            e.group.name,
            e.added_by.username if e.added_by else 'system',
            e.added_at.isoformat() if e.added_at else 'N/A',
            e.expires_at.isoformat() if e.expires_at else 'N/A',
            e.hit_count,
            e.source,
            e.reason,
        )
        ActivityLog.log(
            user=None,
            action='blacklist.entry_expired',
            target_model='BlacklistEntry',
            target_id=str(e.id),
            detail={
                'cidr':                   e.cidr,
                'ip_address':             e.ip_address,
                'prefix_length':          e.prefix_length,
                'group':                  e.group.name,
                'group_label':            e.group.label,
                'reason':                 e.reason,
                'source':                 e.source,
                'added_by':               e.added_by.username if e.added_by else None,
                'added_at':               e.added_at.isoformat() if e.added_at else None,
                'expires_at':             e.expires_at.isoformat() if e.expires_at else None,
                'hit_count':              e.hit_count,
                'last_seen_at':           e.last_seen_at.isoformat() if e.last_seen_at else None,
                'abuse_confidence_score': e.abuse_confidence_score,
                'reporter_ip':            e.reporter_ip,
                'is_pinned':              e.is_pinned,
                'deactivated_at':         now.isoformat(),
                'trigger':                'scheduler',
            },
        )

    BlacklistEntry.objects.filter(
        id__in=[e.id for e in expired_entries]
    ).update(is_active=False)

    logger.warning(
        "cleanup_expired (scheduler): deactivated %d expired blacklist entries.", count
    )


def _run_scheduled_refresh():
    """Executed by APScheduler on each trigger. Reads live settings each time.

    Two independent jobs share this entry point: the AbuseIPDB score refresh
    and the inactive-entry cleanup. Each runs only when its own toggle is on,
    so an admin can enable cleanup without enabling scoring (or vice versa)
    and the schedule still fires daily as long as ONE of them is on.
    """
    from django.utils import timezone
    from apps.settings_app.cache import SettingsCache
    from apps.settings_app.models import ActivityLog
    from apps.blacklist.abuseipdb_service import bulk_refresh

    refresh_on = (
        SettingsCache.get('threat_intel.abuseipdb_schedule_enabled', False)
        and SettingsCache.get('threat_intel.abuseipdb_enabled', False)
        and SettingsCache.get('threat_intel.abuseipdb_api_key', '').strip()
    )
    cleanup_on = SettingsCache.get('threat_intel.abuseipdb_cleanup_enabled', False)

    if not refresh_on and not cleanup_on:
        logger.info("AbuseIPDB scheduler tick: both refresh and cleanup disabled — skipping.")
        return

    if refresh_on:
        started_at = timezone.now()
        logger.info("AbuseIPDB scheduled refresh: starting...")
        try:
            checked, skipped, failed = bulk_refresh(only_unchecked=False)
            elapsed = round((timezone.now() - started_at).total_seconds(), 1)
            logger.info(
                f"AbuseIPDB scheduled refresh complete — "
                f"checked={checked}, skipped={skipped}, failed={failed}, elapsed={elapsed}s"
            )
            ActivityLog.log(
                user=None,
                action='threat_intel.abuseipdb_scheduled_refresh',
                target_model='BlacklistEntry',
                target_id='bulk',
                detail={
                    'checked': checked, 'skipped': skipped, 'failed': failed,
                    'elapsed_seconds': elapsed, 'trigger': 'scheduled',
                },
            )
        except Exception as exc:
            elapsed = round((timezone.now() - started_at).total_seconds(), 1)
            logger.error(
                f"AbuseIPDB scheduled refresh failed after {elapsed}s: {exc}",
                exc_info=True,
            )
            try:
                ActivityLog.log(
                    user=None,
                    action='threat_intel.abuseipdb_scheduled_refresh_error',
                    target_model='BlacklistEntry',
                    target_id='bulk',
                    detail={'error': str(exc), 'elapsed_seconds': elapsed, 'trigger': 'scheduled'},
                )
            except Exception:
                pass

    # Cleanup runs independently of the refresh outcome — even if refresh
    # is off (or just failed) we still honour the cleanup toggle.
    if cleanup_on:
        try:
            from apps.blacklist.cleanup_service import run_cleanup as _bl_cleanup
            _bl_cleanup(actor=None, client_ip='')
        except Exception as ce:
            logger.warning("AbuseIPDB scheduled cleanup failed: %s", ce)


def _run_virustotal_refresh():
    """Executed by APScheduler on each trigger. Reads live settings each time."""
    from django.utils import timezone
    from apps.settings_app.cache import SettingsCache
    from apps.settings_app.models import ActivityLog
    from apps.hashlist.virustotal_service import bulk_refresh as vt_bulk_refresh

    refresh_on = (
        SettingsCache.get('threat_intel.virustotal_schedule_enabled', False)
        and SettingsCache.get('threat_intel.virustotal_enabled', False)
        and SettingsCache.get('threat_intel.virustotal_api_key', '').strip()
    )
    cleanup_on = SettingsCache.get('threat_intel.virustotal_cleanup_enabled', False)

    if not refresh_on and not cleanup_on:
        logger.info("VirusTotal scheduler tick: both refresh and cleanup disabled — skipping.")
        return

    if refresh_on:
        started_at = timezone.now()
        logger.info("VirusTotal scheduled refresh: starting...")
        try:
            checked, skipped, failed = vt_bulk_refresh(only_unchecked=False)
            elapsed = round((timezone.now() - started_at).total_seconds(), 1)
            logger.info(
                f"VirusTotal scheduled refresh complete — "
                f"checked={checked}, skipped={skipped}, failed={failed}, elapsed={elapsed}s"
            )
            ActivityLog.log(
                user=None,
                action='threat_intel.virustotal_scheduled_refresh',
                target_model='HashEntry',
                target_id='bulk',
                detail={
                    'checked': checked, 'skipped': skipped, 'failed': failed,
                    'elapsed_seconds': elapsed, 'trigger': 'scheduled',
                },
            )
        except Exception as exc:
            elapsed = round((timezone.now() - started_at).total_seconds(), 1)
            logger.error(
                f"VirusTotal scheduled refresh failed after {elapsed}s: {exc}",
                exc_info=True,
            )
            try:
                ActivityLog.log(
                    user=None,
                    action='threat_intel.virustotal_scheduled_refresh_error',
                    target_model='HashEntry',
                    target_id='bulk',
                    detail={'error': str(exc), 'elapsed_seconds': elapsed, 'trigger': 'scheduled'},
                )
            except Exception:
                pass

    # Cleanup runs independently of refresh — honoured even when refresh
    # is off or just failed.
    if cleanup_on:
        try:
            from apps.hashlist.cleanup_service import run_cleanup as _hl_cleanup
            _hl_cleanup(actor=None, client_ip='')
        except Exception as ce:
            logger.warning("VirusTotal scheduled cleanup failed: %s", ce)


def _run_db_backup():
    """Executed by APScheduler on each trigger. Reads live settings each time."""
    from apps.settings_app.cache import SettingsCache

    if not SettingsCache.get('backup.enabled', False):
        logger.info("DB backup: disabled — skipping.")
        return

    try:
        from apps.settings_app.backup_service import run_backup
        result = run_backup(user=None, trigger='scheduled')
        if result.get('success'):
            logger.info("DB backup (scheduled): %s", result.get('message'))
        else:
            logger.error("DB backup (scheduled) failed: %s", result.get('message'))
    except Exception as exc:
        logger.error("DB backup (scheduled) crashed: %s", exc, exc_info=True)


def _run_quota_alert():
    """Actions → Quota Alert scheduler entry — probes both providers and
    (only if the threshold is crossed AND cooldown is respected) sends the
    configured recipient an e-mail. All decision logic lives in
    `alert_service.run_quota_alert_check`; this shell just isolates the
    thread and captures crashes."""
    try:
        from apps.settings_app.alert_service import run_quota_alert_check
        result = run_quota_alert_check(actor=None, ip='')
        if result.get('sent'):
            logger.info("Quota alert e-mail sent to %s for %s.",
                        result.get('recipient'), ', '.join(result.get('providers', [])))
    except Exception as exc:
        logger.error("Quota alert check crashed: %s", exc, exc_info=True)


def _run_rate_limit_alert():
    """Actions → API Rate Limit Alert scheduler entry — samples the last
    60 s of API traffic per caller and mails offenders (with per-caller
    cooldown). Decision logic in `alert_service.run_rate_limit_alert_check`."""
    try:
        from apps.settings_app.alert_service import run_rate_limit_alert_check
        result = run_rate_limit_alert_check(actor=None, ip='')
        if result.get('sent'):
            logger.info("Rate-limit alert e-mail sent to %s for %s.",
                        result.get('recipient'), ', '.join(result.get('callers', [])))
    except Exception as exc:
        logger.error("Rate-limit alert check crashed: %s", exc, exc_info=True)


def _run_silence_alert():
    """Actions → API Silence Alert scheduler entry — scans the last 24h of
    API events for monitored callers (baseline hits >= configured) and mails
    the recipient when any of them have gone silent past the threshold. Decision
    logic in `alert_service.run_silence_alert_check`."""
    try:
        from apps.settings_app.alert_service import run_silence_alert_check
        result = run_silence_alert_check(actor=None, ip='')
        if result.get('sent'):
            logger.info("Silence alert e-mail sent to %s for %s.",
                        result.get('recipient'), ', '.join(result.get('callers', [])))
    except Exception as exc:
        logger.error("Silence alert check crashed: %s", exc, exc_info=True)


def _build_trigger(interval, time_str):
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger

    if interval == 'hourly':
        return IntervalTrigger(hours=1)

    # Daily — parse HH:MM
    try:
        hour, minute = (int(x) for x in str(time_str).split(':'))
    except (ValueError, AttributeError):
        hour, minute = 2, 0

    from django.conf import settings as dj_settings
    tz = getattr(dj_settings, 'TIME_ZONE', 'UTC')
    return CronTrigger(hour=hour, minute=minute, timezone=tz)


def start():
    """Initialize and start the background scheduler. Called from AppConfig.ready()."""
    global _scheduler

    import sys
    argv_commands = set(sys.argv[1:2])  # first positional arg is the subcommand
    if argv_commands & _SKIP_COMMANDS:
        return

    with _lock:
        if _scheduler is not None:
            return  # Already running

        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from django.conf import settings as dj_settings

            tz = getattr(dj_settings, 'TIME_ZONE', 'UTC')
            _scheduler = BackgroundScheduler(timezone=tz)
            _scheduler.start()
            logger.info("AbuseIPDB background scheduler started.")

            # Cleanup expired entries every 15 minutes — always active, no settings gate.
            from apscheduler.triggers.interval import IntervalTrigger as _IT
            _scheduler.add_job(
                _run_cleanup_expired,
                trigger=_IT(minutes=15),
                id=_CLEANUP_JOB_ID,
                name='Blacklist Cleanup Expired',
                replace_existing=True,
                misfire_grace_time=120,
            )
            logger.info("Blacklist cleanup-expired job scheduled (every 15 min).")

            reschedule()
            reschedule_vt()
            reschedule_backup()
            reschedule_quota_alert()
            reschedule_rate_limit_alert()
            reschedule_silence_alert()
        except ImportError:
            logger.warning(
                "APScheduler not installed — scheduled AbuseIPDB refresh unavailable. "
                "Run: pip install APScheduler==3.10.4"
            )
            _scheduler = None
        except Exception as exc:
            logger.error(f"Failed to start AbuseIPDB scheduler: {exc}", exc_info=True)
            _scheduler = None


def reschedule():
    """Re-read settings and update (or remove) the scheduled job. Safe to call any time."""
    global _scheduler

    if _scheduler is None:
        return

    with _lock:
        try:
            from apps.settings_app.cache import SettingsCache

            refresh_on = SettingsCache.get('threat_intel.abuseipdb_schedule_enabled', False)
            cleanup_on = SettingsCache.get('threat_intel.abuseipdb_cleanup_enabled', False)
            interval   = SettingsCache.get('threat_intel.abuseipdb_schedule_interval', 'daily')
            time_str   = SettingsCache.get('threat_intel.abuseipdb_schedule_time', '02:00')

            # Remove existing job
            if _scheduler.get_job(_JOB_ID):
                _scheduler.remove_job(_JOB_ID)

            # Schedule the tick if EITHER refresh or cleanup is on — the
            # job itself decides which sub-task to run, so cleanup-only
            # admins still get a daily run without enabling scoring.
            if not (refresh_on or cleanup_on):
                logger.info("AbuseIPDB scheduler: refresh + cleanup both disabled — no job.")
                return

            trigger = _build_trigger(interval, time_str)
            _scheduler.add_job(
                _run_scheduled_refresh,
                trigger=trigger,
                id=_JOB_ID,
                name='AbuseIPDB Auto Refresh / Cleanup',
                replace_existing=True,
                misfire_grace_time=300,
            )

            job = _scheduler.get_job(_JOB_ID)
            next_run = (
                job.next_run_time.strftime('%Y-%m-%d %H:%M')
                if job and job.next_run_time else 'unknown'
            )
            logger.info(
                f"AbuseIPDB scheduler: job scheduled ({interval}), next run: {next_run}"
            )

        except Exception as exc:
            logger.error(f"AbuseIPDB scheduler reschedule failed: {exc}", exc_info=True)


def reschedule_vt():
    """Re-read VT settings and update (or remove) the scheduled VT job. Safe to call any time."""
    global _scheduler

    if _scheduler is None:
        return

    with _lock:
        try:
            from apps.settings_app.cache import SettingsCache

            refresh_on = SettingsCache.get('threat_intel.virustotal_schedule_enabled', False)
            cleanup_on = SettingsCache.get('threat_intel.virustotal_cleanup_enabled', False)
            interval   = SettingsCache.get('threat_intel.virustotal_schedule_interval', 'daily')
            time_str   = SettingsCache.get('threat_intel.virustotal_schedule_time', '03:00')

            if _scheduler.get_job(_VT_JOB_ID):
                _scheduler.remove_job(_VT_JOB_ID)

            if not (refresh_on or cleanup_on):
                logger.info("VirusTotal scheduler: refresh + cleanup both disabled — no job.")
                return

            trigger = _build_trigger(interval, time_str)
            _scheduler.add_job(
                _run_virustotal_refresh,
                trigger=trigger,
                id=_VT_JOB_ID,
                name='VirusTotal Auto Refresh / Cleanup',
                replace_existing=True,
                misfire_grace_time=300,
            )

            job = _scheduler.get_job(_VT_JOB_ID)
            next_run = (
                job.next_run_time.strftime('%Y-%m-%d %H:%M')
                if job and job.next_run_time else 'unknown'
            )
            logger.info(
                f"VirusTotal scheduler: job scheduled ({interval}), next run: {next_run}"
            )

        except Exception as exc:
            logger.error(f"VirusTotal scheduler reschedule failed: {exc}", exc_info=True)


def reschedule_backup():
    """Re-read backup settings and update (or remove) the daily backup job."""
    global _scheduler

    if _scheduler is None:
        return

    with _lock:
        try:
            from apps.settings_app.cache import SettingsCache

            enabled  = SettingsCache.get('backup.enabled', False)
            time_str = SettingsCache.get('backup.time', '04:00')

            if _scheduler.get_job(_BACKUP_JOB_ID):
                _scheduler.remove_job(_BACKUP_JOB_ID)

            if not enabled:
                logger.info("DB backup: disabled.")
                return

            # Backups are always daily at the configured time.
            trigger = _build_trigger('daily', time_str)
            _scheduler.add_job(
                _run_db_backup,
                trigger=trigger,
                id=_BACKUP_JOB_ID,
                name='Database Backup',
                replace_existing=True,
                misfire_grace_time=3600,
            )

            job = _scheduler.get_job(_BACKUP_JOB_ID)
            next_run = (
                job.next_run_time.strftime('%Y-%m-%d %H:%M')
                if job and job.next_run_time else 'unknown'
            )
            logger.info(f"DB backup: job scheduled (daily {time_str}), next run: {next_run}")

        except Exception as exc:
            logger.error(f"DB backup reschedule failed: {exc}", exc_info=True)


def reschedule_quota_alert():
    """Reconfigure the quota-alert job from Settings → Actions. Reads the
    interval + unit on every call so an admin's Save reflects immediately."""
    if _scheduler is None:
        return

    with _lock:
        try:
            from apps.settings_app.cache import SettingsCache
            from apscheduler.triggers.interval import IntervalTrigger

            enabled = SettingsCache.get('actions.quota_alert_enabled', False)

            if _scheduler.get_job(_QUOTA_JOB_ID):
                _scheduler.remove_job(_QUOTA_JOB_ID)

            if not enabled:
                logger.info("Quota alert: disabled.")
                return

            try:
                interval = int(SettingsCache.get('actions.quota_check_interval', 1) or 1)
            except (TypeError, ValueError):
                interval = 1
            interval = max(1, min(interval, 24 * 60))  # 1 min .. 24 hours-in-minutes ceiling

            unit = (SettingsCache.get('actions.quota_check_interval_unit', 'hours') or 'hours').lower()
            if unit == 'minutes':
                trigger = IntervalTrigger(minutes=interval)
            else:
                trigger = IntervalTrigger(hours=interval)

            _scheduler.add_job(
                _run_quota_alert,
                trigger=trigger,
                id=_QUOTA_JOB_ID,
                name='Quota Alert Check',
                replace_existing=True,
                misfire_grace_time=300,
            )
            job = _scheduler.get_job(_QUOTA_JOB_ID)
            next_run = (
                job.next_run_time.strftime('%Y-%m-%d %H:%M')
                if job and job.next_run_time else 'unknown'
            )
            logger.info("Quota alert: job scheduled (every %d %s), next run: %s",
                        interval, unit, next_run)
        except Exception as exc:
            logger.error(f"Quota alert reschedule failed: {exc}", exc_info=True)


def reschedule_rate_limit_alert():
    """Reconfigure the rate-limit-alert job from Settings → Actions. The
    check runs on a fixed 60-second interval — rate-limit windows are
    minute-sized, so anything longer would miss short spikes."""
    if _scheduler is None:
        return

    with _lock:
        try:
            from apps.settings_app.cache import SettingsCache
            from apscheduler.triggers.interval import IntervalTrigger

            enabled = SettingsCache.get('actions.rate_limit_alert_enabled', False)

            if _scheduler.get_job(_RATE_LIMIT_JOB_ID):
                _scheduler.remove_job(_RATE_LIMIT_JOB_ID)

            if not enabled:
                logger.info("Rate-limit alert: disabled.")
                return

            _scheduler.add_job(
                _run_rate_limit_alert,
                trigger=IntervalTrigger(seconds=60),
                id=_RATE_LIMIT_JOB_ID,
                name='Rate Limit Alert Check',
                replace_existing=True,
                misfire_grace_time=30,
            )
            job = _scheduler.get_job(_RATE_LIMIT_JOB_ID)
            next_run = (
                job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
                if job and job.next_run_time else 'unknown'
            )
            logger.info("Rate-limit alert: job scheduled (every 60 s), next run: %s", next_run)
        except Exception as exc:
            logger.error(f"Rate-limit alert reschedule failed: {exc}", exc_info=True)


def reschedule_silence_alert():
    """Reconfigure the silence-alert job from Settings → Actions. Runs on a
    60-second interval; per-minute callers with a 5-minute threshold need a
    check cadence at least that fast to catch the transition promptly."""
    if _scheduler is None:
        return

    with _lock:
        try:
            from apps.settings_app.cache import SettingsCache
            from apscheduler.triggers.interval import IntervalTrigger

            enabled = SettingsCache.get('actions.silence_alert_enabled', False)

            if _scheduler.get_job(_SILENCE_JOB_ID):
                _scheduler.remove_job(_SILENCE_JOB_ID)

            if not enabled:
                logger.info("Silence alert: disabled.")
                return

            _scheduler.add_job(
                _run_silence_alert,
                trigger=IntervalTrigger(seconds=60),
                id=_SILENCE_JOB_ID,
                name='API Silence Alert Check',
                replace_existing=True,
                misfire_grace_time=30,
            )
            job = _scheduler.get_job(_SILENCE_JOB_ID)
            next_run = (
                job.next_run_time.strftime('%Y-%m-%d %H:%M:%S')
                if job and job.next_run_time else 'unknown'
            )
            logger.info("Silence alert: job scheduled (every 60 s), next run: %s", next_run)
        except Exception as exc:
            logger.error(f"Silence alert reschedule failed: {exc}", exc_info=True)


def get_backup_status():
    """Return a dict describing current backup scheduler state for UI display."""
    if _scheduler is None or not _scheduler.running:
        return {'running': False, 'next_run': None, 'job_exists': False}

    try:
        from django.utils import timezone
        job = _scheduler.get_job(_BACKUP_JOB_ID)
        next_run = None
        if job and job.next_run_time:
            next_run = timezone.localtime(job.next_run_time).strftime('%Y-%m-%d %H:%M')
        return {
            'running': True,
            'next_run': next_run,
            'job_exists': job is not None,
        }
    except Exception:
        return {'running': False, 'next_run': None, 'job_exists': False}


def get_vt_status():
    """Return a dict describing current VT scheduler state for UI display."""
    if _scheduler is None or not _scheduler.running:
        return {'running': False, 'next_run': None, 'job_exists': False}

    try:
        from django.utils import timezone
        job = _scheduler.get_job(_VT_JOB_ID)
        next_run = None
        if job and job.next_run_time:
            next_run = timezone.localtime(job.next_run_time).strftime('%Y-%m-%d %H:%M')
        return {
            'running': True,
            'next_run': next_run,
            'job_exists': job is not None,
        }
    except Exception:
        return {'running': False, 'next_run': None, 'job_exists': False}


def get_status():
    """Return a dict describing current scheduler state for UI display."""
    if _scheduler is None or not _scheduler.running:
        return {'running': False, 'next_run': None, 'job_exists': False}

    try:
        from django.utils import timezone
        job = _scheduler.get_job(_JOB_ID)
        next_run = None
        if job and job.next_run_time:
            next_run = timezone.localtime(job.next_run_time).strftime('%Y-%m-%d %H:%M')
        return {
            'running': True,
            'next_run': next_run,
            'job_exists': job is not None,
        }
    except Exception:
        return {'running': False, 'next_run': None, 'job_exists': False}
