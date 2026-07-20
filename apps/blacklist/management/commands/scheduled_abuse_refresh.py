"""
Management command: python manage.py scheduled_abuse_refresh

Manually triggers the same logic that runs on the automatic schedule.
Useful for testing, cron fallback, or one-off forced runs.
"""
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run AbuseIPDB score refresh for all active blacklist entries (same as scheduled job).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Run even if AbuseIPDB or scheduling is disabled in settings.',
        )

    def handle(self, *args, **options):
        from apps.settings_app.cache import SettingsCache
        from apps.settings_app.models import ActivityLog
        from apps.blacklist.abuseipdb_service import bulk_refresh

        force = options['force']

        if not force:
            if not SettingsCache.get('threat_intel.abuseipdb_enabled', False):
                self.stderr.write(self.style.WARNING(
                    'AbuseIPDB is disabled. Use --force to run anyway.'
                ))
                return
            if not SettingsCache.get('threat_intel.abuseipdb_api_key', '').strip():
                self.stderr.write(self.style.WARNING(
                    'AbuseIPDB API key is not configured. Use --force to attempt anyway.'
                ))
                return

        started_at = timezone.now()
        self.stdout.write(f'[{started_at.strftime("%Y-%m-%d %H:%M:%S")}] Starting AbuseIPDB refresh...')

        try:
            checked, skipped, failed = bulk_refresh(only_unchecked=False)
            elapsed = round((timezone.now() - started_at).total_seconds(), 1)

            summary = (
                f'Done — checked: {checked}, skipped: {skipped}, '
                f'failed: {failed}, elapsed: {elapsed}s'
            )
            self.stdout.write(self.style.SUCCESS(summary))
            logger.info(f'scheduled_abuse_refresh command: {summary}')

            ActivityLog.log(
                user=None,
                action='threat_intel.abuseipdb_scheduled_refresh',
                target_model='BlacklistEntry',
                target_id='bulk',
                detail={
                    'checked': checked,
                    'skipped': skipped,
                    'failed': failed,
                    'elapsed_seconds': elapsed,
                    'trigger': 'management_command',
                },
            )

        except Exception as exc:
            elapsed = round((timezone.now() - started_at).total_seconds(), 1)
            self.stderr.write(self.style.ERROR(f'Refresh failed after {elapsed}s: {exc}'))
            logger.error(f'scheduled_abuse_refresh command failed: {exc}', exc_info=True)
