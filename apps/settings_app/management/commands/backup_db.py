"""
Manual / cron database backup.

Usage:
  python manage.py backup_db          # honour the backup.enabled setting
  python manage.py backup_db --force  # back up even if backup.enabled is off

Useful as an OS-level cron fallback or for ad-hoc backups. The in-app
scheduler already runs this automatically when backup.enabled is true.
"""
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create a timestamped backup of the database into the configured directory."

    def add_arguments(self, parser):
        parser.add_argument(
            '--force', action='store_true',
            help='Run even when backup.enabled is false.',
        )

    def handle(self, *args, **options):
        from apps.settings_app.cache import SettingsCache
        from apps.settings_app.backup_service import run_backup

        if not options['force'] and not SettingsCache.get('backup.enabled', False):
            self.stdout.write(self.style.WARNING(
                "backup.enabled is false — skipping. Use --force to override."
            ))
            return

        result = run_backup(user=None, trigger='cli')
        if result.get('success'):
            self.stdout.write(self.style.SUCCESS(result.get('message', 'Backup complete.')))
        else:
            self.stderr.write(self.style.ERROR(result.get('message', 'Backup failed.')))
            raise SystemExit(1)
