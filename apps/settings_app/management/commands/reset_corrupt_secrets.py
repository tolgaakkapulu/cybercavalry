"""Clear secret Setting rows whose ciphertext can no longer be decrypted.

When the field-encryption key changes (Django SECRET_KEY rotated, .env
restored from a different install, DB copied across environments, …) every
secret stored with the old key shows up in the log as:

    Secret decryption failed — wrong field-encryption key, tampering, or
    corruption. Returning empty value...

The app already fails closed (returns ''), but the log noise repeats every
time the cache is warmed. This command finds those rows and blanks their
`value` so the warnings stop. The admin then re-enters each secret from the
Settings page.

Usage:
    python manage.py reset_corrupt_secrets             # apply the fix
    python manage.py reset_corrupt_secrets --dry-run   # list affected keys only
"""
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Clear secret Setting values whose encrypted blob cannot be decrypted with the current key.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run', action='store_true',
            help='List the affected secret keys without modifying the database.',
        )

    def handle(self, *args, **options):
        from apps.settings_app.models import Setting, ActivityLog
        from apps.settings_app.crypto import decrypt, is_encrypted
        from apps.settings_app.cache import SettingsCache

        dry = options['dry_run']
        secrets = Setting.objects.filter(is_secret=True).exclude(value='')

        broken = []
        for s in secrets:
            if not is_encrypted(s.value):
                continue  # legacy plain-text — leave untouched
            # Temporarily silence the per-call ERROR log; we report a summary.
            import logging
            crypto_logger = logging.getLogger('apps.settings_app.crypto')
            prev_level = crypto_logger.level
            crypto_logger.setLevel(logging.CRITICAL)
            try:
                plain = decrypt(s.value, key_hint=s.key)
            finally:
                crypto_logger.setLevel(prev_level)
            if plain == '':
                broken.append(s)

        if not broken:
            self.stdout.write(self.style.SUCCESS("No undecryptable secret rows found — nothing to do."))
            return

        if dry:
            self.stdout.write(f"[DRY RUN] {len(broken)} secret(s) would be cleared:")
            for s in broken:
                self.stdout.write(f"  - {s.key}")
            self.stdout.write("\nRun without --dry-run to apply.")
            return

        cleared_keys = []
        for s in broken:
            s.value = ''
            s.save(update_fields=['value'])
            SettingsCache.invalidate(s.key)
            cleared_keys.append(s.key)
            self.stdout.write(f"  cleared: {s.key}")

        ActivityLog.log(
            user=None,
            action='settings.secrets_reset',
            target_model='Setting',
            target_id='bulk',
            detail={'cleared_count': len(cleared_keys), 'keys': cleared_keys},
            ip_address='',
        )

        self.stdout.write(self.style.SUCCESS(
            f"\n{len(cleared_keys)} secret(s) cleared. Re-enter each value from the Settings UI."
        ))
