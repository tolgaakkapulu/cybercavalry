"""
Security regression tests for settings_app hardening:
  * CSV formula-injection neutralization (csv_util)
  * Secret encryption round-trip + fail-closed decrypt (crypto)
  * Backup directory path confinement (backup_service)

Run: python manage.py test apps.settings_app
"""
from django.test import SimpleTestCase, override_settings


# ── CSV formula injection ──────────────────────────────────────────────────
class CsvSafeTests(SimpleTestCase):
    def test_formula_prefixes_are_neutralized(self):
        from apps.settings_app.csv_util import csv_safe
        for payload in ('=cmd|calc', '+1+1', '-2+3', '@SUM(A1)', '\ttabbed', '\rcarriage'):
            out = csv_safe(payload)
            self.assertEqual(out[0], "'", f"{payload!r} not prefixed")
            self.assertEqual(out[1:], payload, "original content must be preserved")

    def test_benign_values_unchanged(self):
        from apps.settings_app.csv_util import csv_safe
        self.assertEqual(csv_safe('192.168.1.10'), '192.168.1.10')
        self.assertEqual(csv_safe('manual reason text'), 'manual reason text')
        self.assertEqual(csv_safe('user (Full Name)'), 'user (Full Name)')

    def test_none_numbers_and_empty(self):
        from apps.settings_app.csv_util import csv_safe
        self.assertEqual(csv_safe(None), '')
        self.assertEqual(csv_safe(''), '')
        self.assertEqual(csv_safe(42), '42')
        self.assertEqual(csv_safe(0), '0')

    def test_safe_row_applies_to_all_cells(self):
        from apps.settings_app.csv_util import safe_row
        self.assertEqual(
            safe_row(['=evil()', 'ok', None, 5, '-1']),
            ["'=evil()", 'ok', '', '5', "'-1"],
        )


# ── Secret encryption / fail-closed decryption ─────────────────────────────
@override_settings(FIELD_ENCRYPTION_KEY='unit-test-field-key-AAAAAAAAAAAAAAAA', SECRET_KEY='unit-secret')
class CryptoTests(SimpleTestCase):
    def test_encrypt_decrypt_roundtrip(self):
        from apps.settings_app.crypto import encrypt, decrypt
        ct = encrypt('s3cr3t-api-key')
        self.assertTrue(ct.startswith('enc:'))
        self.assertNotIn('s3cr3t-api-key', ct)          # plaintext not present
        self.assertEqual(decrypt(ct), 's3cr3t-api-key')  # recovered

    def test_empty_values(self):
        from apps.settings_app.crypto import encrypt, decrypt
        self.assertEqual(encrypt(''), '')
        self.assertEqual(decrypt(''), '')

    def test_legacy_plaintext_passthrough(self):
        # A value without the enc: prefix is legacy plaintext — returned as-is.
        from apps.settings_app.crypto import decrypt
        self.assertEqual(decrypt('plain-legacy-value'), 'plain-legacy-value')

    def test_fail_closed_on_corrupt_ciphertext(self):
        # enc: prefix but undecryptable → MUST return '' (never the ciphertext).
        from apps.settings_app.crypto import decrypt
        self.assertEqual(decrypt('enc:###not-valid-base64###'), '')

    def test_fail_closed_on_wrong_key(self):
        from apps.settings_app.crypto import encrypt
        ct = encrypt('topsecret-bind-password')
        # Decrypting under a different key must fail closed (empty), not leak the blob.
        with override_settings(FIELD_ENCRYPTION_KEY='a-totally-different-key-XXXXXXXX'):
            from apps.settings_app.crypto import decrypt
            self.assertEqual(decrypt(ct), '')

    def test_secret_key_fallback_when_field_key_absent(self):
        # Backward compat: no FIELD_ENCRYPTION_KEY → derive from SECRET_KEY.
        with override_settings(FIELD_ENCRYPTION_KEY='', SECRET_KEY='legacy-secret-key'):
            from apps.settings_app.crypto import encrypt, decrypt
            ct = encrypt('legacy-value')
            self.assertEqual(decrypt(ct), 'legacy-value')


# ── Backup directory path confinement ──────────────────────────────────────
class BackupDirTests(SimpleTestCase):
    def _resolve_with_setting(self, value):
        from unittest.mock import patch
        from apps.settings_app import backup_service
        from apps.settings_app.cache import SettingsCache
        with patch.object(SettingsCache, 'get',
                          side_effect=lambda key, default=None:
                          value if key == 'backup.directory' else default):
            return backup_service.get_backup_dir()

    def test_relative_path_anchored_and_traversal_normalized(self):
        resolved = self._resolve_with_setting('sub/../backups')
        # '..' must be normalized away and the path anchored to an absolute dir.
        self.assertNotIn('..', str(resolved))
        self.assertTrue(resolved.is_absolute())
        self.assertEqual(resolved.name, 'backups')

    def test_blank_directory_uses_default_backups(self):
        resolved = self._resolve_with_setting('')
        self.assertEqual(resolved.name, 'backups')
        self.assertTrue(resolved.is_absolute())
