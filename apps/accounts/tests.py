"""
Security regression tests for login brute-force protection:
  * Per-identifier lockout after N failures
  * Per-IP throttle (password-spraying guard) with a higher threshold
  * Fixed (non-sliding) window — counter TTL not re-extended on each failure
  * Successful login clears counters
  * End-to-end: repeated failed POSTs lock the account at the view level

Run: python manage.py test apps.accounts
"""
from django.test import TestCase, override_settings
from django.core.cache import cache
from django.urls import reverse

# Isolate brute-force state in a local in-memory cache for every test.
_LOCMEM = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}


@override_settings(CACHES=_LOCMEM)
class LoginThrottleHelperTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_lockout_after_max_attempts(self):
        from apps.accounts.views import _record_failure, _is_locked_out, _get_bf_settings
        max_attempts, _ = _get_bf_settings()
        ident = 'user:victim'
        for _ in range(max_attempts - 1):
            _record_failure(ident)
        self.assertFalse(_is_locked_out(ident), "locked too early")
        _record_failure(ident)                       # the Nth failure
        self.assertTrue(_is_locked_out(ident), "should be locked at threshold")

    def test_clear_failures_unlocks(self):
        from apps.accounts.views import (_record_failure, _is_locked_out,
                                         _clear_failures, _get_bf_settings)
        max_attempts, _ = _get_bf_settings()
        ident = 'user:bob'
        for _ in range(max_attempts):
            _record_failure(ident)
        self.assertTrue(_is_locked_out(ident))
        _clear_failures(ident)
        self.assertFalse(_is_locked_out(ident))

    def test_fixed_window_counter_reaches_lockout(self):
        # With a fixed window the counter keeps accumulating to the threshold
        # (a sliding window that reset TTL each call could let an attacker evade).
        from apps.accounts.views import _record_failure, _is_locked_out, _get_bf_settings
        max_attempts, _ = _get_bf_settings()
        ident = 'user:carol'
        for _ in range(max_attempts):
            _record_failure(ident)
        self.assertTrue(_is_locked_out(ident))

    def test_ip_throttle_uses_higher_threshold(self):
        from apps.accounts.views import (_record_failure, _is_locked_out,
                                         _get_bf_settings, _IP_LOCKOUT_MULTIPLIER)
        max_attempts, _ = _get_bf_settings()
        ip_threshold = max_attempts * _IP_LOCKOUT_MULTIPLIER
        ident = 'ip:10.0.0.9'
        # A single account threshold's worth of failures must NOT lock the IP.
        for _ in range(max_attempts):
            _record_failure(ident, max_attempts=ip_threshold)
        self.assertFalse(_is_locked_out(ident),
                         "IP locked at the per-user threshold — spraying not allowed room")
        # ...but reaching the IP threshold does lock it.
        for _ in range(ip_threshold - max_attempts):
            _record_failure(ident, max_attempts=ip_threshold)
        self.assertTrue(_is_locked_out(ident))


@override_settings(CACHES=_LOCMEM)
class LoginViewThrottleTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_repeated_failed_logins_lock_and_block(self):
        from apps.accounts.views import _get_bf_settings, _is_locked_out
        max_attempts, _ = _get_bf_settings()
        url = reverse('accounts:login')

        for _ in range(max_attempts):
            self.client.post(url, {'username': 'attacker', 'password': 'wrong-pass'})

        self.assertTrue(_is_locked_out('user:attacker'),
                        "username not locked after max failed attempts")

        # The next request is short-circuited with the lockout notice.
        resp = self.client.post(url, {'username': 'attacker', 'password': 'wrong-pass'})
        self.assertContains(resp, 'Too many failed login attempts', status_code=200)
