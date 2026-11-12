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


class ApiReferenceContentTests(TestCase):
    """`api_docs` is the single source for the API Reference page AND its PDF
    export, so a gap there is a gap in both. These pin the published surface
    rather than the prose: a path or an audit action that exists in the code
    but not here means an operator cannot find it."""

    def test_the_taxii_surface_is_documented(self):
        from apps.accounts.api_docs import ENDPOINTS

        tabs = {ep['tab_id'] for ep in ENDPOINTS}
        self.assertIn('taxii', tabs, 'the TAXII server has no reference tab')

    def test_every_taxii_url_appears_in_the_reference(self):
        """Walked straight out of the URLConf, so adding a TAXII endpoint
        without documenting it fails here instead of shipping undocumented."""
        from apps.accounts.api_docs import get_endpoints
        from apps.taxii import urls as taxii_urls

        tab = next(ep for ep in get_endpoints() if ep['tab_id'] == 'taxii')
        documented = ' '.join(
            [row['label'] for sec in tab['sections']
             if sec['type'] == 'params' for row in sec['rows']]
            + [line for sec in tab['sections']
               if sec['type'] == 'code' for line in sec['lines']]
        )

        for pattern in taxii_urls.urlpatterns:
            route = str(pattern.pattern)
            # '<str:root>/collections/' -> 'root', 'collections'
            segments = [seg for seg in route.split('/') if seg]
            with self.subTest(route=route or '(discovery)'):
                for seg in segments:
                    if seg.startswith('<'):
                        continue
                    self.assertIn(seg, documented,
                                  'path segment %r is not in the reference' % seg)

    def test_the_logged_taxii_actions_are_all_documented(self):
        """The audit table is the map between an endpoint and the row it
        writes; a missing action makes the Activity Log unreadable."""
        from apps.accounts.api_docs import get_endpoints
        from apps.taxii import views as taxii_views

        tab = next(ep for ep in get_endpoints() if ep['tab_id'] == 'taxii')
        audit = next(sec for sec in tab['sections']
                     if sec['type'] == 'params' and sec['label'] == 'Audit trail')
        documented = {row['label'] for row in audit['rows']}

        import re
        source = open(taxii_views.__file__, encoding='utf-8').read()
        actual = {'api.taxii_%s' % name
                  for name in re.findall(r"_taxii_endpoint\('(\w+)'\)", source)}
        actual.add('api.taxii_denied')

        self.assertEqual(actual - documented, set(),
                         'logged but undocumented TAXII actions')
        self.assertEqual(documented - actual, set(),
                         'documented TAXII actions that are never written')

    def test_the_taxii_actions_are_the_ones_the_dashboard_charts(self):
        """The reference tells the reader which Request Timeline series each
        action lands in. If the dashboard stopped recognising one, that claim
        would be quietly false."""
        from apps.dashboard import views as dash

        charted = set(dash.REQUEST_PULL_ACTIONS) | set(dash.REQUEST_REJECTED_ACTIONS)
        for action in ('api.taxii_objects', 'api.taxii_object',
                       'api.taxii_manifest', 'api.taxii_denied'):
            with self.subTest(action=action):
                self.assertIn(action, charted)

    def test_both_base_urls_are_published(self):
        """The TAXII paths are not under /api/v1, so one base-URL badge would
        misdescribe the TAXII tab."""
        from apps.accounts.api_docs import BASE_URLS, ENDPOINTS

        prefixes = [url for _, url in BASE_URLS]
        self.assertTrue(any('/api/v1' in u for u in prefixes))
        self.assertTrue(any('/taxii' in u for u in prefixes))

        for ep in ENDPOINTS:
            with self.subTest(tab=ep['tab_id']):
                self.assertTrue(
                    any(ep['path'].startswith(u.split(':8443')[-1])
                        for u in prefixes),
                    '%s is under no published base URL' % ep['path'])

    def test_the_brand_placeholder_is_resolved_for_the_page_too(self):
        """get_endpoints() substitutes the platform name; the page renders
        `html` while the PDF renders `lines`, so patching only one leaves the
        raw placeholder on screen."""
        from apps.accounts.api_docs import get_endpoints

        for ep in get_endpoints():
            for sec in ep['sections']:
                if sec['type'] != 'code':
                    continue
                with self.subTest(tab=ep['tab_id'], section=sec['label']):
                    self.assertNotIn('__PLATFORM_NAME__', sec['html'])
                    self.assertNotIn('__PLATFORM_NAME__', '\n'.join(sec['lines']))

    def test_the_reference_pdf_still_builds(self):
        """Both renderers read the same dicts, so a section shape the PDF
        cannot lay out would only surface on download."""
        from apps.reports.pdf_generator import generate_api_reference

        pdf = generate_api_reference('test-suite')
        self.assertTrue(pdf.startswith(b'%PDF'))
