"""Dashboard timeline tests.

Covers the two side-by-side timeline widgets: the shared bucketing helper, the
Request Timeline series grouping, the "Last 24 hours / Hourly" defaults, and
the template wiring that the Python layer cannot see.

Rendering is driven through RequestFactory rather than self.client: under
Python 3.14 the test client's `template_rendered` instrumentation trips a
Django 4.2 `BaseContext.__copy__` bug, which has nothing to do with the views
under test.
"""

import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.dashboard import views as dash
from apps.settings_app.models import ActivityLog
from apps.urllist.models import URLEntry


def _log(action, when=None):
    """Write an activity-log row, optionally backdated.

    `timestamp` is auto_now_add, so it can only be moved with a queryset
    update after the insert.
    """
    row = ActivityLog.objects.create(action=action, target_model='', target_id='')
    if when is not None:
        ActivityLog.objects.filter(pk=row.pk).update(timestamp=when)
    return row


class DefaultWindowTests(TestCase):
    """Both widgets open on the last 24 hours bucketed hourly."""

    def test_module_defaults_are_24h_hourly(self):
        self.assertEqual(dash._TIMELINE_DEFAULT_DAYS, 1)
        self.assertEqual(dash._TIMELINE_DEFAULT_BUCKET, 'hour')

    def test_blacklist_timeline_defaults_to_24_hourly_points(self):
        t = dash._timeline(timezone.now())
        self.assertEqual(t['bucket'], 'hour')
        self.assertEqual(t['days'], 1)
        self.assertEqual(len(t['labels']), 24)

    def test_request_timeline_defaults_to_24_hourly_points(self):
        t = dash._request_timeline(timezone.now())
        self.assertEqual(t['bucket'], 'hour')
        self.assertEqual(t['days'], 1)
        self.assertEqual(len(t['labels']), 24)

    def test_both_api_endpoints_default_to_24h_hourly(self):
        """A request with no query string must land on the same window the
        widget opens with, so the first user interaction is not a jump."""
        from django.test import RequestFactory

        rf = RequestFactory(SERVER_NAME='localhost')
        for name in ('days', 'bucket', 'minutes'):
            self.assertNotIn(name, rf.get('/').GET)
        days, bucket, minutes, mode = dash._timeline_params(rf.get('/'))
        self.assertEqual((days, bucket, minutes, mode), (1, 'hour', 60, 'activity'))

    def test_unusable_params_fall_back_instead_of_raising(self):
        t = dash._request_timeline(timezone.now(), days='abc', bucket='weekly',
                                   minutes=None)
        self.assertEqual(t['bucket'], 'hour')
        self.assertEqual(t['days'], 1)


class BucketPlanTests(TestCase):
    """The shared helper must bucket any datetime column, not just added_at."""

    def test_every_granularity_yields_aligned_series(self):
        now = timezone.now()
        for bucket in ('minute', 'hour', 'day', 'month'):
            with self.subTest(bucket=bucket):
                plan = dash._bucket_plan(now, 30, bucket, 60, 'timestamp')
                counts = plan.counts(ActivityLog.objects.all())
                self.assertEqual(len(counts), len(plan.labels))
                self.assertEqual(len(plan.labels), len(plan.periods))

    def test_window_is_clamped_to_the_documented_maximums(self):
        now = timezone.now()
        hourly = dash._bucket_plan(now, 9999, 'hour', 60, 'timestamp')
        self.assertEqual(len(hourly.periods), dash._TIMELINE_MAX_HOURLY_HOURS)
        minutely = dash._bucket_plan(now, 1, 'minute', 9999, 'timestamp')
        self.assertEqual(len(minutely.periods), dash._TIMELINE_MAX_MINUTELY_MINUTES)
        daily = dash._bucket_plan(now, 9999, 'day', 60, 'timestamp')
        self.assertEqual(len(daily.periods), dash._TIMELINE_MAX_DAYS)

    def test_empty_buckets_are_zero_not_missing(self):
        """A line chart with gaps would imply "no data" where the truth is
        "no requests in that hour"."""
        plan = dash._bucket_plan(timezone.now(), 1, 'hour', 60, 'timestamp')
        counts = plan.counts(ActivityLog.objects.none())
        self.assertEqual(counts, [0] * 24)


class RequestTimelineSeriesTests(TestCase):
    """Each api.* action must land in exactly one series."""

    def setUp(self):
        ActivityLog.objects.all().delete()

    def _series(self):
        return dash._request_timeline(timezone.now())

    def test_feed_pulls_are_counted_as_pulls(self):
        for action in dash.REQUEST_PULL_ACTIONS:
            with self.subTest(action=action):
                ActivityLog.objects.all().delete()
                _log(action)
                t = self._series()
                self.assertEqual(sum(t['pull']), 1)
                self.assertEqual(sum(t['report']) + sum(t['rejected']) + sum(t['other']), 0)

    def test_reports_are_counted_as_reports(self):
        for action in dash.REQUEST_REPORT_ACTIONS:
            with self.subTest(action=action):
                ActivityLog.objects.all().delete()
                _log(action)
                t = self._series()
                self.assertEqual(sum(t['report']), 1)
                self.assertEqual(sum(t['pull']) + sum(t['rejected']) + sum(t['other']), 0)

    def test_throttled_calls_are_counted_as_rejected(self):
        _log('api.rate_limit')
        t = self._series()
        self.assertEqual(sum(t['rejected']), 1)
        self.assertEqual(sum(t['pull']) + sum(t['report']) + sum(t['other']), 0)

    def test_remaining_api_actions_land_in_other(self):
        """`other` is the remainder, so a known-but-ungrouped action and an
        api.* action added in future both stay visible in the totals rather
        than disappearing from the chart."""
        for action in ('api.status', 'api.report.skipped', 'api.something_new'):
            with self.subTest(action=action):
                ActivityLog.objects.all().delete()
                _log(action)
                t = self._series()
                self.assertEqual(sum(t['other']), 1)
                self.assertEqual(sum(t['pull']) + sum(t['report']) + sum(t['rejected']), 0)

    def test_non_api_actions_are_excluded_entirely(self):
        for action in ('page.dashboard', 'auth.login.success',
                       'threat_intel.vt_auto_check', 'urllist.add',
                       'taxii.collection_add'):
            _log(action)
        t = self._series()
        self.assertEqual(
            sum(t['pull']) + sum(t['report']) + sum(t['rejected']) + sum(t['other']), 0,
            'the Request Timeline must only count incoming API traffic',
        )

    def test_series_account_for_every_api_row_in_the_window(self):
        """The four series together are the complete api.* total — nothing
        counted twice, nothing dropped."""
        actions = (dash.REQUEST_PULL_ACTIONS + dash.REQUEST_REPORT_ACTIONS
                   + dash.REQUEST_REJECTED_ACTIONS + ['api.status', 'api.report.skipped'])
        for action in actions:
            _log(action)
            _log(action)
        t = self._series()
        self.assertEqual(
            sum(t['pull']) + sum(t['report']) + sum(t['rejected']) + sum(t['other']),
            ActivityLog.objects.filter(action__startswith='api.').count(),
        )

    def test_other_is_never_negative(self):
        for action in ('api.blacklist', 'api.report', 'api.rate_limit', 'api.status'):
            _log(action)
        t = dash._request_timeline(timezone.now())
        self.assertTrue(all(v >= 0 for v in t['other']))

    def test_rows_older_than_the_window_are_excluded(self):
        from datetime import timedelta

        _log('api.blacklist', when=timezone.now() - timedelta(days=5))
        t = dash._request_timeline(timezone.now())      # 24h / hourly
        self.assertEqual(sum(t['pull']), 0)
        wide = dash._request_timeline(timezone.now(), days=30, bucket='day')
        self.assertEqual(sum(wide['pull']), 1)

    def test_every_series_the_template_draws_is_in_the_payload(self):
        t = self._series()
        for field in ('labels', 'pull', 'report', 'rejected', 'other',
                      'days', 'minutes', 'bucket'):
            self.assertIn(field, t)
        for field in ('pull', 'report', 'rejected', 'other'):
            self.assertEqual(len(t[field]), len(t['labels']))

    def test_the_three_groups_do_not_overlap(self):
        groups = [set(dash.REQUEST_PULL_ACTIONS), set(dash.REQUEST_REPORT_ACTIONS),
                  set(dash.REQUEST_REJECTED_ACTIONS)]
        self.assertEqual(sum(len(g) for g in groups), len(set().union(*groups)))

    def test_every_grouped_action_is_an_api_action(self):
        """A group entry that does not start with `api.` would be filtered out
        before it could ever be counted."""
        for action in (dash.REQUEST_PULL_ACTIONS + dash.REQUEST_REPORT_ACTIONS
                       + dash.REQUEST_REJECTED_ACTIONS):
            with self.subTest(action=action):
                self.assertTrue(action.startswith('api.'))


class BlacklistTimelineUnchangedTests(TestCase):
    """The additions timeline kept its shape through the refactor."""

    def test_payload_still_carries_the_three_list_series(self):
        t = dash._timeline(timezone.now(), days=30, bucket='day')
        for field in ('labels', 'ip', 'hash', 'url', 'days', 'minutes', 'bucket'):
            self.assertIn(field, t)
        for field in ('ip', 'hash', 'url'):
            self.assertEqual(len(t[field]), len(t['labels']))

    def test_blacklist_additions_are_counted(self):
        from apps.blacklist.models import BlacklistEntry, BlacklistGroup

        group, _ = BlacklistGroup.objects.get_or_create(name='24h')
        BlacklistEntry.objects.create(ip_address='203.0.113.7', group=group,
                                      cidr='203.0.113.7/32')
        t = dash._timeline(timezone.now(), mode='new')
        self.assertEqual(sum(t['ip']), 1)


class TimelineWiringTests(TestCase):
    """Template and URL wiring the Python tests above cannot reach."""

    TEMPLATE = 'templates/dashboard/timeline.html'

    def _template(self):
        from pathlib import Path

        from django.conf import settings as dj_settings

        for d in dj_settings.TEMPLATES[0].get('DIRS', []):
            p = Path(d) / 'dashboard' / 'timeline.html'
            if p.exists():
                return p.read_text(encoding='utf-8')
        self.fail('dashboard/timeline.html not found in any template dir')

    def test_request_timeline_endpoint_is_routed(self):
        self.assertEqual(reverse('dashboard:request_timeline_api'),
                         '/dashboard/api/request-timeline/')

    def test_template_points_each_card_at_its_own_endpoint(self):
        text = self._template()
        self.assertIn('dashboard:timeline_api', text)
        self.assertIn('dashboard:request_timeline_api', text)

    def test_both_charts_have_a_canvas_and_a_first_paint_payload(self):
        text = self._template()
        for element_id in ('ch-timeline', 'ch-requests', 'd-timeline', 'd-requests'):
            with self.subTest(id=element_id):
                self.assertIn(element_id, text)
        self.assertIn('timeline_init|json_script:"d-timeline"', text)
        self.assertIn('request_timeline_init|json_script:"d-requests"', text)

    def test_the_two_cards_sit_in_a_half_and_half_grid(self):
        text = self._template()
        self.assertIn('db-tl-grid', text)
        self.assertIn('grid-template-columns:repeat(2,minmax(0,1fr))', text)

    def test_markup_defaults_match_the_server_defaults(self):
        """The pre-JS markup must already show Last 24 hours / Hourly, or the
        first paint would disagree with the controls."""
        text = self._template()
        self.assertEqual(text.count('<option value="1" selected>Last 24 hours</option>'), 2)
        self.assertEqual(text.count('data-bucket="hour" class="active"'), 2)
        self.assertNotIn('<option value="60min" selected>', text)

    def test_every_script_tag_carries_the_csp_nonce(self):
        """security_middleware drops 'unsafe-inline' from script-src, so a bare
        <script> is refused by the browser and both charts stay blank.

        Template comments are stripped first — prose inside one that mentions a
        script tag is not markup.
        """
        text = re.sub(r'\{%\s*comment\s*%\}.*?\{%\s*endcomment\s*%\}', '',
                      self._template(), flags=re.S)
        offenders = [tag for tag in re.findall(r'<script\b[^>]*>', text, re.I)
                     if 'nonce=' not in tag.lower()]
        self.assertEqual(offenders, [], 'script tag without the nonce: %s' % offenders)

    def test_index_still_includes_the_timeline_section(self):
        from pathlib import Path

        from django.conf import settings as dj_settings

        for d in dj_settings.TEMPLATES[0].get('DIRS', []):
            p = Path(d) / 'dashboard' / 'index.html'
            if p.exists():
                self.assertIn("include 'dashboard/timeline.html'",
                              p.read_text(encoding='utf-8'))
                return
        self.fail('dashboard/index.html not found')


class DashboardRenderTests(TestCase):
    """The dashboard view must hand the template both payloads."""

    def setUp(self):
        from apps.accounts.models import Role, UserProfile

        role, _ = Role.objects.get_or_create(name='admin')
        self.admin = User(username='dash-admin', is_active=True)
        self.admin.set_unusable_password()
        self.admin.save()
        profile, _ = UserProfile.objects.get_or_create(user=self.admin)
        profile.role = role
        profile.save()

    def _render(self):
        from django.test import RequestFactory

        request = RequestFactory(SERVER_NAME='localhost').get('/dashboard/')
        request.user = User.objects.get(pk=self.admin.pk)
        return dash.index(request).content.decode()

    def test_both_canvases_are_rendered(self):
        html = self._render()
        self.assertIn('id="ch-timeline"', html)
        self.assertIn('id="ch-requests"', html)

    def test_both_first_paint_payloads_are_rendered(self):
        html = self._render()
        self.assertIn('id="d-timeline"', html)
        self.assertIn('id="d-requests"', html)

    def test_request_payload_is_valid_json_with_hourly_defaults(self):
        import json

        html = self._render()
        m = re.search(r'<script id="d-requests"[^>]*>(.*?)</script>', html, re.S)
        self.assertIsNotNone(m, 'request timeline payload missing from the page')
        data = json.loads(m.group(1))
        self.assertEqual(data['bucket'], 'hour')
        self.assertEqual(len(data['labels']), 24)
        self.assertEqual(len(data['pull']), 24)


class TaxiiTrafficTests(TestCase):
    """TAXII polls are incoming API requests and must appear on the Request
    Timeline.

    They did not, originally: the TAXII endpoints wrote only to the rotating
    file log, so a subscriber could poll all day while the chart stayed flat.
    These tests pin the grouping that fixed it.
    """

    def setUp(self):
        ActivityLog.objects.all().delete()

    def test_indicator_transferring_polls_count_as_feed_pulls(self):
        for action in ('api.taxii_objects', 'api.taxii_object', 'api.taxii_manifest'):
            with self.subTest(action=action):
                ActivityLog.objects.all().delete()
                _log(action)
                t = dash._request_timeline(timezone.now())
                self.assertEqual(sum(t['pull']), 1)
                self.assertEqual(sum(t['other']), 0)

    def test_refused_polls_count_as_rejected(self):
        """An expired subscriber token must be as visible as throttling, not
        buried in the grey `other` line."""
        _log('api.taxii_denied')
        t = dash._request_timeline(timezone.now())
        self.assertEqual(sum(t['rejected']), 1)
        self.assertEqual(sum(t['pull']) + sum(t['other']), 0)

    def test_metadata_browsing_counts_as_other(self):
        """Discovery and collection browsing happen once at setup; counting
        them as pulls would imply a feed is being consumed when it is not."""
        for action in ('api.taxii_discovery', 'api.taxii_api_root',
                       'api.taxii_collections', 'api.taxii_collection'):
            with self.subTest(action=action):
                ActivityLog.objects.all().delete()
                _log(action)
                t = dash._request_timeline(timezone.now())
                self.assertEqual(sum(t['other']), 1)
                self.assertEqual(sum(t['pull']), 0)

    def test_every_taxii_action_this_module_groups_is_one_the_views_emit(self):
        """Guards the coupling that caused the original bug: if an endpoint
        name changes in apps/taxii/views.py and this list is not updated, the
        TAXII traffic silently drops out of the Feed pulls line again.
        """
        from pathlib import Path

        import apps.taxii.views as taxii_views

        source = Path(taxii_views.__file__).read_text(encoding='utf-8')
        emitted = {'api.taxii_%s' % m
                   for m in re.findall(r"@_taxii_endpoint\('([a-z_]+)'\)", source)}
        self.assertTrue(emitted, 'no @_taxii_endpoint decorators found')
        emitted.add('api.taxii_denied')      # written by the decorator itself

        grouped = {a for a in (dash.REQUEST_PULL_ACTIONS
                               + dash.REQUEST_REPORT_ACTIONS
                               + dash.REQUEST_REJECTED_ACTIONS)
                   if a.startswith('api.taxii_')}
        self.assertEqual(
            grouped - emitted, set(),
            'grouped but never emitted by the TAXII views (dead entry)',
        )

    def test_taxii_rows_are_visible_to_the_activity_log_api_filter(self):
        """The Activity Log page selects API traffic with
        `action__startswith='api.'`; a TAXII action outside that prefix would
        be invisible there as well as on the chart."""
        import apps.taxii.views as taxii_views
        from pathlib import Path

        source = Path(taxii_views.__file__).read_text(encoding='utf-8')
        names = re.findall(r"@_taxii_endpoint\('([a-z_]+)'\)", source)
        for name in names:
            with self.subTest(endpoint=name):
                self.assertTrue(('api.taxii_%s' % name).startswith('api.'))

    def test_a_mixed_window_splits_taxii_and_v1_traffic_correctly(self):
        _log('api.urllist')          # /api/v1/ pull
        _log('api.taxii_objects')    # TAXII pull
        _log('api.url_report')       # report
        _log('api.rate_limit')       # rejected (throttle)
        _log('api.taxii_denied')     # rejected (auth)
        _log('api.status')           # other
        t = dash._request_timeline(timezone.now())
        self.assertEqual(sum(t['pull']), 2)
        self.assertEqual(sum(t['report']), 1)
        self.assertEqual(sum(t['rejected']), 2)
        self.assertEqual(sum(t['other']), 1)


class TimelineMeasureTests(TestCase):
    """The blacklist timeline's three measures.

    From the report that produced them: activating 1396 passive URLs moved
    nothing on the chart, because an entry table dates only `added_at` and
    activating does not change it. 'activity' fixes that by adding the changes
    the activity log recorded; 'new' keeps the original additions-only reading;
    'total' reports list size.
    """

    def setUp(self):
        from apps.blacklist.models import BlacklistEntry
        from apps.hashlist.models import HashEntry

        BlacklistEntry.objects.all().delete()
        HashEntry.objects.all().delete()
        URLEntry.objects.all().delete()
        ActivityLog.objects.all().delete()

    def _url(self, name, *, days_ago=0, active=True):
        e = URLEntry.objects.create(url_value=name, list_type='black',
                                    is_active=active)
        if days_ago:
            when = timezone.now() - timedelta(days=days_ago)
            URLEntry.objects.filter(pk=e.pk).update(added_at=when)
        return e

    def _event(self, action, detail=None, *, days_ago=0):
        row = ActivityLog.objects.create(action=action, target_model='',
                                         target_id='', detail=detail or {})
        if days_ago:
            ActivityLog.objects.filter(pk=row.pk).update(
                timestamp=timezone.now() - timedelta(days=days_ago))
        return row

    def _series(self, mode, feed='url', **kw):
        kw.setdefault('days', 7)
        kw.setdefault('bucket', 'day')
        return dash._timeline(timezone.now(), mode=mode, **kw)[feed]

    # ── defaults ──

    def test_activity_is_the_default_measure(self):
        self.assertEqual(dash._TIMELINE_DEFAULT_MODE, 'activity')
        self.assertEqual(dash._timeline(timezone.now())['mode'], 'activity')

    def test_an_unknown_measure_falls_back_to_the_default(self):
        self.assertEqual(dash._timeline(timezone.now(), mode='sideways')['mode'],
                         'activity')

    def test_all_three_measures_are_offered(self):
        self.assertEqual(set(dash._TIMELINE_MODES), {'activity', 'new', 'total'})

    # ── the reported bug ──

    def test_a_bulk_activation_shows_up_on_the_chart(self):
        """The exact case that was reported: entries added last week, switched
        from passive to active today."""
        for i in range(5):
            self._url('p%02d.example' % i, days_ago=7, active=False)
        self._event('urllist.bulk_activate', {'count': 5})

        activity = self._series('activity')
        self.assertEqual(activity[-1], 5, 'activation did not reach the chart')
        self.assertEqual(self._series('new')[-1], 0,
                         'activating is not adding; New must not move')

    def test_activation_is_counted_once_per_entry_touched(self):
        """A bulk row stands for `detail['count']` entries, not for one."""
        self._event('urllist.bulk_activate', {'count': 500})
        self._event('urllist.bulk_activate', {'count': 396})
        self.assertEqual(self._series('activity')[-1], 896)

    def test_a_single_entry_activation_counts_as_one(self):
        self._event('urllist.activate')
        self.assertEqual(self._series('activity')[-1], 1)

    def test_edits_count_as_activity(self):
        for _ in range(3):
            self._event('urllist.edit', {'reason': 'x'})
        self.assertEqual(self._series('activity')[-1], 3)
        self.assertEqual(self._series('new')[-1], 0)

    def test_a_repeat_report_counts_as_activity(self):
        """An existing entry whose hit count was bumped."""
        self._event('api.url_report', {'action': 'existing'})
        self.assertEqual(self._series('activity')[-1], 1)

    def test_a_report_that_created_the_entry_is_not_double_counted(self):
        """`added_at` already dates it, so the log row must not add a second
        count for the same event."""
        self._url('fresh.example')
        self._event('api.url_report', {'action': 'added'})
        self.assertEqual(self._series('activity')[-1], 1)
        self.assertEqual(self._series('new')[-1], 1)

    def test_each_list_gets_its_own_line(self):
        self._event('urllist.bulk_activate', {'count': 7})
        self._event('hashlist.bulk_activate', {'count': 3})
        self._event('blacklist.bulk_activate', {'count': 2})
        self.assertEqual(self._series('activity', 'url')[-1], 7)
        self.assertEqual(self._series('activity', 'hash')[-1], 3)
        self.assertEqual(self._series('activity', 'ip')[-1], 2)

    def test_removals_are_not_counted_as_activity(self):
        """Folding them in would make 100 adds plus 100 removals read as 200
        changes, hiding whether the list grew or shrank."""
        for action in ('urllist.bulk_deactivate', 'urllist.bulk_delete',
                       'urllist.deactivate', 'urllist.delete'):
            with self.subTest(action=action):
                ActivityLog.objects.all().delete()
                self._event(action, {'count': 9})
                self.assertEqual(self._series('activity')[-1], 0)

    def test_unrelated_log_actions_are_ignored(self):
        for action in ('page.dashboard', 'auth.login.success', 'settings.save',
                       'taxii.collection_add', 'api.taxii_objects'):
            self._event(action, {'count': 99})
        self.assertEqual(self._series('activity')[-1], 0)

    # ── 'new' keeps the original reading ──

    def test_new_counts_additions_in_the_bucket_only(self):
        for i in range(5):
            self._url('old%02d.example' % i, days_ago=5)
        self._url('today.example')
        s = self._series('new')
        self.assertEqual(s[-1], 1)
        self.assertEqual(sum(s), 6)

    def test_event_measures_report_history_regardless_of_current_state(self):
        """An entry added on Tuesday was added on Tuesday. Deactivating it
        later must not rewrite Tuesday — otherwise the past changes every time
        someone edits the list."""
        self._url('live.example', days_ago=2)
        self._url('dead.example', days_ago=2, active=False)
        for mode in ('activity', 'new'):
            with self.subTest(mode=mode):
                self.assertEqual(sum(self._series(mode)), 2)

    # ── 'total' reports state ──

    def test_total_counts_only_the_live_list(self):
        self._url('live.example', days_ago=2)
        self._url('dead.example', days_ago=2, active=False)
        self.assertEqual(self._series('total')[-1], 1)

    def test_total_excludes_expired_ip_entries(self):
        from apps.blacklist.models import BlacklistEntry, BlacklistGroup

        group, _ = BlacklistGroup.objects.get_or_create(name='24h')
        BlacklistEntry.objects.create(ip_address='203.0.113.1', group=group,
                                      cidr='203.0.113.1/32')
        BlacklistEntry.objects.create(
            ip_address='203.0.113.2', group=group, cidr='203.0.113.2/32',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertEqual(self._series('total', 'ip')[-1], 1)

    def test_total_includes_entries_added_before_the_window(self):
        for i in range(5):
            self._url('old%02d.example' % i, days_ago=30)
        t = dash._timeline(timezone.now(), mode='total')   # 24h / hourly
        self.assertEqual(t['url'], [5] * 24)

    def test_total_never_decreases(self):
        for i in range(4):
            self._url('g%02d.example' % i, days_ago=i + 1)
        t = dash._timeline(timezone.now(), days=30, bucket='day', mode='total')
        for feed in ('ip', 'hash', 'url'):
            with self.subTest(feed=feed):
                s = t[feed]
                self.assertTrue(all(s[i] <= s[i + 1] for i in range(len(s) - 1)),
                                f'{feed} total went down: {s}')

    def test_the_last_total_bucket_equals_the_live_list_size(self):
        for i in range(3):
            self._url('a%02d.example' % i, days_ago=40)
        self._url('b.example', days_ago=2)
        self._url('c.example')
        now = timezone.now()
        live = dash._timeline_sources(now, live_only=True)['url'].count()
        self.assertEqual(live, 5)
        for bucket, days in (('minute', 1), ('hour', 1), ('day', 30), ('month', 365)):
            with self.subTest(bucket=bucket):
                t = dash._timeline(now, days=days, bucket=bucket, mode='total')
                self.assertEqual(t['url'][-1], live)

    def test_stat_cards_and_the_total_measure_share_their_querysets(self):
        from apps.blacklist.models import BlacklistEntry, BlacklistGroup

        group, _ = BlacklistGroup.objects.get_or_create(name='24h')
        BlacklistEntry.objects.create(ip_address='198.51.100.9', group=group,
                                      cidr='198.51.100.9/32')
        BlacklistEntry.objects.create(ip_address='198.51.100.10', group=group,
                                      cidr='198.51.100.10/32', is_active=False)
        self._url('card.example')
        self._url('card-off.example', active=False)

        now = timezone.now()
        src = dash._timeline_sources(now, live_only=True)
        t = dash._timeline(now, mode='total')
        for feed in ('ip', 'hash', 'url'):
            with self.subTest(feed=feed):
                self.assertEqual(t[feed][-1], src[feed].count())

    # ── relationships between the measures ──

    def test_activity_is_new_plus_the_logged_events(self):
        """The two measures must describe the same data, or one is lying."""
        self._url('x.example', days_ago=1)
        self._url('y.example')
        self._event('urllist.bulk_activate', {'count': 40})
        self._event('urllist.edit', days_ago=3)

        now = timezone.now()
        activity = dash._timeline(now, days=7, bucket='day', mode='activity')
        new = dash._timeline(now, days=7, bucket='day', mode='new')
        events = dash._activity_events(now, 7, 'day', 60)
        for feed in ('ip', 'hash', 'url'):
            with self.subTest(feed=feed):
                self.assertEqual(
                    activity[feed],
                    [a + b for a, b in zip(new[feed], events[feed])],
                )

    def test_activity_is_never_below_new(self):
        self._url('z.example')
        self._event('urllist.bulk_activate', {'count': 3})
        now = timezone.now()
        a = dash._timeline(now, days=7, bucket='day', mode='activity')
        n = dash._timeline(now, days=7, bucket='day', mode='new')
        for feed in ('ip', 'hash', 'url'):
            self.assertTrue(all(x >= y for x, y in zip(a[feed], n[feed])))

    def test_events_outside_the_window_are_excluded(self):
        self._event('urllist.bulk_activate', {'count': 50}, days_ago=10)
        self.assertEqual(self._series('activity', days=7)[-1], 0)
        self.assertEqual(sum(self._series('activity', days=7)), 0)
        self.assertEqual(sum(self._series('activity', days=30)), 50)

    def test_every_series_is_aligned_with_labels_in_every_measure(self):
        for mode in dash._TIMELINE_MODES:
            for bucket in ('minute', 'hour', 'day', 'month'):
                with self.subTest(mode=mode, bucket=bucket):
                    t = dash._timeline(timezone.now(), days=30, bucket=bucket,
                                       mode=mode)
                    for feed in ('ip', 'hash', 'url'):
                        self.assertEqual(len(t[feed]), len(t['labels']))

    def test_the_window_filter_and_its_complement_do_not_overlap(self):
        """`cumulative()` adds the before-window count to the in-window
        buckets, so the two filters must partition the rows exactly."""
        for i in range(6):
            self._url('p%02d.example' % i, days_ago=i * 3)
        plan = dash._bucket_plan(timezone.now(), 10, 'day', 60, 'added_at')
        qs = URLEntry.objects.filter(list_type='black')
        inside = qs.filter(**plan.flt).count()
        before = qs.filter(**plan.pre_flt).count()
        self.assertEqual(inside + before, qs.count())
        self.assertEqual(
            qs.filter(**plan.flt).filter(**plan.pre_flt).count(), 0,
            'a row counted in both halves would be double counted',
        )

    # ── event weights ──

    def test_a_bulk_row_with_no_count_still_counts_as_one_change(self):
        """It definitely represents at least one entry; dropping it would
        under-report."""
        self._event('urllist.bulk_activate', {})
        self.assertEqual(self._series('activity')[-1], 1)

    def test_an_unreadable_count_counts_as_one(self):
        self._event('urllist.bulk_activate', {'count': 'lots'})
        self.assertEqual(self._series('activity')[-1], 1)

    def test_a_bulk_row_that_matched_nothing_counts_as_nothing(self):
        self._event('urllist.bulk_activate', {'count': 0})
        self.assertEqual(self._series('activity')[-1], 0)

    def test_every_grouped_action_names_a_real_series(self):
        for action, (feed, _key) in dash._ACTIVITY_EVENTS.items():
            with self.subTest(action=action):
                self.assertIn(feed, dash._TIMELINE_FEEDS)
        for action, (feed, values) in dash._ACTIVITY_REPEAT_REPORTS.items():
            with self.subTest(action=action):
                self.assertIn(feed, dash._TIMELINE_FEEDS)
                self.assertTrue(values, 'a repeat report needs its marker values')

    def test_no_action_is_counted_as_both_an_addition_and_an_event(self):
        """An `*.add` or import row would double the additions `added_at`
        already provides."""
        for action in list(dash._ACTIVITY_EVENTS) + list(dash._ACTIVITY_REPEAT_REPORTS):
            with self.subTest(action=action):
                self.assertFalse(
                    action.endswith('.add') or action.endswith('.bulk_add')
                    or action.endswith('.import_csv'),
                    f'{action} duplicates what added_at already counts',
                )

    def test_mode_reaches_the_pdf_caption(self):
        """A chart captioned only with its window would be ambiguous between
        three very different measures."""
        from apps.reports.pdf_generator import _timeline_window_label

        self.assertEqual(_timeline_window_label(1, 'hour', 60, 'activity'),
                         'Last 24 hours · Hourly · Activity')
        self.assertEqual(_timeline_window_label(30, 'day', 60, 'new'),
                         'Last 30 days · Daily · New only')
        self.assertEqual(_timeline_window_label(30, 'day', 60, 'total'),
                         'Last 30 days · Daily · Total')
        # Callers that pass no mode must still get a usable label.
        self.assertEqual(_timeline_window_label(30, 'day'), 'Last 30 days · Daily')


class TimelineMeasureMarkupTests(TestCase):
    """The measure control has to exist in the markup and agree with the
    server default before any JavaScript runs."""

    def _template(self):
        from pathlib import Path

        from django.conf import settings as dj_settings

        for d in dj_settings.TEMPLATES[0].get('DIRS', []):
            p = Path(d) / 'dashboard' / 'timeline.html'
            if p.exists():
                return p.read_text(encoding='utf-8')
        self.fail('dashboard/timeline.html not found')

    def test_the_blacklist_card_offers_every_measure(self):
        text = self._template()
        self.assertIn('id="tl-mode"', text)
        self.assertIn('<option value="activity" selected>Activity</option>', text)
        self.assertIn('<option value="new">New only</option>', text)
        self.assertIn('<option value="total">Total</option>', text)

    def test_the_markup_default_matches_the_server_default(self):
        text = self._template()
        self.assertIn('value="%s" selected' % dash._TIMELINE_DEFAULT_MODE, text)
        self.assertIn("curMode = '%s'" % dash._TIMELINE_DEFAULT_MODE, text)

    def test_the_request_card_has_no_measure_select(self):
        """Cumulative request counts would be meaningless — the question is
        how much traffic arrived, not how much has ever arrived."""
        self.assertNotIn('id="rq-mode"', self._template())

    def test_only_the_blacklist_chart_is_wired_to_a_measure_control(self):
        self.assertEqual(self._template().count("modeId: 'tl-mode'"), 1)


class TimelineAlignmentTests(TestCase):
    """The two timeline cards must present the same frame whatever is in them,
    so their plot areas read as a single row.

    Three things used to move one chart off the other, and each has its own
    test here because CSS cannot be asserted at runtime:
      * the headers carry a different number of controls, so a header left
        free to wrap wrapped in one card and not in the other;
      * Chart.js drew its legend inside the canvas, so 4 long labels left a
        shorter plot than 3 short ones;
      * a 4-digit y-axis tick is wider than a 1-digit one, pushing one plot
        area right of its neighbour.
    """

    def _template(self):
        from pathlib import Path

        from django.conf import settings as dj_settings

        for d in dj_settings.TEMPLATES[0].get('DIRS', []):
            p = Path(d) / 'dashboard' / 'timeline.html'
            if p.exists():
                return p.read_text(encoding='utf-8')
        self.fail('dashboard/timeline.html not found')

    # ── header ──

    def test_both_headers_wrap_their_title_the_same_way(self):
        """Identical structure, so a differing control count cannot make one
        header taller than the other."""
        self.assertEqual(self._template().count('class="db-tl-titlerow"'), 2)

    def test_the_header_is_a_single_row_that_cannot_wrap(self):
        """Title left, controls right, on one line. Wrapping is what made the
        two headers different heights, so it is turned off rather than merely
        avoided: a header that can wrap will wrap at some width."""
        text = self._template()
        self.assertRegex(
            text, r'\.db-tl-head \{ display:flex; flex-direction:row;')
        head = re.search(r'\.db-tl-head \{(.*?)\}', text, re.S).group(1)
        self.assertIn('flex-wrap:nowrap', head)
        self.assertIn('justify-content:space-between', head)
        self.assertRegex(head, r'min-height:\d+px')

    def test_the_controls_sit_hard_right_and_do_not_shrink(self):
        text = self._template()
        controls = re.search(r'\.db-tl-controls \{(.*?)\}', text, re.S).group(1)
        self.assertIn('margin-left:auto', controls)
        self.assertIn('flex-wrap:nowrap', controls)
        self.assertIn('flex-shrink:0', controls)

    def test_the_title_is_the_only_part_of_the_header_that_gives_way(self):
        """Something has to absorb a narrow card. If it were the controls they
        would wrap and break the alignment, so the title clips instead."""
        text = self._template()
        titlerow = re.search(r'\.db-tl-titlerow \{(.*?)\}', text, re.S).group(1)
        self.assertIn('min-width:0', titlerow)
        title = re.search(
            r'\.db-tl-titlerow \.card-title \{(.*?)\}', text, re.S).group(1)
        self.assertIn('overflow:hidden', title)
        self.assertIn('text-overflow:ellipsis', title)
        # ...but not the tooltip, which would clip to nothing.
        self.assertIn('.db-tl-titlerow .info-tip { flex-shrink:0; }', text)

    def test_the_header_does_not_clip_the_tooltip(self):
        """The info-tip renders its panel as an absolutely positioned
        pseudo-element, so an overflow:hidden on the row around it would crop
        the tooltip to the width of the title. The ellipsis belongs on the
        title text, which has no tooltip of its own."""
        titlerow = re.search(r'\.db-tl-titlerow \{(.*?)\}',
                             self._template(), re.S).group(1)
        self.assertNotIn('overflow', titlerow)

    def test_the_grid_gives_up_the_second_column_before_the_title_clips(self):
        """The single row needs more width than the stacked header did, so the
        breakpoint has to move with it — otherwise the ellipsis above, which is
        only a safety net, becomes the normal appearance."""
        text = self._template()
        breakpoints = [int(v) for v in re.findall(
            r'@media \(max-width:(\d+)px\) \{ \.db-tl-grid', text)]
        self.assertEqual(len(breakpoints), 1, 'expected one grid breakpoint')
        self.assertGreaterEqual(breakpoints[0], 1360)

    # ── plot box ──

    def test_the_plot_box_has_a_fixed_height(self):
        text = self._template()
        self.assertIn('.db-tl-canvas { position:relative; height:240px; }', text)
        self.assertIn('maintainAspectRatio: false', text)

    def test_the_canvas_height_is_declared_once_per_breakpoint(self):
        """Two competing heights would silently make the cards differ."""
        text = self._template()
        self.assertEqual(text.count('.db-tl-canvas { position:relative;'), 1)

    # ── legend ──

    def test_the_in_canvas_legend_is_disabled(self):
        """Chart.js takes the legend's room out of the plot area."""
        self.assertIn('legend: { display: false }', self._template())

    def test_the_legend_is_centred_under_the_plot(self):
        """Centring is horizontal only: the row keeps its fixed height, so it
        cannot reintroduce a difference between the two cards."""
        legend = re.search(r'\.db-tl-legend \{(.*?)\}',
                           self._template(), re.S).group(1)
        self.assertIn('justify-content:center', legend)
        self.assertIn('height:20px', legend)

    def test_both_cards_render_an_html_legend_of_fixed_height(self):
        text = self._template()
        self.assertEqual(text.count('class="db-tl-legend"'), 2)
        self.assertIn('.db-tl-legend {', text)
        self.assertRegex(text, r'\.db-tl-legend \{[^}]*height:20px')

    def test_the_html_legend_matches_the_chart_colours(self):
        """The legend is now static markup while the lines are coloured in JS
        — two sources of truth that must not drift. A legend swatch that no
        longer matches its line is worse than no legend at all.
        """
        text = self._template()

        js = {}
        for m in re.finditer(r'\{[^{}]*?field:[^{}]*?\}', text):
            block = m.group(0)
            label = re.search(r"label:\s*'([^']+)'", block)
            color = re.search(r"color:\s*'([^']+)'", block)
            css_var = re.search(r"cssVar:\s*'([^']+)'", block)
            if not (label and color):
                continue
            js[label.group(1)] = ('var(%s)' % css_var.group(1)) if css_var \
                else color.group(1)

        markup = {label: swatch for swatch, label in
                  re.findall(r'<i style="background:([^"]+);"></i>([^<]+)</span>', text)}

        self.assertTrue(js, 'no chart series found in the script')
        self.assertEqual(
            markup, js,
            'legend swatches and line colours disagree:\n'
            '  markup: %r\n  script: %r' % (markup, js),
        )

    def test_every_series_appears_in_its_card_legend(self):
        text = self._template()
        for label in ('IP', 'Hash', 'URL',
                      'Feed pulls', 'Reports', 'Rejected', 'Other'):
            with self.subTest(label=label):
                self.assertIn('</i>%s</span>' % label, text)

    # ── axis ──

    def test_the_y_axis_width_is_pinned(self):
        text = self._template()
        self.assertIn('var Y_AXIS_WIDTH =', text)
        self.assertIn('afterFit: function (scale) { scale.width = Y_AXIS_WIDTH; }',
                      text)

    def test_both_charts_use_the_same_pinned_axis_width(self):
        """One shared constant, used by the single render path both cards go
        through — a per-card width would defeat the point."""
        text = self._template()
        self.assertEqual(text.count('var Y_AXIS_WIDTH ='), 1)
        self.assertEqual(text.count('scale.width = Y_AXIS_WIDTH'), 1)

    def test_the_layout_padding_is_fixed_rather_than_derived(self):
        self.assertIn('layout: { padding: {', self._template())

    # ── rendered markup ──

    def test_the_rendered_cards_have_identical_skeletons(self):
        from apps.accounts.models import Role, UserProfile
        from django.test import RequestFactory

        role, _ = Role.objects.get_or_create(name='admin')
        admin = User(username='align-admin', is_active=True)
        admin.set_unusable_password()
        admin.save()
        profile, _ = UserProfile.objects.get_or_create(user=admin)
        profile.role = role
        profile.save()

        request = RequestFactory(SERVER_NAME='localhost').get('/dashboard/')
        request.user = User.objects.get(pk=admin.pk)
        html = dash.index(request).content.decode()

        grid = re.search(r'<div class="db-tl-grid">.*?\n</div>', html, re.S)
        self.assertIsNotNone(grid, 'timeline grid missing from the page')
        cards = re.findall(r'<div class="card">(.*?)\n  </div>', grid.group(0), re.S)
        self.assertEqual(len(cards), 2)

        # Only the containers that position the chart. The leaf counts are
        # meant to differ — the blacklist card has an extra select (the
        # measure) and the request card an extra legend item — and that is
        # exactly what the fixed heights absorb.
        CONTAINERS = ('card-header db-tl-head', 'db-tl-titlerow',
                      'db-tl-controls', 'card-body', 'db-tl-canvas',
                      'db-tl-legend')

        def skeleton(card):
            return [c for c in re.findall(r'class="([a-z0-9- ]+)"', card)
                    if c in CONTAINERS]

        self.assertEqual(skeleton(cards[0]), skeleton(cards[1]),
                         'the two cards no longer share a structure')
        self.assertEqual(skeleton(cards[0]), list(CONTAINERS),
                         'a positioning container was dropped or reordered')


class LegendToggleTests(TestCase):
    """Moving the legend out of the canvas cost Chart.js's click-to-hide, so
    the HTML legend has to provide it instead — with four overlapping lines on
    the request chart, being able to mute one is not a nicety."""

    def _template(self):
        from pathlib import Path

        from django.conf import settings as dj_settings

        for d in dj_settings.TEMPLATES[0].get('DIRS', []):
            p = Path(d) / 'dashboard' / 'timeline.html'
            if p.exists():
                return p.read_text(encoding='utf-8')
        self.fail('dashboard/timeline.html not found')

    def test_both_legends_are_addressable(self):
        text = self._template()
        self.assertIn('id="tl-legend"', text)
        self.assertIn('id="rq-legend"', text)
        self.assertIn("legendId: 'tl-legend'", text)
        self.assertIn("legendId: 'rq-legend'", text)

    def test_every_legend_entry_names_its_series_index(self):
        """The click handler maps data-s straight onto the dataset order, so a
        missing or duplicated index would toggle the wrong line."""
        text = self._template()
        for container, count in (('tl-legend', 3), ('rq-legend', 4)):
            with self.subTest(legend=container):
                block = re.search(
                    r'id="%s">(.*?)</div>' % container, text, re.S).group(1)
                indexes = [int(v) for v in re.findall(r'data-s="(\d+)"', block)]
                self.assertEqual(indexes, list(range(count)))

    def test_the_indexes_line_up_with_the_declared_series_order(self):
        text = self._template()
        for legend_id, canvas in (('tl-legend', 'ch-timeline'),
                                  ('rq-legend', 'ch-requests')):
            with self.subTest(legend=legend_id):
                block = re.search(
                    r'id="%s">(.*?)</div>' % legend_id, text, re.S).group(1)
                labels = re.findall(r'</i>([^<]+)</span>', block)

                cfg = re.search(
                    r"canvasId: '%s'.*?series: \[(.*?)\n    \]" % canvas,
                    text, re.S)
                self.assertIsNotNone(cfg, 'series block not found for ' + canvas)
                js_labels = re.findall(r"label:\s*'([^']+)'", cfg.group(1))
                self.assertEqual(labels, js_labels)

    def test_a_hidden_series_is_applied_and_survives_a_redraw(self):
        text = self._template()
        self.assertIn('hidden: !!hidden[i]', text)
        # Declared outside render(), or a refresh would silently un-hide.
        self.assertIn('var hidden = {};', text)
        self.assertRegex(text, r'function render\(data\)')
        self.assertLess(text.index('var hidden = {};'),
                        text.index('function render(data)'),
                        'hidden state must outlive a single render')

    def test_a_hidden_series_does_not_hold_up_the_y_axis(self):
        self.assertIn('if (hidden[i]) return;', self._template())

    def test_the_toggle_has_a_visible_off_state(self):
        text = self._template()
        self.assertIn("classList.toggle('is-off'", text)
        self.assertIn('.db-tl-leg.is-off', text)
        self.assertIn('.db-tl-leg[data-s] { cursor:pointer', text)


class ApiEndpointsCardTaxiiTests(TestCase):
    """The API Endpoints card at the foot of the dashboard is where an
    operator looks for "what can a client call?". It listed only /api/v1,
    so the TAXII server was invisible there."""

    def _render(self, role_name='admin', username=None):
        from apps.accounts.models import Role, UserProfile
        from django.test import RequestFactory

        username = username or ('card-%s' % role_name)
        role, _ = Role.objects.get_or_create(name=role_name)
        user = User(username=username, is_active=True)
        user.set_unusable_password()
        user.save()
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = role
        profile.save()

        request = RequestFactory(SERVER_NAME='localhost').get('/dashboard/')
        request.user = User.objects.get(pk=user.pk)
        return dash.index(request).content.decode()

    def _set_taxii(self, enabled):
        from apps.settings_app.cache import SettingsCache
        from apps.settings_app.models import Setting

        Setting.objects.update_or_create(
            key='taxii.enabled',
            defaults={'value': 'true' if enabled else 'false',
                      'value_type': 'bool', 'category': 'taxii',
                      'description': 'taxii.enabled', 'is_secret': False},
        )
        SettingsCache.invalidate('taxii.enabled')

    # ── the status helper ──

    def test_the_status_reports_the_setting_and_the_active_collections(self):
        from apps.taxii.models import TaxiiCollection

        TaxiiCollection.objects.all().delete()
        self._set_taxii(True)
        TaxiiCollection.objects.create(api_root='urllist', title='URLs', feed='url')
        TaxiiCollection.objects.create(api_root='urllist', title='IPs', feed='ip',
                                       is_active=False)

        status = dash._taxii_status()
        self.assertTrue(status['enabled'])
        # Only the active one counts — a paused collection is off the air.
        self.assertEqual(status['collections'], 1)

    def test_a_taxii_failure_does_not_take_the_dashboard_down(self):
        """The card is informational. If reading the status ever raises, the
        dashboard must still render — reported as off rather than blank."""
        from unittest.mock import patch

        from apps.taxii.models import TaxiiCollection

        with patch.object(TaxiiCollection.objects, 'filter',
                          side_effect=RuntimeError('boom')):
            with self.assertLogs('apps.dashboard.views', level='WARNING'):
                status = dash._taxii_status()
        self.assertEqual(status, {'enabled': False, 'collections': 0})

    # ── the rendered block ──

    def test_the_card_documents_the_taxii_endpoints(self):
        html = self._render()
        self.assertIn('class="db-api-taxii"', html)
        for path in ('/taxii/',
                     '/taxii/&lt;root&gt;/collections/',
                     '/taxii/&lt;root&gt;/collections/&lt;id&gt;/objects/',
                     '/taxii/&lt;root&gt;/collections/&lt;id&gt;/manifest/'):
            with self.subTest(path=path):
                self.assertIn(path, html)

    def test_the_block_says_the_authentication_is_different(self):
        """Every endpoint above it is source-IP-only. Listing TAXII paths
        without that distinction would send an operator to a 401."""
        html = self._render()
        self.assertIn('HTTP Basic', html)
        self.assertIn('API token', html)

    def test_the_chip_distinguishes_off_from_on_but_empty(self):
        """A server that is enabled with no active collection answers, but
        there is nothing to subscribe to — not visible from a path list."""
        from apps.taxii.models import TaxiiCollection

        TaxiiCollection.objects.all().delete()

        self._set_taxii(False)
        self.assertIn('Disabled', self._render(username='chip-off'))

        self._set_taxii(True)
        html = self._render(username='chip-empty')
        self.assertIn('no active collection', html)

        TaxiiCollection.objects.create(api_root='urllist', title='URLs', feed='url')
        html = self._render(username='chip-on')
        self.assertIn('1 collection', html)
        self.assertNotIn('no active collection', html)

    def test_the_card_stays_restricted(self):
        """The card was already gated. Adding TAXII to it must not widen who
        sees the platform's callable surface.

        Only admin reaches it in practice: the template also allows
        `api_user`, but login_required_custom sends that role to its profile
        page, so it never renders the dashboard at all. That branch is
        pre-existing and harmless; this pins the behaviour as it is rather
        than as the template suggests.
        """
        CARD = '<span class="card-title">API Endpoints</span>'
        self.assertIn('class="db-api-taxii"', self._render(role_name='admin',
                                                           username='card-adm'))
        for role in ('viewer', 'operator'):
            with self.subTest(role=role):
                html = self._render(role_name=role, username='card-' + role)
                self.assertNotIn(CARD, html)
                self.assertNotIn('class="db-api-taxii"', html)

        # api_user is redirected away from the dashboard entirely.
        from apps.accounts.models import Role, UserProfile
        from django.test import RequestFactory

        role, _ = Role.objects.get_or_create(name='api_user')
        user = User(username='card-apiuser', is_active=True)
        user.set_unusable_password()
        user.save()
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = role
        profile.save()
        request = RequestFactory(SERVER_NAME='localhost').get(
            reverse('dashboard:index'))
        request.user = User.objects.get(pk=user.pk)
        from apps.dashboard import views as dash_views
        self.assertEqual(dash_views.index(request).status_code, 302)

    def test_every_taxii_url_is_listed(self):
        """Walked out of the URLConf: a new TAXII endpoint that never reaches
        this card fails here rather than staying invisible."""
        from apps.taxii import urls as taxii_urls

        html = self._render(username='card-urls')
        block = re.search(r'class="db-api-taxii">(.*?)</div>\s*</div>\s*</div>',
                          html, re.S)
        self.assertIsNotNone(block, 'TAXII block missing from the card')
        listed = block.group(1)

        for pattern in taxii_urls.urlpatterns:
            route = str(pattern.pattern)
            if 'objects/<str:oid>' in route:
                continue        # a single object by id: a subscriber never
                                # builds that URL by hand, it follows the bundle
            segments = [seg for seg in route.split('/')
                        if seg and not seg.startswith('<')]
            with self.subTest(route=route or '(discovery)'):
                for seg in segments:
                    self.assertIn(seg, listed,
                                  '%r is not in the card' % seg)
