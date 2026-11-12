"""TAXII 2.0 conformance tests.

Covers the spec requirements that are easy to get subtly wrong and that a
subscriber would fail on silently: media types, the Range/206/416
pagination contract, the mandatory X-TAXII date headers, the STIX 2.0
bundle shape (spec_version on the bundle, not the objects), and the
domain-name-vs-url pattern split that matters because this blacklist is
mostly whole domains.

Run just these: `manage.py test apps.taxii`
"""
import base64
import json
import re
from datetime import timedelta, timezone as dt_timezone
from urllib.parse import quote

from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.utils import timezone

from apps.settings_app.cache import SettingsCache
from apps.settings_app.models import Setting
from apps.taxii.models import TaxiiCollection
from apps.urllist.models import URLEntry

USER = 'ddd-taxii'
ROOT = 'urllist'


def _auth_header(user, token):
    """TAXII Basic auth: username + the account's API token as the password."""
    raw = base64.b64encode(f'{user}:{token}'.encode()).decode()
    return {'HTTP_AUTHORIZATION': f'Basic {raw}'}


class TaxiiTestBase(TestCase):
    def setUp(self):
        self.client = Client()
        self._set('taxii.enabled', 'true', 'bool')
        # Isolate the token path; the source-IP gate has its own test.
        self._set('taxii.require_source_ip', 'false', 'bool')
        self._set('taxii.page_size_default', '500', 'int')

        # Migration 0002 seeds a default collection, which is correct for a
        # real deploy but means every test would start with two. Clear it so
        # each test controls exactly what is published.
        TaxiiCollection.objects.all().delete()

        self.token = self._make_api_user(USER)
        self.collection = TaxiiCollection.objects.create(
            api_root=ROOT, title='Malicious URLs & Domains', feed='url',
        )

    def _set(self, key, value, vtype, secret=False):
        Setting.objects.update_or_create(
            key=key,
            defaults={'value': value, 'value_type': vtype, 'category': 'taxii',
                      'description': key, 'is_secret': secret},
        )
        SettingsCache.invalidate(key)

    def _make_api_user(self, username, role_name='api_user', active=True):
        """Create a user with the given role and mint an API token.
        Returns the raw token (only available at mint time).

        No usable password is set — TAXII never checks one, and skipping
        the PBKDF2 hash keeps the suite fast.
        """
        from apps.accounts.models import Role, UserProfile

        user = User(username=username, is_active=active)
        user.set_unusable_password()
        user.save()
        role, _ = Role.objects.get_or_create(name=role_name)
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = role
        profile.save()
        return profile.generate_api_token()

    @property
    def cid(self):
        return self.collection.uuid_str

    def _objects_url(self):
        return f'/taxii/{ROOT}/collections/{self.cid}/objects/'

    def _manifest_url(self):
        return f'/taxii/{ROOT}/collections/{self.cid}/manifest/'

    def _get(self, url, **extra):
        return self.client.get(url, **{**_auth_header(USER, self.token), **extra})


class AuthTests(TaxiiTestBase):
    def test_disabled_server_returns_404(self):
        self._set('taxii.enabled', 'false', 'bool')
        # 404 rather than 403 so a scanner cannot tell a disabled TAXII
        # server from a host that never had one.
        self.assertEqual(self._get('/taxii/').status_code, 404)

    def test_missing_credentials_is_401_with_challenge(self):
        resp = self.client.get('/taxii/')
        self.assertEqual(resp.status_code, 401)
        self.assertIn('Basic', resp['WWW-Authenticate'])

    def test_unknown_token_is_401(self):
        resp = self.client.get('/taxii/', **_auth_header(USER, 'not-a-real-token'))
        self.assertEqual(resp.status_code, 401)

    def test_valid_token_with_wrong_username_is_401(self):
        # A leaked token must not authenticate as whatever account the
        # caller happens to name.
        resp = self.client.get('/taxii/', **_auth_header('someone-else', self.token))
        self.assertEqual(resp.status_code, 401)

    def test_login_password_is_not_accepted(self):
        # The whole point of using tokens: the account's console password
        # must NOT work as the Basic secret.
        resp = self.client.get('/taxii/', **_auth_header(USER, 'irrelevant'))
        self.assertEqual(resp.status_code, 401)

    def test_non_api_user_role_is_403(self):
        token = self._make_api_user('viewer-acct', role_name='viewer')
        resp = self.client.get('/taxii/', **_auth_header('viewer-acct', token))
        self.assertEqual(resp.status_code, 403)

    def test_inactive_account_is_403(self):
        token = self._make_api_user('disabled-acct', active=False)
        resp = self.client.get('/taxii/', **_auth_header('disabled-acct', token))
        self.assertEqual(resp.status_code, 403)

    def test_revoked_token_stops_working(self):
        from apps.accounts.models import UserProfile
        profile = UserProfile.objects.get(user__username=USER)
        profile.revoke_api_token()
        resp = self.client.get('/taxii/', **_auth_header(USER, self.token))
        self.assertEqual(resp.status_code, 401)

    def test_source_ip_gate_returns_403_when_not_allowlisted(self):
        self._set('taxii.require_source_ip', 'true', 'bool')
        # No AllowedSourceIP rows exist, and check_source_ip denies all in
        # that case — so a valid token still must not get through.
        resp = self._get('/taxii/')
        self.assertEqual(resp.status_code, 403)


class DiscoveryTests(TaxiiTestBase):
    def test_discovery_shape_and_media_type(self):
        resp = self._get('/taxii/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/vnd.oasis.taxii+json; version=2.0')
        body = json.loads(resp.content)
        self.assertIn('title', body)                      # required by §4.1.1
        self.assertIn(body['default'], body['api_roots'])  # default must be in api_roots
        self.assertTrue(body['api_roots'][0].endswith(f'/taxii/{ROOT}/'))

    def test_api_root_advertises_taxii_20(self):
        resp = self._get(f'/taxii/{ROOT}/')
        self.assertEqual(resp.status_code, 200)
        body = json.loads(resp.content)
        # §4.2.1: "A value of taxii-2.0 MUST be included in this list."
        self.assertIn('taxii-2.0', body['versions'])
        self.assertIn('title', body)
        self.assertIsInstance(body['max_content_length'], int)

    def test_unknown_api_root_is_404(self):
        self.assertEqual(self._get('/taxii/not-a-root/').status_code, 404)


class CollectionTests(TaxiiTestBase):
    def test_collections_list(self):
        resp = self._get(f'/taxii/{ROOT}/collections/')
        self.assertEqual(resp.status_code, 200)
        cols = json.loads(resp.content)['collections']
        self.assertEqual(len(cols), 1)
        c = cols[0]
        for required in ('id', 'title', 'can_read', 'can_write'):
            self.assertIn(required, c)
        self.assertTrue(c['can_read'])
        self.assertFalse(c['can_write'])   # read-only producer
        self.assertEqual(c['media_types'], ['application/vnd.oasis.stix+json; version=2.0'])

    def test_unknown_collection_is_404(self):
        bad = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
        self.assertEqual(self._get(f'/taxii/{ROOT}/collections/{bad}/').status_code, 404)

    def test_malformed_collection_id_is_404_not_500(self):
        # A subscriber holding a corrupted id should re-discover, not see a
        # server error.
        resp = self._get(f'/taxii/{ROOT}/collections/not-a-uuid/')
        self.assertEqual(resp.status_code, 404)

    def test_paused_collection_disappears(self):
        # Pausing keeps the UUID but takes the feed off the air.
        self.collection.is_active = False
        self.collection.save(update_fields=['is_active'])
        self.assertEqual(self._get(f'/taxii/{ROOT}/collections/{self.cid}/').status_code, 404)
        self.assertEqual(self._get(self._objects_url()).status_code, 404)
        # ...and the api root goes with it, since it has no active collections.
        self.assertEqual(self._get(f'/taxii/{ROOT}/').status_code, 404)
        # Discovery still answers, just with nothing to point at.
        body = json.loads(self._get('/taxii/').content)
        self.assertEqual(body['api_roots'], [])
        self.assertNotIn('default', body)

    def test_multiple_roots_are_discoverable(self):
        # The point of modelling collections rather than hard-coding one:
        # a second root/collection shows up without a code change.
        other = TaxiiCollection.objects.create(
            api_root='partner', title='Partner Feed', feed='url',
        )
        body = json.loads(self._get('/taxii/').content)
        self.assertEqual(len(body['api_roots']), 2)

        resp = self._get(f'/taxii/partner/collections/')
        cols = json.loads(resp.content)['collections']
        self.assertEqual(cols[0]['id'], other.uuid_str)

    def test_same_feed_twice_in_one_root_is_rejected(self):
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            TaxiiCollection.objects.create(
                api_root=ROOT, title='Duplicate', feed='url',
            )

    def test_collection_from_another_root_is_404_under_this_root(self):
        other = TaxiiCollection.objects.create(
            api_root='partner', title='Partner Feed', feed='url',
        )
        # Right UUID, wrong root → must not resolve.
        resp = self._get(f'/taxii/{ROOT}/collections/{other.uuid_str}/')
        self.assertEqual(resp.status_code, 404)


class ObjectsTests(TaxiiTestBase):
    def setUp(self):
        super().setUp()
        base = timezone.now() - timedelta(days=5)
        # A bare domain — the dominant case for this blacklist.
        self.bare = URLEntry.objects.create(
            url_value='phishing.example', list_type='black', reason='Credential harvest',
        )
        URLEntry.objects.filter(pk=self.bare.pk).update(added_at=base)
        # A path-bearing URL.
        self.withpath = URLEntry.objects.create(
            url_value='bad.example/login.php', list_type='black', reason='Fake login',
        )
        URLEntry.objects.filter(pk=self.withpath.pk).update(added_at=base + timedelta(days=1))
        # Excluded: inactive.
        URLEntry.objects.create(url_value='old.example', list_type='black', is_active=False)
        # Excluded: VT unreachable, so no verdict to publish.
        URLEntry.objects.create(url_value='unknown.example', list_type='black', vt_unavailable=True)
        self.bare.refresh_from_db()
        self.withpath.refresh_from_db()

    def test_bundle_shape_is_stix_20(self):
        resp = self._get(self._objects_url())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/vnd.oasis.stix+json; version=2.0')
        b = json.loads(resp.content)
        self.assertEqual(b['type'], 'bundle')
        # In STIX 2.0 spec_version lives on the bundle; 2.1 moved it onto
        # each object. Getting this backwards breaks strict parsers.
        self.assertEqual(b['spec_version'], '2.0')
        self.assertTrue(b['id'].startswith('bundle--'))

    def test_only_active_available_entries_published(self):
        b = json.loads(self._get(self._objects_url()).content)
        self.assertEqual(len(b['objects']), 2)
        patterns = ' '.join(o['pattern'] for o in b['objects'])
        self.assertNotIn('old.example', patterns)
        self.assertNotIn('unknown.example', patterns)

    def test_bare_domain_becomes_domain_name_pattern(self):
        b = json.loads(self._get(self._objects_url()).content)
        pats = [o['pattern'] for o in b['objects']]
        self.assertIn("[domain-name:value = 'phishing.example']", pats)

    def test_path_url_becomes_url_pattern_with_scheme(self):
        b = json.loads(self._get(self._objects_url()).content)
        pats = [o['pattern'] for o in b['objects']]
        self.assertIn("[url:value = 'https://bad.example/login.php']", pats)

    def test_labels_survive_ddd_filter(self):
        # Deep Discovery Director drops indicators labelled
        # anomalous-activity / anonymization / benign / compromised.
        dropped = {'anomalous-activity', 'anonymization', 'benign', 'compromised'}
        b = json.loads(self._get(self._objects_url()).content)
        for o in b['objects']:
            self.assertEqual(o['labels'], ['malicious-activity'])
            self.assertFalse(dropped & set(o['labels']))
            self.assertNotIn('revoked', o)

    def test_stix_20_required_fields_present_and_21_fields_absent(self):
        b = json.loads(self._get(self._objects_url()).content)
        for o in b['objects']:
            for required in ('type', 'id', 'created', 'modified', 'labels',
                             'pattern', 'valid_from'):
                self.assertIn(required, o)
            # These are STIX 2.1 additions and must not appear in 2.0 output.
            self.assertNotIn('pattern_type', o)
            self.assertNotIn('indicator_types', o)
            self.assertNotIn('spec_version', o)

    def test_indicator_ids_are_deterministic(self):
        first = {o['id'] for o in json.loads(self._get(self._objects_url()).content)['objects']}
        second = {o['id'] for o in json.loads(self._get(self._objects_url()).content)['objects']}
        self.assertEqual(first, second)
        self.assertTrue(all(i.startswith('indicator--') for i in first))

    def test_x_taxii_date_headers_present(self):
        resp = self._get(self._objects_url())
        # Required on 200/206 from objects and manifest (§3.4).
        self.assertIn('X-TAXII-Date-Added-First', resp)
        self.assertIn('X-TAXII-Date-Added-Last', resp)
        self.assertTrue(resp['X-TAXII-Date-Added-First'].endswith('Z'))

    def test_sorted_ascending_by_date_added(self):
        resp = self._get(self._objects_url())
        self.assertLessEqual(resp['X-TAXII-Date-Added-First'],
                             resp['X-TAXII-Date-Added-Last'])

    def test_added_after_filters_incrementally(self):
        # Mirrors Deep Discovery Director's "start-polling lookback".
        cutoff = quote((self.bare.added_at + timedelta(hours=1)).isoformat())
        b = json.loads(self._get(f'{self._objects_url()}?added_after={cutoff}').content)
        pats = ' '.join(o['pattern'] for o in b['objects'])
        self.assertIn('bad.example', pats)
        self.assertNotIn('phishing.example', pats)

    def test_added_after_survives_unencoded_plus(self):
        # A `+` left unencoded in the query string decodes to a space, so
        # `+00:00` arrives as ` 00:00`. The filter must still apply —
        # silently falling back to "serve everything" would hand a client
        # a full dump it believes is a delta.
        raw = (self.bare.added_at + timedelta(hours=1)).isoformat()   # has +00:00
        b = json.loads(self._get(f'{self._objects_url()}?added_after={raw}').content)
        pats = ' '.join(o['pattern'] for o in b['objects'])
        self.assertIn('bad.example', pats)
        self.assertNotIn('phishing.example', pats)

    def test_added_after_accepts_z_suffix(self):
        cutoff = quote(
            (self.bare.added_at + timedelta(hours=1))
            .astimezone(dt_timezone.utc)
            .strftime('%Y-%m-%dT%H:%M:%S.000Z')
        )
        b = json.loads(self._get(f'{self._objects_url()}?added_after={cutoff}').content)
        pats = ' '.join(o['pattern'] for o in b['objects'])
        self.assertNotIn('phishing.example', pats)

    def test_garbage_added_after_is_400_not_a_silent_full_dump(self):
        resp = self._get(f'{self._objects_url()}?added_after=not-a-timestamp')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(json.loads(resp.content)['title'], 'Bad Request')

    def test_garbage_added_after_on_manifest_is_also_400(self):
        resp = self._get(f'{self._manifest_url()}?added_after=nope')
        self.assertEqual(resp.status_code, 400)

    def test_match_type_non_indicator_yields_empty_bundle(self):
        b = json.loads(self._get(f'{self._objects_url()}?match[type]=malware').content)
        self.assertEqual(b['objects'], [])

    def test_empty_collection_is_an_empty_bundle_not_an_error(self):
        URLEntry.objects.all().delete()
        resp = self._get(self._objects_url())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(json.loads(resp.content)['objects'], [])


class PaginationTests(TaxiiTestBase):
    def setUp(self):
        super().setUp()
        base = timezone.now() - timedelta(days=30)
        for i in range(10):
            e = URLEntry.objects.create(url_value=f'host{i:02d}.example', list_type='black')
            URLEntry.objects.filter(pk=e.pk).update(added_at=base + timedelta(hours=i))

    def test_range_returns_206_with_content_range(self):
        resp = self._get(self._objects_url(), HTTP_RANGE='items 0-2')
        self.assertEqual(resp.status_code, 206)
        self.assertEqual(resp['Content-Range'], 'items 0-2/10')
        self.assertEqual(resp['Accept-Ranges'], 'items')
        self.assertEqual(len(json.loads(resp.content)['objects']), 3)

    def test_mid_range_slice(self):
        resp = self._get(self._objects_url(), HTTP_RANGE='items 4-6')
        self.assertEqual(resp.status_code, 206)
        self.assertEqual(resp['Content-Range'], 'items 4-6/10')

    def test_range_past_end_is_416(self):
        resp = self._get(self._objects_url(), HTTP_RANGE='items 500-600')
        self.assertEqual(resp.status_code, 416)

    def test_no_range_under_page_size_is_200(self):
        resp = self._get(self._objects_url())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(json.loads(resp.content)['objects']), 10)

    def test_no_range_over_page_size_is_206(self):
        # §3.4.3 lets a server answer 206 even with no Range requested.
        self._set('taxii.page_size_default', '4', 'int')
        resp = self._get(self._objects_url())
        self.assertEqual(resp.status_code, 206)
        self.assertEqual(resp['Content-Range'], 'items 0-3/10')
        self.assertEqual(len(json.loads(resp.content)['objects']), 4)

    def test_malformed_range_is_lenient_not_416(self):
        resp = self._get(self._objects_url(), HTTP_RANGE='bytes=0-100')
        self.assertIn(resp.status_code, (200, 206))


class ManifestTests(TaxiiTestBase):
    def setUp(self):
        super().setUp()
        self.entry = URLEntry.objects.create(
            url_value='manifest.example', list_type='black', reason='test',
        )

    def test_manifest_entry_shape(self):
        resp = self._get(self._manifest_url())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/vnd.oasis.taxii+json; version=2.0')
        objs = json.loads(resp.content)['objects']
        self.assertEqual(len(objs), 1)
        m = objs[0]
        self.assertTrue(m['id'].startswith('indicator--'))
        self.assertTrue(m['date_added'].endswith('Z'))
        self.assertEqual(m['media_types'], ['application/vnd.oasis.stix+json; version=2.0'])
        self.assertEqual(len(m['versions']), 1)

    def test_empty_manifest_omits_objects_key(self):
        URLEntry.objects.all().delete()
        body = json.loads(self._get(self._manifest_url()).content)
        # §5.1.1 pattern: omit the key entirely rather than send an empty list.
        self.assertEqual(body, {})


class SingleObjectTests(TaxiiTestBase):
    def setUp(self):
        super().setUp()
        self.entry = URLEntry.objects.create(url_value='single.example', list_type='black')

    def test_fetch_by_indicator_id(self):
        from apps.taxii import stix
        oid = stix.indicator_id(self.entry)
        resp = self._get(f'{self._objects_url()}{oid}/')
        self.assertEqual(resp.status_code, 200)
        objs = json.loads(resp.content)['objects']
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['id'], oid)

    def test_unknown_object_id_is_404(self):
        resp = self._get(f'{self._objects_url()}indicator--{"0"*8}-0000-4000-8000-{"0"*12}/')
        self.assertEqual(resp.status_code, 404)


class UrlWiringTests(TestCase):
    """Guards the bug class that took down every authenticated page:
    `{% url 'taxii_admin:... %}` in the shared sidebar while the namespace
    was nested under `settings_app:` and so unresolvable.

    `manage.py check` does not validate `{% url %}` tags and none of the
    API tests render a template, so nothing caught it. These tests render
    the sidebar directly — `render_to_string`, not the test client, because
    the test client's `template_rendered` instrumentation copies the
    template Context and `BaseContext.__copy__` is broken on this
    Python 3.14 / Django 4.2 combination. Direct rendering still exercises
    every `{% url %}` in the template, which is the point.
    """

    def test_taxii_admin_namespace_is_registered(self):
        from django.urls import reverse
        self.assertEqual(
            reverse('taxii_admin:collection_list'),
            '/settings/taxii/collections/',
        )
        self.assertEqual(
            reverse('taxii_admin:collection_add'),
            '/settings/taxii/collections/add/',
        )
        for name in ('collection_edit', 'collection_toggle', 'collection_delete'):
            with self.subTest(name=name):
                self.assertTrue(reverse(f'taxii_admin:{name}', kwargs={'pk': 1}))

    def test_public_taxii_namespace_is_registered(self):
        from django.urls import reverse
        self.assertEqual(reverse('taxii:discovery'), '/taxii/')
        self.assertEqual(
            reverse('taxii:api_root', kwargs={'root': 'urllist'}),
            '/taxii/urllist/',
        )

    def test_admin_prefix_does_not_shadow_settings_index(self):
        # /settings/taxii/collections/ is mounted BEFORE /settings/ in the
        # root urlconf; make sure the broader include still resolves.
        from django.urls import reverse
        self.assertEqual(reverse('settings_app:index'), '/settings/')

    def test_every_taxii_admin_url_tag_in_templates_resolves(self):
        """The real guard against the nested-namespace bug, and immune to the
        link moving between templates: find every `{% url 'taxii_admin:…' %}`
        in the template tree and reverse it. `manage.py check` does not
        validate url tags, so without this nothing catches an unresolvable
        name until a page 500s."""
        import re
        from pathlib import Path

        from django.conf import settings as dj_settings
        from django.urls import NoReverseMatch, reverse

        tag_re = re.compile(r"""\{%\s*url\s+['"](taxii_admin:[a-z_]+)['"]([^%]*)%\}""")
        dirs = [Path(d) for d in dj_settings.TEMPLATES[0].get('DIRS', [])]
        self.assertTrue(dirs, 'no project template directory configured')

        found = []
        for base in dirs:
            for tpl in base.rglob('*.html'):
                for name, rest in tag_re.findall(tpl.read_text(encoding='utf-8')):
                    found.append((tpl.relative_to(base).as_posix(), name, rest))

        self.assertTrue(found, 'no template links to the collection UI any more')
        for where, name, rest in found:
            with self.subTest(template=where, name=name):
                kwargs = {'pk': 1} if rest.strip() else {}
                try:
                    reverse(name, kwargs=kwargs)
                except NoReverseMatch as exc:
                    self.fail(f'{where} references {name}, which does not '
                              f'reverse: {exc}')

    def test_collection_ui_is_reached_from_the_taxii_settings_category(self):
        """Placement is a requirement, not an accident: the collection UI is
        TAXII configuration, so it hangs off that settings category rather
        than the global sidebar."""
        from pathlib import Path

        from django.conf import settings as dj_settings

        base = Path(dj_settings.TEMPLATES[0]['DIRS'][0])
        settings_index = (base / 'settings_app' / 'index.html').read_text(encoding='utf-8')
        sidebar = (base / 'partials' / 'sidebar.html').read_text(encoding='utf-8')

        self.assertIn('taxii_admin:collection_list', settings_index)
        self.assertNotIn('taxii_admin', sidebar)

    def test_sidebar_template_resolves_every_url(self):
        from django.contrib.auth.models import AnonymousUser
        from django.template.loader import render_to_string
        from django.test import RequestFactory

        from apps.accounts.models import Role, UserProfile

        role, _ = Role.objects.get_or_create(name='admin')
        admin = User(username='sidebar-admin', is_active=True)
        admin.set_unusable_password()
        admin.save()
        profile, _ = UserProfile.objects.get_or_create(user=admin)
        profile.role = role
        profile.save()
        # Re-fetch: a post_save signal caches a role-less profile on the
        # instance, and the template reads request.user.profile.role.name.
        admin = User.objects.get(pk=admin.pk)

        # The sidebar derives `role_name` and `path` itself from `request`
        # (`{% with role_name=request.user.profile.role.name ... %}`), so the
        # context needs a real request — passing None skips the very
        # Administration block the TAXII link lives in and the assertion
        # below would fail for the wrong reason.
        rf = RequestFactory()
        request = rf.get('/dashboard/')
        request.user = admin

        html = render_to_string('partials/sidebar.html', {
            'request': request,
            'user': admin,
            'role_name': 'admin',
            'path': '/dashboard/',
            'sidebarOpen': True,
        })
        # The Administration block must have rendered, or this template never
        # reached the part where a bad {% url %} would have thrown.
        self.assertIn('Administration', html)
        self.assertIn('/settings/', html)
        # Collection management is NOT a top-level destination any more — it
        # belongs to the TAXII settings category and is reached from there.
        self.assertNotIn('/settings/taxii/collections/', html)
        self.assertNotIn('TAXII Collections', html)

        # AnonymousUser must not blow up the template either.
        anon_request = rf.get('/')
        anon_request.user = AnonymousUser()
        render_to_string('partials/sidebar.html', {
            'request': anon_request, 'user': anon_request.user,
            'role_name': None, 'path': '/',
        })


class AdminCrudTests(TestCase):
    """Collection CRUD through the real views.

    Every assertion here lands on a redirect or a DB fact rather than a
    rendered page, so it works despite the template-render limitation
    described in UrlWiringTests.
    """

    def setUp(self):
        from apps.accounts.models import Role, UserProfile

        self.client = Client()
        role, _ = Role.objects.get_or_create(name='admin')
        self.admin = User(username='crud-admin', is_active=True)
        self.admin.set_unusable_password()
        self.admin.save()
        profile, _ = UserProfile.objects.get_or_create(user=self.admin)
        profile.role = role
        profile.save()
        self.client.force_login(self.admin)
        TaxiiCollection.objects.all().delete()

    def test_create_assigns_a_uuid_we_never_typed(self):
        resp = self.client.post('/settings/taxii/collections/add/', {
            'api_root': 'partner', 'title': 'Partner Feed',
            'feed': 'url', 'description': 'via UI',
        })
        self.assertEqual(resp.status_code, 302)
        coll = TaxiiCollection.objects.get(api_root='partner')
        self.assertEqual(coll.title, 'Partner Feed')
        self.assertIsNotNone(coll.collection_id)
        self.assertEqual(len(coll.uuid_str), 36)

    def _post_add(self, data):
        """POST to the Add view without the test client.

        A rejected submission now re-renders the form (so a typo in one field
        does not discard the other three) instead of bouncing to the list, and
        the test client's `template_rendered` instrumentation cannot copy a
        template Context on this Python 3.14 / Django 4.2 combination. Driving
        the view directly keeps the real code path and skips that
        instrumentation; messages need a storage backend attached by hand
        because no middleware runs here.
        """
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.test import RequestFactory

        from apps.taxii import admin_views

        request = RequestFactory().post('/settings/taxii/collections/add/', data)
        request.user = User.objects.get(pk=self.admin.pk)
        request.session = {}
        request._messages = FallbackStorage(request)
        return admin_views.collection_add(request)

    def test_duplicate_feed_in_same_root_is_rejected(self):
        TaxiiCollection.objects.create(api_root='dup', title='First', feed='url')
        resp = self._post_add({'api_root': 'dup', 'title': 'Second', 'feed': 'url'})
        # Re-rendered form, not an IntegrityError 500 and not a redirect that
        # throws the operator's input away.
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(TaxiiCollection.objects.filter(api_root='dup').count(), 1)

    def test_new_api_root_option_resolves_to_the_text_field(self):
        """The dropdown's "+ New API root…" sentinel is not itself a root —
        the view must read the companion text box instead."""
        resp = self._post_add({
            'api_root': '__new__', 'api_root_new': 'partner-b',
            'title': 'Partner B', 'feed': 'url',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(TaxiiCollection.objects.filter(api_root='partner-b').exists())
        # The sentinel must never reach the database, or /taxii/__new__/ would
        # be advertised as a real api root.
        self.assertFalse(TaxiiCollection.objects.filter(api_root='__new__').exists())

    def test_api_root_is_lower_cased(self):
        """Django path matching is case-sensitive, so a root stored with
        capitals would advertise a URL that only resolves if the subscriber
        reproduces them."""
        resp = self._post_add({
            'api_root': '__new__', 'api_root_new': 'MixedCase',
            'title': 'Mixed', 'feed': 'url',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(TaxiiCollection.objects.filter(api_root='mixedcase').exists())

    def test_api_root_that_cannot_live_in_a_url_is_rejected(self):
        for bad in ('has space', 'has/slash', 'has.dot', ''):
            with self.subTest(api_root=bad):
                resp = self._post_add({
                    'api_root': '__new__', 'api_root_new': bad,
                    'title': 'Bad', 'feed': 'url',
                })
                self.assertEqual(resp.status_code, 200)
        self.assertFalse(TaxiiCollection.objects.filter(title='Bad').exists())

    def test_unknown_feed_is_rejected(self):
        resp = self._post_add({
            'api_root': '__new__', 'api_root_new': 'r1',
            'title': 'Ghost', 'feed': 'does-not-exist',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(TaxiiCollection.objects.filter(api_root='r1').exists())

    def test_missing_title_is_rejected(self):
        resp = self._post_add({
            'api_root': '__new__', 'api_root_new': 'r2',
            'title': '   ', 'feed': 'url',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(TaxiiCollection.objects.filter(api_root='r2').exists())

    def test_toggle_pauses_and_resumes_without_changing_uuid(self):
        coll = TaxiiCollection.objects.create(api_root='t', title='T', feed='url')
        original = coll.uuid_str

        self.client.post(f'/settings/taxii/collections/{coll.pk}/toggle/')
        coll.refresh_from_db()
        self.assertFalse(coll.is_active)
        self.assertEqual(coll.uuid_str, original)

        self.client.post(f'/settings/taxii/collections/{coll.pk}/toggle/')
        coll.refresh_from_db()
        self.assertTrue(coll.is_active)
        self.assertEqual(coll.uuid_str, original)

    def test_edit_updates_title_only(self):
        coll = TaxiiCollection.objects.create(api_root='e', title='Old', feed='url')
        original_uuid, original_root = coll.uuid_str, coll.api_root
        self.client.post(f'/settings/taxii/collections/{coll.pk}/edit/', {
            'title': 'New Title', 'description': 'changed',
        })
        coll.refresh_from_db()
        self.assertEqual(coll.title, 'New Title')
        # Address-defining fields stay put — changing them would break a
        # subscriber that already discovered this collection.
        self.assertEqual(coll.uuid_str, original_uuid)
        self.assertEqual(coll.api_root, original_root)

    def test_delete_removes_the_collection(self):
        coll = TaxiiCollection.objects.create(api_root='d', title='D', feed='url')
        resp = self.client.post(f'/settings/taxii/collections/{coll.pk}/delete/')
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(TaxiiCollection.objects.filter(pk=coll.pk).exists())

    def test_non_admin_cannot_mutate_collections(self):
        from django.core.exceptions import PermissionDenied
        from django.test import RequestFactory

        from apps.accounts.models import Role, UserProfile
        from apps.taxii import admin_views

        role, _ = Role.objects.get_or_create(name='viewer')
        viewer = User(username='crud-viewer', is_active=True)
        viewer.set_unusable_password()
        viewer.save()
        profile, _ = UserProfile.objects.get_or_create(user=viewer)
        profile.role = role
        profile.save()

        # Re-fetch so `user.profile` is not the stale object a post_save
        # signal cached on the instance at creation time. With the stale
        # copy the role reads as None, `login_required_custom` takes its
        # "no role assigned" branch and redirects to the profile page — the
        # viewer is still denied, but via a different path than the one
        # this test is about.
        viewer = User.objects.get(pk=viewer.pk)

        # Call the view directly: the test client turns PermissionDenied into
        # a 403 response, which hides whether the decorator actually fired or
        # something else failed. RequestFactory lets the exception surface.
        request = RequestFactory().post('/settings/taxii/collections/add/', {
            'api_root': 'nope', 'title': 'Nope', 'feed': 'url',
        })
        request.user = viewer
        with self.assertRaises(PermissionDenied):
            admin_views.collection_add(request)
        self.assertFalse(TaxiiCollection.objects.filter(api_root='nope').exists())

    def test_user_with_no_role_is_redirected_away(self):
        """The other denial path: no role at all → bounced to the profile
        page by login_required_custom, never reaching role_required."""
        from django.test import RequestFactory

        from apps.accounts.models import UserProfile
        from apps.taxii import admin_views

        nobody = User(username='crud-norole', is_active=True)
        nobody.set_unusable_password()
        nobody.save()
        UserProfile.objects.get_or_create(user=nobody)   # left role=None

        request = RequestFactory().post('/settings/taxii/collections/add/', {
            'api_root': 'nope2', 'title': 'Nope', 'feed': 'url',
        })
        request.user = User.objects.get(pk=nobody.pk)
        resp = admin_views.collection_add(request)
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(TaxiiCollection.objects.filter(api_root='nope2').exists())


class PatternEdgeCaseTests(TaxiiTestBase):
    """The pattern split is the one piece of business logic here, so it gets
    direct unit coverage rather than only going through HTTP."""

    def test_pattern_selection(self):
        from apps.taxii.stix import pattern_for
        cases = [
            ('phishing.example',            "[domain-name:value = 'phishing.example']"),
            ('sub.phishing.example',        "[domain-name:value = 'sub.phishing.example']"),
            ('bad.example/a/b',             "[url:value = 'https://bad.example/a/b']"),
            ('bad.example:8443/x',          "[url:value = 'https://bad.example:8443/x']"),
            ('bad.example:8443',            "[url:value = 'https://bad.example:8443']"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(pattern_for(value), expected)

    def test_quote_is_escaped_in_pattern(self):
        from apps.taxii.stix import pattern_for
        # A quote in a stored URL must not break out of the STIX literal.
        got = pattern_for("bad.example/it's")
        self.assertIn("\\'", got)
        self.assertTrue(got.startswith('[url:value = '))

class AddFormDataTests(TestCase):
    """The Add form drives its dropdowns off these three helpers, so the data
    they return is what decides whether the operator can submit a combination
    the database would then reject.

    Plain `TestCase`, not `TaxiiTestBase`: that base seeds a collection for
    the HTTP tests to serve, and these assertions are about exactly which
    roots and feeds exist.
    """

    def setUp(self):
        # Clear both the migration-seeded collection and anything a sibling
        # test left behind, so each assertion sees only its own fixtures.
        TaxiiCollection.objects.all().delete()

    def test_known_roots_is_distinct_and_sorted(self):
        TaxiiCollection.objects.create(api_root='zeta', title='Z', feed='url')
        TaxiiCollection.objects.create(api_root='alpha', title='A', feed='url')
        self.assertEqual(TaxiiCollection.known_roots(), ['alpha', 'zeta'])

    def test_known_roots_includes_paused_collections(self):
        """A paused collection still owns its (root, feed) pair, so hiding it
        would offer the operator a combination that cannot be created."""
        TaxiiCollection.objects.create(api_root='paused', title='P',
                                       feed='url', is_active=False)
        self.assertIn('paused', TaxiiCollection.known_roots())

    def test_taken_feeds_by_root_maps_each_pair_in_use(self):
        TaxiiCollection.objects.create(api_root='r1', title='A', feed='url')
        TaxiiCollection.objects.create(api_root='r2', title='B',
                                       feed='url', is_active=False)
        taken = TaxiiCollection.taken_feeds_by_root()
        self.assertEqual(taken['r1'], ['url'])
        self.assertEqual(taken['r2'], ['url'])
        self.assertNotIn('r3', taken)

    def test_feed_catalog_covers_every_choice_with_a_title(self):
        catalog = TaxiiCollection.feed_catalog()
        self.assertEqual(
            {f['value'] for f in catalog},
            {k for k, _ in TaxiiCollection.FEED_CHOICES},
        )
        for f in catalog:
            with self.subTest(feed=f['value']):
                # The form pre-fills Title from this, so it must never be blank
                # or the operator lands on a form that cannot be submitted.
                self.assertTrue(f['title'])
                self.assertTrue(f['label'])

    def test_form_context_opens_on_a_root_that_still_has_a_free_feed(self):
        """With every existing root full, the form must open on "new root"
        rather than on a selection that cannot produce a collection."""
        from django.test import RequestFactory

        from apps.taxii.admin_views import NEW_ROOT, _add_form_context

        # Occupy every feed under one root, so no existing root can take
        # another collection.
        for feed, _label in TaxiiCollection.FEED_CHOICES:
            TaxiiCollection.objects.create(api_root='full', title=f'F-{feed}', feed=feed)

        ctx = _add_form_context(RequestFactory().get('/'))
        self.assertEqual(ctx['form_data']['rootMode'], NEW_ROOT)
        self.assertEqual(ctx['known_roots'], ['full'])
        # A suggested root is never also listed as in use, or the dropdown
        # would show the same value twice.
        self.assertNotIn('full', ctx['suggested_roots'])

    def test_a_root_with_a_free_feed_is_preselected(self):
        """The opposite case: an existing root that can still take a
        collection should be what the form opens on."""
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        TaxiiCollection.objects.create(api_root='partly', title='P', feed='url')
        ctx = _add_form_context(RequestFactory().get('/'))
        self.assertEqual(ctx['form_data']['rootMode'], 'partly')

    def test_suggested_roots_exclude_roots_already_in_use(self):
        TaxiiCollection.objects.create(api_root='urllist', title='U', feed='url')
        suggested = TaxiiCollection.suggested_roots()
        self.assertNotIn('urllist', suggested)
        self.assertIn('default', suggested)

    def test_form_context_preserves_a_rejected_submission(self):
        from django.test import RequestFactory

        from apps.taxii.admin_views import NEW_ROOT, _add_form_context

        ctx = _add_form_context(
            RequestFactory().get('/'),
            api_root='typo root', feed='url', title='Kept', description='Also kept',
            root_mode=NEW_ROOT,
        )
        data = ctx['form_data']
        self.assertEqual(data['newRoot'], 'typo root')
        self.assertEqual(data['title'], 'Kept')
        self.assertEqual(data['description'], 'Also kept')


class UrlIndicatorIdStabilityTests(TaxiiTestBase):
    """The URL feed shipped first and subscribers already hold its indicator
    ids. Refactoring `stix.py` into per-feed adapters must not have changed
    a single one of them."""

    def test_url_indicator_id_is_still_uuid5_of_the_bare_url_hash(self):
        import uuid

        from apps.taxii.stix import INDICATOR_NAMESPACE, indicator_id

        entry = URLEntry.objects.create(
            url_value='stability.example', list_type='black', is_active=True,
        )
        expected = f'indicator--{uuid.uuid5(INDICATOR_NAMESPACE, entry.url_hash)}'
        self.assertEqual(indicator_id(entry), expected)


class IpFeedTests(TestCase):
    """IP Blacklist to ipv4-addr / ipv6-addr indicators."""

    def setUp(self):
        from apps.blacklist.models import BlacklistGroup

        TaxiiCollection.objects.all().delete()
        self.group, _ = BlacklistGroup.objects.get_or_create(
            name='30d', defaults={'label': '30 Days', 'is_published': True},
        )
        self.unpublished, _ = BlacklistGroup.objects.get_or_create(
            name='no_group', defaults={'label': 'None', 'is_published': False},
        )

    def _ip(self, cidr, prefix=32, **kw):
        from apps.blacklist.models import BlacklistEntry

        addr = cidr.split('/')[0]
        return BlacklistEntry.objects.create(
            ip_address=addr, prefix_length=prefix, cidr=cidr,
            group=kw.pop('group', self.group), **kw,
        )

    def test_host_prefix_is_published_as_a_bare_address(self):
        """A /32 ships without the prefix: consumers match a bare address
        most reliably, even though STIX would accept the CIDR form."""
        from apps.taxii.stix import entry_to_indicator

        entry = self._ip('198.51.100.7/32')
        self.assertEqual(
            entry_to_indicator(entry)['pattern'],
            "[ipv4-addr:value = '198.51.100.7']",
        )

    def test_real_block_keeps_its_prefix(self):
        from apps.taxii.stix import entry_to_indicator

        entry = self._ip('203.0.113.0/24', prefix=24)
        self.assertEqual(
            entry_to_indicator(entry)['pattern'],
            "[ipv4-addr:value = '203.0.113.0/24']",
        )

    def test_ipv6_uses_the_ipv6_observable(self):
        from apps.taxii.stix import entry_to_indicator

        entry = self._ip('2001:db8::1/128', prefix=128)
        pattern = entry_to_indicator(entry)['pattern']
        self.assertTrue(pattern.startswith('[ipv6-addr:value = '), pattern)
        self.assertIn('2001:db8::1', pattern)

    def test_indicator_is_a_valid_stix_20_indicator(self):
        from apps.taxii.stix import entry_to_indicator

        obj = entry_to_indicator(self._ip('198.51.100.8/32', reason='brute force'))
        for field in ('type', 'id', 'created', 'modified', 'labels',
                      'pattern', 'valid_from'):
            self.assertIn(field, obj)
        self.assertEqual(obj['labels'], ['malicious-activity'])
        # 2.1-only properties must never appear in a 2.0 object.
        self.assertNotIn('pattern_type', obj)
        self.assertNotIn('indicator_types', obj)
        self.assertNotIn('spec_version', obj)
        self.assertIn('brute force', obj['description'])

    def test_queryset_mirrors_the_firewall_predicate(self):
        from apps.taxii.stix import published_queryset

        keep = self._ip('198.51.100.10/32')
        self._ip('198.51.100.11/32', is_active=False)
        self._ip('198.51.100.12/32', group=self.unpublished)
        self._ip('198.51.100.13/32',
                 expires_at=timezone.now() - timedelta(hours=1))
        future = self._ip('198.51.100.14/32',
                          expires_at=timezone.now() + timedelta(hours=1))

        published = set(published_queryset('ip').values_list('pk', flat=True))
        self.assertIn(keep.pk, published)
        self.assertIn(future.pk, published, 'a not-yet-expired row must publish')
        self.assertEqual(len(published), 2)

    def test_whitelisted_ip_is_excluded(self):
        from apps.whitelist.models import WhitelistEntry
        from apps.taxii.stix import published_queryset

        blocked = self._ip('198.51.100.20/32')
        self._ip('10.1.2.3/32')

        WhitelistEntry.objects.create(
            ip_address='10.0.0.0', prefix_length=8, cidr='10.0.0.0/8',
            is_active=True,
        )

        published = set(published_queryset('ip').values_list('pk', flat=True))
        self.assertEqual(published, {blocked.pk})

    def test_mixed_ipv4_ipv6_whitelist_does_not_crash(self):
        """Comparing an IPv4 network with an IPv6 one raises TypeError, so
        the overlap test must check the version first."""
        from apps.whitelist.models import WhitelistEntry
        from apps.taxii.stix import published_queryset

        WhitelistEntry.objects.create(
            ip_address='2001:db8::', prefix_length=32, cidr='2001:db8::/32',
            is_active=True,
        )
        v4 = self._ip('198.51.100.30/32')
        published = set(published_queryset('ip').values_list('pk', flat=True))
        self.assertIn(v4.pk, published)

    def test_ids_are_deterministic_and_distinct_per_cidr(self):
        from apps.taxii.stix import indicator_id

        host = self._ip('198.51.100.40/32')
        block = self._ip('198.51.100.0/24', prefix=24)
        self.assertEqual(indicator_id(host), indicator_id(host))
        self.assertNotEqual(indicator_id(host), indicator_id(block))


class HashFeedTests(TestCase):
    """Hash Blacklist to file:hashes indicators."""

    def setUp(self):
        TaxiiCollection.objects.all().delete()

    def _hash(self, value, hash_type='unknown', **kw):
        from apps.hashlist.models import HashEntry
        return HashEntry.objects.create(
            hash_value=value, hash_type=hash_type,
            list_type=kw.pop('list_type', 'black'), **kw,
        )

    def test_algorithm_names_follow_the_stix_vocabulary(self):
        from apps.taxii.stix import entry_to_indicator

        cases = [
            ('md5',    'a' * 32,  'MD5'),
            ('sha1',   'b' * 40,  'SHA-1'),
            ('sha256', 'c' * 64,  'SHA-256'),
            ('sha512', 'd' * 128, 'SHA-512'),
        ]
        for hash_type, value, algo in cases:
            with self.subTest(hash_type=hash_type):
                entry = self._hash(value, hash_type)
                self.assertEqual(
                    entry_to_indicator(entry)['pattern'],
                    "[file:hashes.'" + algo + "' = '" + value + "']",
                )

    def test_unknown_type_is_inferred_from_length(self):
        from apps.taxii.stix import hash_algorithm

        self.assertEqual(hash_algorithm(self._hash('e' * 64)), 'SHA-256')
        self.assertEqual(hash_algorithm(self._hash('f' * 40)), 'SHA-1')

    def test_undeterminable_hash_is_not_published(self):
        """Publishing it under a guessed algorithm would create an indicator
        that silently matches nothing at the consumer."""
        from apps.taxii.stix import hash_algorithm, published_queryset

        junk = self._hash('abcdef0123')          # 10 chars, unknown type
        good = self._hash('a' * 64, 'sha256')

        self.assertIsNone(hash_algorithm(junk))
        published = set(published_queryset('hash').values_list('pk', flat=True))
        self.assertEqual(published, {good.pk})

    def test_queryset_mirrors_the_firewall_predicate(self):
        from apps.taxii.stix import published_queryset

        keep = self._hash('1' * 64, 'sha256')
        self._hash('2' * 64, 'sha256', is_active=False)
        self._hash('3' * 64, 'sha256', vt_unavailable=True)
        self._hash('4' * 64, 'sha256', list_type='white')

        published = set(published_queryset('hash').values_list('pk', flat=True))
        self.assertEqual(published, {keep.pk})

    def test_hash_value_is_lower_cased_in_the_pattern(self):
        from apps.taxii.stix import entry_to_indicator

        entry = self._hash('A' * 64, 'sha256')
        self.assertIn('a' * 64, entry_to_indicator(entry)['pattern'])


class FeedRegistryTests(TestCase):
    def test_every_feed_choice_has_a_queryset_and_a_default_title(self):
        """A choice without a mapper would let an operator create a
        collection that 500s on its first poll."""
        from apps.taxii.stix import adapter_for_feed, published_queryset

        for value, label in TaxiiCollection.FEED_CHOICES:
            with self.subTest(feed=value):
                self.assertIsNotNone(adapter_for_feed(value))
                published_queryset(value).count()   # must execute
                self.assertTrue(
                    TaxiiCollection.FEED_DEFAULTS.get(value, {}).get('title'),
                    label + ' has no default title for the Add form',
                )

    def test_unknown_feed_raises_rather_than_serving_the_wrong_list(self):
        from apps.taxii.stix import published_queryset

        with self.assertRaises(ValueError):
            published_queryset('nope')

    def test_a_row_from_an_unpublished_model_is_rejected(self):
        from apps.taxii.stix import indicator_id

        with self.assertRaises(ValueError):
            indicator_id(TaxiiCollection(api_root='x', title='x', feed='url'))


class IpCollectionOverHttpTests(TaxiiTestBase):
    """End-to-end: an `ip` collection really serves IP indicators."""

    def setUp(self):
        super().setUp()
        from apps.blacklist.models import BlacklistEntry, BlacklistGroup

        group, _ = BlacklistGroup.objects.get_or_create(
            name='30d', defaults={'label': '30 Days', 'is_published': True},
        )
        BlacklistEntry.objects.create(
            ip_address='198.51.100.77', prefix_length=32,
            cidr='198.51.100.77/32', group=group, reason='scanner',
        )
        self.ip_collection = TaxiiCollection.objects.create(
            api_root=ROOT, title='Malicious IP Addresses', feed='ip',
        )

    def _ip_objects_url(self):
        return f'/taxii/{ROOT}/collections/{self.ip_collection.uuid_str}/objects/'

    def test_objects_endpoint_serves_the_ip_feed(self):
        resp = self._get(self._ip_objects_url())
        self.assertEqual(resp.status_code, 200)
        body = json.loads(resp.content)
        self.assertEqual(body['type'], 'bundle')
        self.assertEqual(body['spec_version'], '2.0')
        patterns = [o['pattern'] for o in body['objects']]
        self.assertIn("[ipv4-addr:value = '198.51.100.77']", patterns)

    def test_the_two_collections_publish_different_lists(self):
        """Same api root, two collections, the subscriber picks. The URL
        collection must not leak IP indicators or vice versa."""
        URLEntry.objects.create(
            url_value='separate.example', list_type='black', is_active=True,
        )
        ip_body = json.loads(self._get(self._ip_objects_url()).content)
        url_body = json.loads(self._get(self._objects_url()).content)

        ip_patterns = ' '.join(o['pattern'] for o in ip_body['objects'])
        url_patterns = ' '.join(o['pattern'] for o in url_body['objects'])

        self.assertIn('ipv4-addr', ip_patterns)
        self.assertNotIn('domain-name', ip_patterns)
        self.assertIn('domain-name', url_patterns)
        self.assertNotIn('ipv4-addr', url_patterns)

    def test_both_collections_are_discoverable_under_one_api_root(self):
        resp = self._get(f'/taxii/{ROOT}/collections/')
        self.assertEqual(resp.status_code, 200)
        titles = {c['title'] for c in json.loads(resp.content)['collections']}
        self.assertIn('Malicious URLs & Domains', titles)
        self.assertIn('Malicious IP Addresses', titles)


class InlineScriptNonceTests(TestCase):
    """security_middleware drops `'unsafe-inline'` from `script-src`, so an
    inline <script> without the per-request nonce is silently refused by the
    browser. Nothing errors server-side and the page still renders — only the
    JavaScript is missing, which is how a bare <script> in the Add Collection
    form shipped with an empty Feed dropdown.

    `manage.py check` cannot see this, so it gets a test.
    """

    #: Django comments never reach the browser, so prose inside them that
    #: happens to mention a script tag is not a finding.
    _COMMENT_RE = re.compile(
        r'\{%\s*comment\s*%\}.*?\{%\s*endcomment\s*%\}|\{#.*?#\}',
        re.S,
    )

    def _templates(self):
        from pathlib import Path

        from django.conf import settings as dj_settings

        for d in dj_settings.TEMPLATES[0].get('DIRS', []):
            base = Path(d)
            for tpl in base.rglob('*.html'):
                text = self._COMMENT_RE.sub('', tpl.read_text(encoding='utf-8'))
                yield tpl.relative_to(base).as_posix(), text

    def test_csp_blocks_inline_script_without_a_nonce(self):
        """Guards the assumption this test rests on: if the policy ever gains
        'unsafe-inline' this test becomes noise and should be deleted."""
        from django.http import HttpResponse
        from django.test import RequestFactory

        from cybercavalry.security_middleware import SecurityHeadersMiddleware

        mw = SecurityHeadersMiddleware(lambda r: HttpResponse('ok'))
        req = RequestFactory(SERVER_NAME='localhost').get('/')
        csp = mw(req).get('Content-Security-Policy', '')
        self.assertIn('script-src', csp)
        self.assertNotIn("'unsafe-inline'", csp.split('style-src')[0])

    def test_every_inline_script_carries_the_nonce(self):
        tag_re = re.compile(r'<script\b[^>]*>', re.I)
        offenders = []
        for name, text in self._templates():
            for tag in tag_re.findall(text):
                if 'src=' in tag.lower():
                    continue          # external file, covered by 'self'
                if 'nonce=' not in tag.lower():
                    offenders.append(f'{name}: {tag}')
        self.assertEqual(
            offenders, [],
            'inline <script> without nonce="{{ csp_nonce }}" — the browser '
            'will refuse to run it:\n  ' + '\n  '.join(offenders),
        )


class FeedSelectRendersWithoutJsTests(TestCase):
    """The Feed dropdown must carry real <option> elements from the server.

    It used to be built by `<template x-for>`, which renders nothing at all
    if the Alpine component does not start — the failure mode that produced
    an empty dropdown.
    """

    def setUp(self):
        from apps.accounts.models import Role, UserProfile

        TaxiiCollection.objects.all().delete()
        role, _ = Role.objects.get_or_create(name='admin')
        self.admin = User(username='feed-select-admin', is_active=True)
        self.admin.set_unusable_password()
        self.admin.save()
        profile, _ = UserProfile.objects.get_or_create(user=self.admin)
        profile.role = role
        profile.save()

    def _render_add_form(self):
        from django.test import RequestFactory

        from apps.taxii import admin_views

        request = RequestFactory(SERVER_NAME='localhost').get(
            '/settings/taxii/collections/add/')
        request.user = User.objects.get(pk=self.admin.pk)
        return admin_views.collection_add(request).content.decode()

    def test_every_feed_has_a_server_rendered_option(self):
        html = self._render_add_form()
        for value, label in TaxiiCollection.FEED_CHOICES:
            with self.subTest(feed=value):
                self.assertIn(f'value="{value}"', html)
                self.assertIn(label, html)
        self.assertNotIn('x-for', html, 'options must not depend on Alpine')

    def test_the_rendered_nonce_matches_the_csp_header(self):
        """End-to-end proof of the fix: a static scan only shows the nonce
        attribute is present, not that it carries the value the browser is
        told to trust. Run the view through the real middleware and compare."""
        from django.test import RequestFactory

        from apps.taxii import admin_views
        from cybercavalry.security_middleware import SecurityHeadersMiddleware

        mw = SecurityHeadersMiddleware(admin_views.collection_add)
        request = RequestFactory(SERVER_NAME='localhost').get(
            '/settings/taxii/collections/add/')
        request.user = User.objects.get(pk=self.admin.pk)
        response = mw(request)

        in_page = re.search(r'<script nonce="([^"]*)">', response.content.decode())
        in_header = re.search(r"nonce-([^']*)", response['Content-Security-Policy'])
        self.assertIsNotNone(in_page, 'no nonce-bearing inline script rendered')
        self.assertTrue(in_page.group(1), 'nonce attribute rendered empty')
        self.assertEqual(in_page.group(1), in_header.group(1))

    def test_a_feed_is_preselected_server_side(self):
        html = self._render_add_form()
        self.assertIn('selected', html)

    def test_preselection_skips_a_feed_already_taken_in_that_root(self):
        """With `url` already published under the only known root, the form
        must open on a feed that can actually be created."""
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        TaxiiCollection.objects.create(api_root='urllist', title='U', feed='url')
        ctx = _add_form_context(RequestFactory().get('/'))
        self.assertEqual(ctx['form_data']['rootMode'], 'urllist')
        self.assertNotEqual(ctx['selected_feed'], 'url')
        self.assertIn(ctx['selected_feed'], {'ip', 'hash'})


class RootFeedHintTests(TestCase):
    """An API root named after one of the platform's lists pre-selects that
    list's feed, so the common case needs no second decision. It is a
    starting point only — the operator can still pick any free feed."""

    def setUp(self):
        TaxiiCollection.objects.all().delete()

    def test_each_root_name_implies_its_own_feed(self):
        cases = [('urllist', 'url'), ('blacklist', 'ip'), ('hashlist', 'hash')]
        for root, feed in cases:
            with self.subTest(api_root=root):
                self.assertEqual(TaxiiCollection.preferred_feed_for(root), feed)

    def test_hint_is_case_and_whitespace_insensitive(self):
        self.assertEqual(TaxiiCollection.preferred_feed_for('  BlackList '), 'ip')

    def test_default_root_implies_nothing_and_falls_back(self):
        """A catch-all root says nothing about which list it serves, so it
        just takes the first free feed."""
        self.assertEqual(
            TaxiiCollection.preferred_feed_for('default'),
            TaxiiCollection.FEED_CHOICES[0][0],
        )

    def test_unknown_root_falls_back_to_the_first_free_feed(self):
        self.assertEqual(
            TaxiiCollection.preferred_feed_for('partner-a', taken=['url']),
            'ip',
        )

    def test_hint_yields_when_that_feed_is_already_published_there(self):
        """Honouring the hint would offer a pair unique_together rejects."""
        self.assertEqual(
            TaxiiCollection.preferred_feed_for('blacklist', taken=['ip']),
            'url',
        )

    def test_full_root_has_no_preferred_feed(self):
        every = [v for v, _ in TaxiiCollection.FEED_CHOICES]
        self.assertEqual(TaxiiCollection.preferred_feed_for('urllist', taken=every), '')

    def test_form_preselects_the_hinted_feed_for_a_named_root(self):
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        ctx = _add_form_context(RequestFactory().get('/'), root_mode='blacklist')
        self.assertEqual(ctx['selected_feed'], 'ip')
        self.assertEqual(ctx['form_data']['feed'], 'ip')

    def test_form_payload_carries_the_hint_map_for_the_browser(self):
        """The dropdown re-derives the feed client-side when the root
        changes, so it needs the same mapping the server used."""
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        hints = _add_form_context(RequestFactory().get('/'))['form_data']['hints']
        self.assertEqual(hints.get('hashlist'), 'hash')
        self.assertEqual(hints.get('blacklist'), 'ip')
        self.assertEqual(hints.get('urllist'), 'url')

    def test_every_hint_points_at_a_real_feed(self):
        valid = {v for v, _ in TaxiiCollection.FEED_CHOICES}
        for root, feed in TaxiiCollection.ROOT_FEED_HINTS.items():
            with self.subTest(api_root=root):
                self.assertIn(feed, valid)

    def test_every_hinted_root_is_offered_in_the_dropdown(self):
        """A hint for a root nobody can pick would be dead configuration."""
        for root in TaxiiCollection.ROOT_FEED_HINTS:
            self.assertIn(root, TaxiiCollection.SUGGESTED_ROOTS)


class ServerSidePrefillTests(TestCase):
    """Title and description are rendered by the server, not filled in once
    Alpine boots, so the form is complete on first paint and still usable if
    the JavaScript never runs."""

    def setUp(self):
        from apps.accounts.models import Role, UserProfile

        TaxiiCollection.objects.all().delete()
        role, _ = Role.objects.get_or_create(name='admin')
        self.admin = User(username='prefill-admin', is_active=True)
        self.admin.set_unusable_password()
        self.admin.save()
        profile, _ = UserProfile.objects.get_or_create(user=self.admin)
        profile.role = role
        profile.save()

    def _render(self):
        from django.test import RequestFactory

        from apps.taxii import admin_views

        request = RequestFactory(SERVER_NAME='localhost').get(
            '/settings/taxii/collections/add/')
        request.user = User.objects.get(pk=self.admin.pk)
        return admin_views.collection_add(request).content.decode()

    def test_title_and_description_are_in_the_markup(self):
        # escape(): the URL feed's default title contains an ampersand, which
        # the template renders as &amp;.
        from django.utils.html import escape

        html = self._render()
        defaults = TaxiiCollection.FEED_DEFAULTS[TaxiiCollection.FEED_URL]
        self.assertIn('value="' + escape(defaults['title']) + '"', html)
        self.assertIn(escape(defaults['description']), html)

    def test_prefilled_values_are_not_marked_as_operator_edits(self):
        """Otherwise changing the Feed dropdown would refuse to refresh the
        title, because the form would think the operator typed it."""
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        data = _add_form_context(RequestFactory().get('/'))['form_data']
        self.assertTrue(data['title'])
        self.assertFalse(data['titleTouched'])
        self.assertFalse(data['descTouched'])

    def test_a_resubmitted_title_is_marked_as_an_operator_edit(self):
        """A re-render after a validation error must keep what was typed."""
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        data = _add_form_context(
            RequestFactory().get('/'), title='My own name', feed='url',
        )['form_data']
        self.assertEqual(data['title'], 'My own name')
        self.assertTrue(data['titleTouched'])

    def test_title_follows_the_feed_the_root_name_implies(self):
        from django.test import RequestFactory

        from apps.taxii.admin_views import _add_form_context

        for root, feed in TaxiiCollection.ROOT_FEED_HINTS.items():
            with self.subTest(api_root=root):
                ctx = _add_form_context(RequestFactory().get('/'), root_mode=root)
                self.assertEqual(ctx['selected_feed'], feed)
                self.assertEqual(
                    ctx['selected_title'],
                    TaxiiCollection.FEED_DEFAULTS[feed]['title'],
                )


class ActivityLogTests(TaxiiTestBase):
    """Every TAXII request must leave an ActivityLog row under an `api.`
    action.

    The rotating file log is not enough: the console reads the ActivityLog,
    and both Settings -> Activity Log's "API" type filter and the dashboard's
    Request Timeline select rows by the `api.` prefix. Before these rows
    existed, a subscriber could poll the server all day and the console would
    show nothing at all -- which is the regression this class exists to stop
    from coming back.
    """

    def setUp(self):
        super().setUp()
        from apps.settings_app.models import ActivityLog

        ActivityLog.objects.all().delete()
        self._seed_url_entry()

    def _seed_url_entry(self):
        """One published indicator, so `served`/`total` are not both zero."""
        return URLEntry.objects.create(url_value='audit.example', list_type='black')

    def _rows(self, action=None):
        from apps.settings_app.models import ActivityLog

        qs = ActivityLog.objects.all()
        return list(qs.filter(action=action) if action else qs)

    # ── the data-serving endpoints ──

    def test_objects_poll_is_recorded(self):
        resp = self._get(self._objects_url())
        self.assertEqual(resp.status_code, 200)
        rows = self._rows('api.taxii_objects')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].user.username, USER)
        self.assertEqual(rows[0].target_id, self.cid)

    def test_objects_row_records_what_was_served(self):
        """Without the counts the row cannot answer "is my subscriber
        actually receiving indicators?" -- only "did it connect?"."""
        self._get(self._objects_url())
        detail = self._rows('api.taxii_objects')[0].detail
        self.assertEqual(detail['root'], ROOT)
        self.assertEqual(detail['feed'], 'url')
        self.assertEqual(detail['served'], 1)
        self.assertEqual(detail['total'], 1)
        self.assertEqual(detail['status'], 200)

    def test_manifest_poll_is_recorded_with_counts(self):
        self._get(self._manifest_url())
        detail = self._rows('api.taxii_manifest')[0].detail
        self.assertEqual(detail['served'], 1)
        self.assertEqual(detail['feed'], 'url')

    def test_every_endpoint_writes_exactly_one_api_prefixed_row(self):
        from apps.settings_app.models import ActivityLog
        from apps.taxii import stix

        oid = next(stix.indicator_id(e) for e in stix.published_queryset('url'))

        urls = [
            '/taxii/',
            f'/taxii/{ROOT}/',
            f'/taxii/{ROOT}/collections/',
            f'/taxii/{ROOT}/collections/{self.cid}/',
            self._objects_url(),
            self._manifest_url(),
            f'{self._objects_url()}{oid}/',
        ]
        for url in urls:
            with self.subTest(url=url):
                ActivityLog.objects.all().delete()
                resp = self._get(url)
                self.assertEqual(resp.status_code, 200, url)
                rows = self._rows()
                self.assertEqual(len(rows), 1, f'{url} wrote {len(rows)} row(s)')
                self.assertTrue(
                    rows[0].action.startswith('api.'),
                    f'{url} logged {rows[0].action!r}, which the API filter and '
                    f'the Request Timeline would both miss',
                )

    def test_row_carries_the_request_context(self):
        self._get(self._objects_url() + '?added_after=2026-01-01T00:00:00Z',
                  HTTP_USER_AGENT='DDD/7.0')
        detail = self._rows('api.taxii_objects')[0].detail
        self.assertEqual(detail['method'], 'GET')
        self.assertIn('added_after', detail['body'])
        self.assertEqual(detail['user_agent'], 'DDD/7.0')

    # ── denials ──

    def test_missing_credentials_are_recorded_as_denied(self):
        resp = self.client.get(self._objects_url())
        self.assertEqual(resp.status_code, 401)
        rows = self._rows('api.taxii_denied')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].detail['status'], 401)
        self.assertEqual(rows[0].detail['endpoint'], 'objects')
        self.assertIsNone(rows[0].user)

    def test_bad_token_is_recorded_as_denied(self):
        resp = self.client.get(self._objects_url(),
                               **_auth_header(USER, 'not-the-real-token'))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(len(self._rows('api.taxii_denied')), 1)

    def test_wrong_role_is_recorded_as_denied(self):
        token = self._make_api_user('viewer-not-api', role_name='viewer')
        resp = self.client.get(self._objects_url(),
                               **_auth_header('viewer-not-api', token))
        self.assertEqual(resp.status_code, 403)
        rows = self._rows('api.taxii_denied')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].detail['status'], 403)

    # ── the quiet cases ──

    def test_disabled_server_records_nothing(self):
        """There is no subscriber activity to report, and a scanner probing a
        switched-off server should not be able to fill the audit log."""
        self._set('taxii.enabled', 'false', 'bool')
        self.assertEqual(self._get(self._objects_url()).status_code, 404)
        self.assertEqual(self._rows(), [])

    def test_a_client_error_is_still_recorded_with_its_status(self):
        resp = self._get(self._objects_url() + '?added_after=yesterday')
        self.assertEqual(resp.status_code, 400)
        rows = self._rows('api.taxii_objects')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].detail['status'], 400)

    def test_logging_failure_cannot_break_a_poll(self):
        """ActivityLog.log swallows its own errors; assert the feed survives
        one, because a broken audit write must never cost a subscriber its
        blacklist update."""
        from unittest.mock import patch

        with patch('apps.settings_app.models.ActivityLog.objects.create',
                   side_effect=RuntimeError('db gone')):
            resp = self._get(self._objects_url())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(json.loads(resp.content)['objects']), 1)
