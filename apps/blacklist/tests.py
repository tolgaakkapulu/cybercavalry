"""
Tests for AbuseIPDB enrichment metadata storage + display helpers.

Run: python manage.py test apps.blacklist
"""
from django.test import SimpleTestCase
from django.utils import timezone


class AbuseMetadataTests(SimpleTestCase):
    def _entry(self):
        from apps.blacklist.models import BlacklistEntry
        return BlacklistEntry(ip_address='1.2.3.4', cidr='1.2.3.4/32')

    def test_store_metadata_maps_response_fields(self):
        from apps.blacklist.abuseipdb_service import _store_metadata
        e, update_fields = self._entry(), []
        meta = {
            'abuseConfidenceScore': 90,
            'isp': 'Tencent Cloud Computing',
            'usageType': 'Data Center/Web Hosting/Transit',
            'domain': 'tencent.com',
            'hostnames': ['a.example.com', 'b.example.com'],
            'countryCode': 'CN',
            'countryName': 'China',
            'totalReports': 42,
            'lastReportedAt': '2026-05-20T12:34:56+00:00',
        }
        _store_metadata(e, meta, update_fields)
        self.assertEqual(e.abuse_isp, 'Tencent Cloud Computing')
        self.assertEqual(e.abuse_usage_type, 'Data Center/Web Hosting/Transit')
        self.assertEqual(e.abuse_domain, 'tencent.com')
        self.assertEqual(e.abuse_hostnames, ['a.example.com', 'b.example.com'])
        self.assertEqual(e.abuse_country_code, 'CN')
        self.assertEqual(e.abuse_country_name, 'China')
        self.assertEqual(e.abuse_total_reports, 42)
        self.assertIsNotNone(e.abuse_last_reported_at)
        self.assertEqual(e.abuse_last_reported_at.year, 2026)
        self.assertIn('abuse_isp', update_fields)
        self.assertIn('abuse_hostnames', update_fields)
        self.assertIn('abuse_total_reports', update_fields)
        self.assertIn('abuse_last_reported_at', update_fields)

    def test_total_reports_non_numeric_is_none(self):
        from apps.blacklist.abuseipdb_service import _store_metadata
        e = self._entry()
        _store_metadata(e, {'totalReports': None, 'lastReportedAt': None}, [])
        self.assertIsNone(e.abuse_total_reports)
        self.assertIsNone(e.abuse_last_reported_at)

    def test_missing_fields_default_to_empty(self):
        from apps.blacklist.abuseipdb_service import _store_metadata
        e = self._entry()
        _store_metadata(e, {'isp': 'OnlyISP'}, [])
        self.assertEqual(e.abuse_isp, 'OnlyISP')
        self.assertEqual(e.abuse_usage_type, '')
        self.assertEqual(e.abuse_domain, '')
        self.assertEqual(e.abuse_hostnames, [])

    def test_hostnames_capped_at_ten(self):
        from apps.blacklist.abuseipdb_service import _store_metadata
        e = self._entry()
        _store_metadata(e, {'hostnames': [f'h{i}.example.com' for i in range(20)]}, [])
        self.assertEqual(len(e.abuse_hostnames), 10)

    def test_none_meta_is_noop(self):
        from apps.blacklist.abuseipdb_service import _store_metadata
        e, uf = self._entry(), []
        _store_metadata(e, None, uf)
        self.assertEqual(uf, [])
        self.assertEqual(e.abuse_isp, '')

    def test_country_display(self):
        e = self._entry()
        e.abuse_country_name, e.abuse_country_code = 'China', 'CN'
        self.assertEqual(e.abuse_country_display, 'China (CN)')
        e.abuse_country_name = ''
        self.assertEqual(e.abuse_country_display, 'CN')

    def test_hostnames_display(self):
        e = self._entry()
        e.abuse_hostnames = ['x.com', 'y.com']
        self.assertEqual(e.abuse_hostnames_display, 'x.com, y.com')

    def test_has_abuse_intel_gate(self):
        e = self._entry()
        self.assertFalse(e.has_abuse_intel)            # not checked yet
        e.abuse_checked_at = timezone.now()
        self.assertFalse(e.has_abuse_intel)            # checked but no enrichment
        e.abuse_isp = 'SomeISP'
        self.assertTrue(e.has_abuse_intel)             # has data → tooltip shows
