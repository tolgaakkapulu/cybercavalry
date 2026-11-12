"""TAXII 2.0 server — publishes the URL Blacklist as STIX 2.0 indicators.

Purely additive to the existing `GET /api/v1/urllist/` feed the firewall
consumes: different URL prefix (`/taxii/`), different app, different auth,
same read-only `URLEntry` data. Nothing in `apps.api` is touched, so the
firewall path cannot be affected by anything in here.

Built against OASIS TAXII 2.0 Committee Specification 01 (19 July 2017)
because that is the version Trend Micro Deep Discovery Director
(Consolidated Mode) 5.3 speaks — its "Add Intelligence Feed" screen
offers TAXII 1.x and 2.0 only, and links that exact spec as the
compatibility reference.
"""
default_app_config = 'apps.taxii.apps.TaxiiConfig'
