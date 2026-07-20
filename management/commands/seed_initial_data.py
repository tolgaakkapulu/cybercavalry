"""
Management command: python manage.py seed_initial_data
Seeds default BlacklistGroups, Roles, and Settings.
Safe to re-run (uses get_or_create).
"""
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Seed initial platform data (roles, groups, settings)'

    def handle(self, *args, **options):
        self.seed_roles()
        self.seed_blacklist_groups()
        self.seed_settings()
        self.seed_admin_user()
        self.stdout.write(self.style.SUCCESS('Initial data seeded successfully.'))

    def seed_roles(self):
        from apps.accounts.models import Role
        roles = [
            ('admin', 'Full platform access including settings and user management.'),
            ('operator', 'Manage blacklist and whitelist. No settings or user management.'),
            ('viewer', 'Read-only access to blacklist, whitelist, and dashboard.'),
            ('api_user', 'API access only. Can report IPs and fetch blacklist.'),
        ]
        for name, desc in roles:
            role, created = Role.objects.get_or_create(name=name, defaults={'description': desc})
            status = 'created' if created else 'exists'
            self.stdout.write(f"  Role '{name}': {status}")

    def seed_blacklist_groups(self):
        from apps.blacklist.models import BlacklistGroup
        groups = [
            {'name': '24h', 'label': '24 Hours', 'default_duration_hours': 24, 'is_published': True, 'order': 1},
            {'name': '30d', 'label': '30 Days', 'default_duration_hours': 720, 'is_published': True, 'order': 2},
            {'name': 'permanent', 'label': 'Permanent', 'default_duration_hours': None, 'is_published': True, 'order': 3},
        ]
        for g in groups:
            obj, created = BlacklistGroup.objects.get_or_create(
                name=g['name'],
                defaults={k: v for k, v in g.items() if k != 'name'}
            )
            status = 'created' if created else 'exists'
            self.stdout.write(f"  BlacklistGroup '{g['name']}': {status}")

    def seed_settings(self):
        from apps.settings_app.models import Setting
        defaults = [
            # LDAP
            ('ldap.enabled', 'false', 'bool', 'ldap', 'Enable LDAP authentication', False),
            ('ldap.server_uri', 'ldap://your-ldap:389', 'str', 'ldap', 'LDAP server URI', False),
            ('ldap.bind_dn', '', 'str', 'ldap', 'Service account DN for LDAP bind', False),
            ('ldap.bind_password', '', 'str', 'ldap', 'Service account password', True),
            ('ldap.user_search_base', 'ou=users,dc=example,dc=com', 'str', 'ldap', 'LDAP user search base', False),
            ('ldap.user_search_filter', '(sAMAccountName=%(user)s)', 'str', 'ldap', 'LDAP user search filter', False),
            ('ldap.user_attr_map', '{"first_name": "givenName", "last_name": "sn", "email": "mail"}', 'json', 'ldap', 'LDAP attribute mapping', False),
            ('ldap.group_map', '{}', 'json', 'ldap', 'LDAP group to CYBERCavalry role mapping (JSON)', False),
            ('ldap.use_ssl', 'false', 'bool', 'ldap', 'Use SSL/TLS for LDAP connection', False),
            # API
            ('api.require_auth_for_publish', 'false', 'bool', 'api', 'Require token auth for /api/v1/blacklist/ endpoints', False),
            ('api.rate_limit_rpm', '60', 'int', 'api', 'API rate limit: requests per minute per token', False),
            ('api.trust_proxy', 'false', 'bool', 'api', 'Trust X-Forwarded-For header (enable if behind a proxy)', False),
            # General
            ('general.platform_name', 'CYBERCavalry', 'str', 'general', 'Platform display name', False),
            ('general.items_per_page', '50', 'int', 'general', 'Default items per page in lists', False),
        ]
        for key, value, vtype, category, description, is_secret in defaults:
            obj, created = Setting.objects.get_or_create(
                key=key,
                defaults={
                    'value': value,
                    'value_type': vtype,
                    'category': category,
                    'description': description,
                    'is_secret': is_secret,
                }
            )
            status = 'created' if created else 'exists'
            self.stdout.write(f"  Setting '{key}': {status}")

    def seed_admin_user(self):
        from django.contrib.auth import get_user_model
        from apps.accounts.models import Role, UserProfile
        User = get_user_model()
        admin_role = Role.objects.filter(name='admin').first()
        user, created = User.objects.get_or_create(
            username='admin',
            defaults={'is_superuser': True, 'is_staff': True, 'email': ''},
        )
        if created:
            user.set_password('admin')
            user.save()
            self.stdout.write("  User 'admin': created (password: admin)")
        else:
            self.stdout.write("  User 'admin': exists")
        # Assign the admin role if the profile has no role yet
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if admin_role and profile.role != admin_role:
            profile.role = admin_role
            profile.save(update_fields=['role'])
            self.stdout.write("  User 'admin' role: assigned admin")
