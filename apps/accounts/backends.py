import logging
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend

logger = logging.getLogger(__name__)


class LDAPAuthBackend:
    """
    LDAP authentication backend. Falls back to local auth if LDAP is disabled
    or if connection fails.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        from apps.settings_app.cache import SettingsCache

        if not SettingsCache.get('ldap.enabled', False):
            return None

        # Reject empty / whitespace-only passwords. A blank password can trigger
        # an LDAP *unauthenticated bind* that some directory servers answer with
        # success — that would be an auth bypass. This guard is the first defense;
        # _ldap_authenticate adds an explicit anonymous-bind rejection too.
        if not username or not password or not password.strip():
            return None

        try:
            return self._ldap_authenticate(username, password)
        except Exception as e:
            logger.warning(f"LDAP auth failed for {username}: {e}")
            return None

    def _ldap_authenticate(self, username, password):
        from apps.settings_app.cache import SettingsCache
        from apps.accounts.models import UserProfile, Role
        import json

        try:
            import ldap3
        except ImportError:
            logger.error("ldap3 not installed. Install it with: pip install ldap3")
            return None

        server_uri = SettingsCache.get('ldap.server_uri', '')
        bind_dn = SettingsCache.get('ldap.bind_dn', '')
        bind_password = SettingsCache.get('ldap.bind_password', '')
        search_base = SettingsCache.get('ldap.user_search_base', '')
        search_filter = SettingsCache.get('ldap.user_search_filter', '(sAMAccountName=%(user)s)')
        attr_map_str = SettingsCache.get('ldap.user_attr_map', '{}')
        group_map_str = SettingsCache.get('ldap.group_map', '{}')
        use_ssl = SettingsCache.get('ldap.use_ssl', False)

        if not server_uri:
            logger.warning("LDAP server URI not configured")
            return None

        def _to_dict(val):
            if isinstance(val, dict):
                return val
            try:
                return json.loads(val) if val else {}
            except (json.JSONDecodeError, TypeError):
                return {}

        attr_map = _to_dict(attr_map_str)
        group_map = _to_dict(group_map_str)

        # Parse server URI
        if server_uri.startswith('ldaps://'):
            use_ssl = True
            host = server_uri.replace('ldaps://', '')
            port = 636
        elif server_uri.startswith('ldap://'):
            host = server_uri.replace('ldap://', '')
            port = 389
        else:
            host = server_uri
            port = 636 if use_ssl else 389

        # Warn loudly when binding over plaintext LDAP — the service-account bind
        # password and each user's password travel unencrypted. Prefer ldaps://.
        if not use_ssl:
            logger.warning(
                "LDAP is configured over plaintext (no TLS) — bind credentials and "
                "user passwords are sent unencrypted. Use an ldaps:// URI or enable SSL."
            )

        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            port = int(port_str)

        server = ldap3.Server(
            host,
            port=port,
            use_ssl=use_ssl,
            get_info=ldap3.ALL,
        )

        # Service account bind
        conn = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

        # Search for user — escape special LDAP characters to prevent injection
        safe_username = ldap3.utils.conv.escape_filter_chars(username)
        search_filter_str = search_filter % {'user': safe_username}

        # Multi-base support: admins can configure several bases separated by
        # `;` (e.g. "OU=Staff,DC=corp,DC=local;OU=Contractors,DC=corp,DC=local").
        # We probe them in order and stop at the first hit so the user can only
        # exist under one OU at a time — duplicates would be ambiguous anyway.
        bases = [b.strip() for b in search_base.split(';') if b.strip()]
        if not bases:
            logger.warning("LDAP user_search_base not configured")
            return None

        user_entry = None
        matched_base = ''
        for base in bases:
            conn.search(
                search_base=base,
                search_filter=search_filter_str,
                attributes=list(attr_map.values()) + ['memberOf'],
            )
            if conn.entries:
                user_entry = conn.entries[0]
                matched_base = base
                break

        if user_entry is None:
            logger.debug(f"LDAP: user {username} not found in {len(bases)} base(s)")
            return None

        user_dn = str(user_entry.entry_dn)

        # Bind as the user to verify password. Force SIMPLE auth so an empty/odd
        # password cannot silently become an anonymous bind.
        user_conn = ldap3.Connection(server, user=user_dn, password=password,
                                     authentication=ldap3.SIMPLE)
        if not user_conn.bind():
            logger.debug(f"LDAP: password check failed for {username}")
            return None
        # Defense in depth: reject if the server granted an anonymous/unauthenticated
        # bind instead of a real authenticated one.
        if getattr(user_conn, 'authentication', None) == getattr(ldap3, 'ANONYMOUS', 'ANONYMOUS'):
            logger.warning(f"LDAP: rejected anonymous bind for {username}")
            return None

        # Get or create Django user
        email = ''
        first_name = ''
        last_name = ''

        for django_attr, ldap_attr in attr_map.items():
            try:
                val = str(user_entry[ldap_attr])
                if django_attr == 'email':
                    email = val
                elif django_attr == 'first_name':
                    first_name = val
                elif django_attr == 'last_name':
                    last_name = val
            except Exception:
                pass

        user, created = User.objects.get_or_create(
            username=username,
            defaults={'email': email, 'first_name': first_name, 'last_name': last_name}
        )

        if not created:
            user.email = email or user.email
            user.first_name = first_name or user.first_name
            user.last_name = last_name or user.last_name
            user.save(update_fields=['email', 'first_name', 'last_name'])

        # Map LDAP groups to roles
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.auth_source = UserProfile.AUTH_LDAP
        # GROUP label = first OU of the search base that picked this user up
        # (SECURITY, NETWORK, …). Keeps the Users page consistent with the
        # Settings → LDAP base list, and stays correct if AD nests sub-OUs.
        from apps.accounts.ldap_utils import first_ou_from_dn
        profile.ldap_ou = first_ou_from_dn(matched_base)

        try:
            member_of = [str(g) for g in user_entry.memberOf] if hasattr(user_entry, 'memberOf') else []
            for ldap_group, role_name in group_map.items():
                if any(ldap_group.lower() in g.lower() for g in member_of):
                    role, _ = Role.objects.get_or_create(name=role_name)
                    profile.role = role
                    break
        except Exception as e:
            logger.warning(f"LDAP group mapping failed: {e}")

        profile.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
