import json
import logging
import re
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.cache import cache
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator

from .forms import LoginForm, UserCreateForm, UserRoleForm, validate_password_policy
from .models import UserProfile, Role
from .decorators import role_required, login_required_custom
from apps.settings_app.models import ActivityLog

logger = logging.getLogger(__name__)

# ── Brute-force login protection ─────────────────────────────

def _get_bf_settings():
    """Read lockout config from DB settings; fall back to safe defaults."""
    try:
        from apps.settings_app.cache import SettingsCache
        max_attempts = int(SettingsCache.get('security.lockout_attempts', 5) or 5)
        duration_min = int(SettingsCache.get('security.lockout_duration', 5) or 5)
    except Exception:
        max_attempts, duration_min = 5, 5
    return max_attempts, duration_min * 60   # (attempts, window_seconds)


def _bf_key(kind: str, identifier: str) -> str:
    return f'login_{kind}:{identifier}'


def _is_locked_out(identifier: str) -> bool:
    return bool(cache.get(_bf_key('lockout', identifier)))


# Per-IP failures tolerate more attempts than a single account (multiple
# legitimate users may share an egress IP), but still stop password spraying
# (one IP hammering many usernames).
_IP_LOCKOUT_MULTIPLIER = 5


def _record_failure(identifier: str, max_attempts: int = None) -> None:
    cfg_max, window = _get_bf_settings()
    if max_attempts is None:
        max_attempts = cfg_max
    key = _bf_key('attempts', identifier)
    # Fixed (non-sliding) window: set TTL only when the counter is first created,
    # so a steady trickle of attempts cannot keep extending the window and evade
    # the lockout. Uses add()+incr() — the same correct pattern as api/auth.py.
    if cache.add(key, 1, window):
        attempts = 1
    else:
        try:
            attempts = cache.incr(key)
        except ValueError:
            cache.add(key, 1, window)
            attempts = 1
    if attempts >= max_attempts:
        cache.set(_bf_key('lockout', identifier), True, window)
        logger.warning(
            f"Brute-force lockout triggered for '{identifier}' "
            f"after {attempts} failures ({window // 60} min)."
        )


def _clear_failures(identifier: str) -> None:
    cache.delete(_bf_key('attempts', identifier))
    cache.delete(_bf_key('lockout', identifier))


class LoginView(View):
    template_name = 'accounts/login.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:index')
        return render(request, self.template_name, {'form': LoginForm()})

    def post(self, request):
        ip       = getattr(request, 'client_ip', '')
        username = request.POST.get('username', '').strip()

        # Lockout if EITHER the username OR the source IP is locked. The per-IP
        # counter (higher threshold) stops password spraying across many usernames.
        if (username and _is_locked_out(f'user:{username}')) or (ip and _is_locked_out(f'ip:{ip}')):
            logger.warning(f"Login blocked (lockout) for '{username}' from {ip}")
            ActivityLog.log(None, 'auth.login.blocked', 'User', '',
                         {'ip': ip, 'username': username, 'reason': 'brute_force_lockout'}, ip)
            _, window = _get_bf_settings()
            duration_min = window // 60
            lockout_msg = (
                f"Too many failed login attempts. "
                f"Please try again in {duration_min} minute{'s' if duration_min != 1 else ''}."
            )
            return render(request, self.template_name, {
                'form': LoginForm(),
                'lockout_message': lockout_msg,
            })

        form = LoginForm(request=request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            _clear_failures(f'user:{username}')
            if ip:
                _clear_failures(f'ip:{ip}')
            login(request, user)

            if not form.cleaned_data.get('remember_me'):
                request.session.set_expiry(0)

            logger.info(f"Login: {user.username} from {ip}")
            ActivityLog.log(user, 'auth.login.success', 'User', str(user.pk),
                         {'username': user.username}, ip)
            return redirect('dashboard:index')

        # Record failure for both the username and the source IP (spraying guard)
        if username:
            _record_failure(f'user:{username}')
        if ip:
            cfg_max, _ = _get_bf_settings()
            _record_failure(f'ip:{ip}', max_attempts=cfg_max * _IP_LOCKOUT_MULTIPLIER)
        logger.warning(f"Failed login attempt for '{username}' from {ip}")
        ActivityLog.log(None, 'auth.login.failed', 'User', '',
                     {'username': username}, ip)
        return render(request, self.template_name, {'form': form})


def logout_view(request):
    if request.user.is_authenticated:
        ip = getattr(request, 'client_ip', '')
        logger.info(f"Logout: {request.user.username}")
        ActivityLog.log(request.user, 'auth.logout', 'User', str(request.user.pk),
                     {'username': request.user.username}, ip)
    logout(request)
    return redirect('accounts:login')


@login_required_custom
def api_reference(request):
    """GET /accounts/api-reference/ — API documentation page."""
    from django.core.exceptions import PermissionDenied
    from apps.accounts.api_docs import get_endpoints
    profile = request.user.profile
    if profile.role is None or not profile.role.can_use_api:
        raise PermissionDenied
    return render(request, 'accounts/api_reference.html', {
        'profile':   profile,
        'endpoints': get_endpoints(),
    })


@login_required_custom
def api_reference_pdf(request):
    """GET /accounts/api-reference/export-pdf/ — Download API Reference as PDF."""
    from django.core.exceptions import PermissionDenied
    from django.http import HttpResponse
    from apps.reports.pdf_generator import generate_api_reference
    from django.utils import timezone
    from apps.settings_app.models import ActivityLog

    profile = request.user.profile
    if profile.role is None or not profile.role.can_use_api:
        raise PermissionDenied

    _full = request.user.get_full_name()
    _generated_by = f'{request.user.username} ({_full})' if _full else request.user.username
    pdf_bytes = generate_api_reference(_generated_by)
    ts = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
    from apps.settings_app.branding import brand_filename_prefix
    filename = f'{brand_filename_prefix()}_api_reference_{ts}.pdf'
    ActivityLog.log(request.user, 'report.download', None, None,
                    {'report_type': 'api_reference', 'filename': filename},
                    getattr(request, 'client_ip', ''))
    resp = HttpResponse(pdf_bytes, content_type='application/pdf')
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp


@login_required_custom
def profile_view(request):
    from apps.settings_app.models import ActivityLog
    from apps.blacklist.models import BlacklistEntry
    from apps.whitelist.models import WhitelistEntry
    from apps.hashlist.models import HashEntry

    profile = request.user.profile
    total_actions = ActivityLog.objects.filter(user=request.user).count()

    # Last login IP: most recent auth.login.success log entry
    last_login_log = (
        ActivityLog.objects.filter(user=request.user, action='auth.login.success')
        .order_by('-timestamp').first()
    )
    last_login_ip = last_login_log.ip_address if last_login_log else None

    # Blacklist counts by this user
    bl_qs = BlacklistEntry.objects.filter(added_by=request.user)
    blacklist_active   = bl_qs.filter(is_active=True).count()
    blacklist_inactive = bl_qs.filter(is_active=False).count()

    # Whitelist counts by this user
    wl_qs = WhitelistEntry.objects.filter(added_by=request.user)
    whitelist_active   = wl_qs.filter(is_active=True).count()
    whitelist_inactive = wl_qs.filter(is_active=False).count()

    # Hash blacklist counts by this user
    hl_qs = HashEntry.objects.filter(added_by=request.user, list_type='black')
    hashlist_active   = hl_qs.filter(is_active=True).count()
    hashlist_inactive = hl_qs.filter(is_active=False).count()

    return render(request, 'accounts/profile.html', {
        'profile': profile,
        'total_actions': total_actions,
        'last_login_ip': last_login_ip,
        'blacklist_active': blacklist_active,
        'blacklist_inactive': blacklist_inactive,
        'whitelist_active': whitelist_active,
        'whitelist_inactive': whitelist_inactive,
        'hashlist_active': hashlist_active,
        'hashlist_inactive': hashlist_inactive,
    })


@login_required_custom
@role_required('admin')
def user_list(request):
    from django.db.models import Q, Case, When, IntegerField
    status = request.GET.get('status', 'active')
    search = request.GET.get('search', '').strip()

    users = User.objects.select_related('profile__role')

    # Non-superusers cannot see the superuser account
    if not request.user.is_superuser:
        users = users.filter(is_superuser=False)

    if search:
        # Pure-digit query also matches the row's primary key so an admin can
        # paste an ID from the activity-log into the search box. Group label
        # (`ldap_ou`) is also searchable so typing "SECURITY" or "NETWORK"
        # filters the table to that LDAP base.
        q = (Q(username__icontains=search)
             | Q(email__icontains=search)
             | Q(profile__ldap_ou__icontains=search))
        if search.isdigit():
            q |= Q(pk=int(search))
        users = users.filter(q)

    # Counts per status (after search/superuser filters, before status filter)
    count_active   = users.filter(is_active=True).count()
    count_inactive = users.filter(is_active=False).count()
    count_all      = count_active + count_inactive

    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)

    # Superuser always at the top, rest alphabetical
    users = users.annotate(
        _is_super=Case(When(is_superuser=True, then=0), default=1, output_field=IntegerField())
    ).order_by('_is_super', 'username')

    try:
        from apps.settings_app.cache import SettingsCache
        pw_policy = {
            'min_length':        int(SettingsCache.get('security.password_min_length', 8) or 8),
            'require_uppercase': SettingsCache.get('security.password_require_uppercase', True),
            'require_lowercase': SettingsCache.get('security.password_require_lowercase', True),
            'require_digits':    SettingsCache.get('security.password_require_digits', True),
            'require_symbols':   SettingsCache.get('security.password_require_symbols', True),
        }
    except Exception:
        pw_policy = {'min_length': 8, 'require_uppercase': True, 'require_lowercase': True,
                     'require_digits': True, 'require_symbols': True}

    return render(request, 'accounts/user_list.html', {
        'users': users,
        'status': status,
        'search': search,
        'count_active': count_active,
        'count_inactive': count_inactive,
        'count_all': count_all,
        'roles': Role.objects.all(),
        'pw_policy': pw_policy,
    })


@login_required_custom
@role_required('admin')
def user_bulk_activate(request):
    if request.method == 'POST':
        ids = request.POST.getlist('user_ids')
        if not ids:
            messages.warning(request, "No users selected.")
            return redirect('accounts:user_list')
        count = 0
        for uid in ids:
            try:
                u = User.objects.get(pk=uid)
                # Non-superusers may not (re)activate superuser accounts —
                # mirrors user_list hiding superusers and user_bulk_deactivate.
                if u.is_superuser and not request.user.is_superuser:
                    continue
                if not u.is_active:
                    u.is_active = True
                    u.save()
                    ActivityLog.log(request.user, 'user.activate', 'User', str(u.pk),
                                 _user_audit_snapshot(u), getattr(request, 'client_ip', ''))
                    count += 1
            except User.DoesNotExist:
                pass
        messages.success(request, f"{count} user{'s' if count != 1 else ''} activated.")
    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def user_bulk_deactivate(request):
    if request.method == 'POST':
        ids = request.POST.getlist('user_ids')
        if not ids:
            messages.warning(request, "No users selected.")
            return redirect('accounts:user_list')
        count = 0
        for uid in ids:
            try:
                u = User.objects.get(pk=uid)
                if u == request.user or u.is_superuser:
                    continue  # skip self and superusers
                if u.is_active:
                    u.is_active = False
                    u.save()
                    ActivityLog.log(request.user, 'user.deactivate', 'User', str(u.pk),
                                 _user_audit_snapshot(u), getattr(request, 'client_ip', ''))
                    count += 1
            except User.DoesNotExist:
                pass
        messages.success(request, f"{count} user{'s' if count != 1 else ''} deactivated.")
    return redirect('accounts:user_list')


def _user_audit_snapshot(user):
    """Build a per-user audit-log payload — the full visible state of an account
    (name, e-mail, role, LDAP group, auth source, key timestamps). Captured by
    every user-mutation view (create/update/activate/deactivate/delete/import)
    so an admin can reconstruct what the account looked like at log time."""
    profile = getattr(user, 'profile', None)
    role_name = ''
    auth_source = ''
    ldap_ou = ''
    if profile is not None:
        try:
            role_name = profile.role.name if profile.role_id else ''
        except Exception:
            role_name = ''
        auth_source = getattr(profile, 'auth_source', '') or ''
        ldap_ou = getattr(profile, 'ldap_ou', '') or ''
    return {
        'username':     user.username,
        'first_name':   user.first_name or '',
        'last_name':    user.last_name or '',
        'full_name':    user.get_full_name() or '',
        'email':        user.email or '',
        'role':         role_name,
        'auth_source':  auth_source,
        'group':        ldap_ou,
        'is_superuser': bool(user.is_superuser),
        'date_joined':  user.date_joined.isoformat() if user.date_joined else None,
        'last_login':   user.last_login.isoformat() if user.last_login else None,
    }


@login_required_custom
def user_bulk_delete(request):
    """Permanently delete selected inactive users. Mirrors `user_delete`:
    superuser-only, refuses to touch active accounts, the actor's own row, or
    other superusers, and writes one `user.delete` log per removed account.
    """
    if not request.user.is_superuser:
        messages.error(request, "Only the system administrator can delete users.")
        return redirect('accounts:user_list')
    if request.method != 'POST':
        return redirect('accounts:user_list')

    ids = request.POST.getlist('user_ids')
    if not ids:
        messages.warning(request, "No users selected.")
        return redirect('accounts:user_list')

    deleted     = 0
    skipped_active = 0
    skipped_other  = 0
    ip = getattr(request, 'client_ip', '')
    for uid in ids:
        try:
            u = User.objects.get(pk=uid)
        except User.DoesNotExist:
            continue
        if u == request.user or u.is_superuser:
            skipped_other += 1
            continue
        if u.is_active:
            skipped_active += 1
            continue
        snap = _user_audit_snapshot(u)
        # Log BEFORE delete so the row's pk is still resolvable in audit context.
        ActivityLog.log(request.user, 'user.delete', 'User', str(u.pk), snap, ip)
        u.delete()
        deleted += 1

    if deleted:
        messages.success(request, f"{deleted} user{'s' if deleted != 1 else ''} permanently deleted.")
    if skipped_active:
        messages.warning(request, f"{skipped_active} active user{'s' if skipped_active != 1 else ''} skipped — deactivate before deleting.")
    if skipped_other:
        messages.warning(request, f"{skipped_other} protected account{'s' if skipped_other != 1 else ''} skipped (your own / superuser).")
    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def user_create(request):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    if request.method == 'POST':
        form = UserCreateForm(request.POST)
        if form.is_valid():
            user = form.save()
            ActivityLog.log(request.user, 'user.create', 'User', str(user.pk),
                         _user_audit_snapshot(user),
                         getattr(request, 'client_ip', ''))
            if is_ajax:
                return JsonResponse({'ok': True})
            messages.success(request, f"User '{user.username}' created successfully.")
        else:
            errors = []
            for field, errs in form.errors.items():
                for e in errs:
                    errors.append(e)
            if is_ajax:
                return JsonResponse({'ok': False, 'error': errors[0] if errors else 'Validation failed.'})
            for e in errors:
                messages.error(request, e)
    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def user_set_role(request, user_id):
    target_user = get_object_or_404(User, pk=user_id)
    profile = target_user.profile

    if request.method == 'POST':
        form = UserRoleForm(request.POST)
        if form.is_valid():
            old_role = profile.role.name if profile.role else None
            new_role = form.cleaned_data['role']
            profile.role = new_role
            profile.save()

            action = 'user.role.remove' if new_role is None else 'user.role.assign'
            ActivityLog.log(request.user, action, 'User', str(target_user.pk),
                         {'username': target_user.username,
                          'old_role': old_role,
                          'new_role': new_role.name if new_role else None},
                         getattr(request, 'client_ip', ''))

            messages.success(request, f"Role updated for '{target_user.username}'.")
        else:
            messages.error(request, "Invalid role selection.")

    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def user_toggle_active(request, user_id):
    if request.method == 'POST':
        target_user = get_object_or_404(User, pk=user_id)
        if target_user.is_superuser:
            messages.error(request, "The administrator account cannot be deactivated.")
        elif target_user == request.user:
            messages.error(request, "You cannot deactivate your own account.")
        else:
            target_user.is_active = not target_user.is_active
            target_user.save()
            status = "activated" if target_user.is_active else "deactivated"
            action = 'user.activate' if target_user.is_active else 'user.deactivate'
            toggle_detail = _user_audit_snapshot(target_user)
            toggle_detail['status'] = status
            ActivityLog.log(request.user, action, 'User', str(target_user.pk),
                         toggle_detail, getattr(request, 'client_ip', ''))
            messages.success(request, f"User '{target_user.username}' {status}.")
    return redirect('accounts:user_list')


@login_required_custom
def user_delete(request, user_id):
    if not request.user.is_superuser:
        messages.error(request, "Only the system administrator can delete users.")
        return redirect('accounts:user_list')
    if request.method == 'POST':
        target_user = get_object_or_404(User, pk=user_id)
        if target_user.is_active:
            messages.error(request, f"Only inactive users can be deleted. Deactivate '{target_user.username}' first.")
        elif target_user == request.user:
            messages.error(request, "You cannot delete your own account.")
        elif target_user.is_superuser:
            messages.error(request, "Superuser accounts cannot be deleted.")
        else:
            username = target_user.username
            snap = _user_audit_snapshot(target_user)
            ActivityLog.log(request.user, 'user.delete', 'User', str(target_user.pk),
                         snap, getattr(request, 'client_ip', ''))
            target_user.delete()
            messages.success(request, f"User '{username}' permanently deleted.")
    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def ldap_users_import(request):
    """
    GET  → test LDAP connection and return list of LDAP users not yet in Django.
    POST → create selected users (LDAP auth, no role).
    """
    from apps.settings_app.cache import SettingsCache

    # ── shared: read & validate LDAP settings ──────────────────────
    if not SettingsCache.get('ldap.enabled', False):
        return JsonResponse({
            'ok': False, 'error': 'ldap_disabled',
            'message': 'LDAP is not enabled. Please configure LDAP settings first.',
        })

    server_uri = SettingsCache.get('ldap.server_uri', '')
    if not server_uri:
        return JsonResponse({
            'ok': False, 'error': 'ldap_not_configured',
            'message': 'LDAP Server URI is not set. Please fill in the LDAP settings.',
        })

    try:
        import ldap3
    except ImportError:
        return JsonResponse({
            'ok': False, 'error': 'ldap3_missing',
            'message': 'ldap3 library is not installed on the server.',
        })

    bind_dn       = SettingsCache.get('ldap.bind_dn', '')
    bind_password = SettingsCache.get('ldap.bind_password', '')
    search_base   = SettingsCache.get('ldap.user_search_base', '')
    search_filter = SettingsCache.get('ldap.user_search_filter', '(sAMAccountName=%(user)s)')
    attr_map_raw  = SettingsCache.get('ldap.user_attr_map', '{}')
    use_ssl       = SettingsCache.get('ldap.use_ssl', False)

    def _to_dict(val):
        if isinstance(val, dict):
            return val
        try:
            return json.loads(val) if val else {}
        except Exception:
            return {}

    attr_map = _to_dict(attr_map_raw)

    # Parse host / port from URI
    if server_uri.startswith('ldaps://'):
        use_ssl = True
        host = server_uri[len('ldaps://'):]
        port = 636
    elif server_uri.startswith('ldap://'):
        host = server_uri[len('ldap://'):]
        port = 389
    else:
        host = server_uri
        port = 636 if use_ssl else 389

    if ':' in host:
        host, port_str = host.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            pass

    # Detect which LDAP attribute holds the login username
    m = re.match(r'\((\w+)=%\(user\)s\)', search_filter.strip())
    username_ldap_attr = m.group(1) if m else 'sAMAccountName'

    # All LDAP attributes we want to fetch
    extra_attrs = [a for a in attr_map.values() if a != username_ldap_attr]
    ldap_attrs  = list(dict.fromkeys([username_ldap_attr] + extra_attrs))

    # ── open connection ─────────────────────────────────────────────
    try:
        server = ldap3.Server(host, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)
        conn   = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
    except Exception as exc:
        return JsonResponse({
            'ok': False, 'error': 'connection_failed',
            'message': f'LDAP connection failed: {exc}',
        })

    # ── GET: list LDAP users (imported + new) ──────────────────────
    if request.method == 'GET':
        # '*' is a hardcoded wildcard to list all users, not user-supplied — do NOT escape
        list_filter = search_filter % {'user': '*'}

        # Multi-base support — admins can configure several `;`-separated bases
        # (e.g. "OU=Staff,DC=corp,DC=local;OU=Contractors,DC=corp,DC=local").
        # We probe each one and merge the results, deduping by the username
        # attribute in case the same account is reachable from two OUs.
        bases = [b.strip() for b in (search_base or '').split(';') if b.strip()]
        if not bases:
            return JsonResponse({
                'ok': False, 'error': 'search_failed',
                'message': 'LDAP User Search Base is not configured.',
            })

        from apps.accounts.ldap_utils import first_ou_from_dn
        all_entries = []  # list of (entry, base_label) tuples
        seen_dns    = set()
        for base in bases:
            # Label = the first OU of the configured search base itself, not
            # the user's DN. So users found under `OU=SECURITY,OU=BT,...` all
            # get the "SECURITY" label regardless of any sub-OU nesting.
            base_label = first_ou_from_dn(base)
            try:
                conn.search(
                    search_base=base,
                    search_filter=list_filter,
                    attributes=ldap_attrs,
                )
            except Exception as exc:
                return JsonResponse({
                    'ok': False, 'error': 'search_failed',
                    'message': f'LDAP search failed for base "{base}": {exc}',
                })
            for entry in conn.entries:
                dn = str(entry.entry_dn)
                if dn in seen_dns:
                    continue
                seen_dns.add(dn)
                all_entries.append((entry, base_label))

        existing_usernames = set(
            User.objects.values_list('username', flat=True)
        )

        users_found = []
        for entry, base_label in all_entries:
            try:
                uname = str(entry[username_ldap_attr]).strip()
            except Exception:
                continue
            if not uname:
                continue

            email      = ''
            first_name = ''
            last_name  = ''
            for django_attr, ldap_attr in attr_map.items():
                try:
                    val = str(entry[ldap_attr]).strip()
                    if django_attr == 'email':
                        email = val
                    elif django_attr == 'first_name':
                        first_name = val
                    elif django_attr == 'last_name':
                        last_name = val
                except Exception:
                    pass

            display_name = f'{first_name} {last_name}'.strip() or uname
            users_found.append({
                'username':         uname,
                'display_name':     display_name,
                'email':            email,
                # GROUP = first OU of the matched search base (SECURITY,
                # NETWORK, …) so admins see which Settings → LDAP base picked
                # the user up. Falls back to '' when the base has no OU.
                'ou':               base_label,
                # Tell the modal whether this LDAP account is already a Django
                # user — the frontend disables the checkbox and shows a badge
                # instead of letting the admin re-import a duplicate.
                'already_imported': uname in existing_usernames,
            })

        # Sort: group label first (so admins see all SECURITY rows together,
        # then NETWORK, etc.), then display name. Empty group sorts last by
        # using a high-codepoint sentinel for the empty-string case.
        def _sort_key(u):
            grp = (u.get('ou') or '').lower()
            return (grp or '~', (u.get('display_name') or u.get('username') or '').lower())
        users_found.sort(key=_sort_key)
        return JsonResponse({'ok': True, 'users': users_found})

    # ── POST: create selected users ─────────────────────────────────
    if request.method == 'POST':
        try:
            payload = json.loads(request.body)
        except Exception:
            return JsonResponse({'ok': False, 'message': 'Invalid request body.'})

        selected = payload.get('users', [])
        if not selected:
            return JsonResponse({'ok': False, 'message': 'No users selected.'})

        created_count = 0
        skipped       = []
        ip            = getattr(request, 'client_ip', '')

        for u in selected:
            uname = (u.get('username') or '').strip()
            if not uname:
                continue
            if User.objects.filter(username=uname).exists():
                skipped.append(uname)
                continue

            email      = (u.get('email') or '').strip()
            first_name = ''
            last_name  = ''
            display    = (u.get('display_name') or '').strip()
            if display and display != uname:
                parts      = display.split(' ', 1)
                first_name = parts[0]
                last_name  = parts[1] if len(parts) > 1 else ''

            new_user = User(
                username=uname,
                email=email,
                first_name=first_name,
                last_name=last_name,
            )
            new_user.set_unusable_password()
            new_user.save()

            ou_value = (u.get('ou') or '').strip()
            profile = new_user.profile
            profile.auth_source = UserProfile.AUTH_LDAP
            profile.role        = None
            profile.ldap_ou     = ou_value
            profile.save()

            import_detail = _user_audit_snapshot(new_user)
            import_detail['imported_by'] = request.user.username
            ActivityLog.log(
                request.user, 'user.ldap_import', 'User', str(new_user.pk),
                import_detail, ip,
            )
            created_count += 1

        word = 'user' if created_count == 1 else 'users'
        return JsonResponse({
            'ok':      True,
            'created': created_count,
            'skipped': skipped,
            'message': f'{created_count} {word} imported successfully.',
        })

    return JsonResponse({'ok': False, 'message': 'Method not allowed.'}, status=405)


@login_required_custom
@role_required('admin')
def user_update(request, user_id):
    target_user = get_object_or_404(User, pk=user_id)
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    # Superuser account can only be edited by the superuser themselves
    if target_user.is_superuser and not request.user.is_superuser:
        if is_ajax:
            return JsonResponse({'ok': False, 'error': 'You do not have permission to edit this account.'})
        messages.error(request, "You do not have permission to edit this account.")
        return redirect('accounts:user_list')

    profile = target_user.profile

    if request.method == 'POST':
        # Validate password first — return early on error without saving anything
        new_password = request.POST.get('new_password', '').strip()
        if new_password and profile.auth_source != 'ldap':
            confirm_password = request.POST.get('confirm_password', '').strip()
            policy_error = validate_password_policy(new_password)
            if policy_error:
                if is_ajax:
                    return JsonResponse({'ok': False, 'error': policy_error})
                messages.error(request, policy_error)
                return redirect('accounts:user_list')
            if new_password != confirm_password:
                if is_ajax:
                    return JsonResponse({'ok': False, 'error': 'Passwords do not match.'})
                messages.error(request, "Passwords do not match.")
                return redirect('accounts:user_list')

        # Snapshot pre-edit profile values for the audit-log diff.
        old_first_name = target_user.first_name or ''
        old_last_name  = target_user.last_name or ''
        old_email      = target_user.email or ''

        # Save profile info
        target_user.first_name = request.POST.get('first_name', '').strip()
        target_user.last_name  = request.POST.get('last_name', '').strip()
        target_user.email      = request.POST.get('email', '').strip()
        target_user.save(update_fields=['first_name', 'last_name', 'email'])

        # Role — only for non-superusers
        if not target_user.is_superuser:
            old_role = profile.role.name if profile.role else None
            role_id  = request.POST.get('role', '').strip()
            new_role = Role.objects.filter(pk=role_id).first() if role_id else None
            profile.role = new_role
            profile.save()
            action = 'user.role.remove' if new_role is None else 'user.role.assign'
            ActivityLog.log(request.user, action, 'User', str(target_user.pk),
                         {'username': target_user.username,
                          'old_role': old_role,
                          'new_role': new_role.name if new_role else None},
                         getattr(request, 'client_ip', ''))

        # Save password (already validated above)
        if new_password and profile.auth_source != 'ldap':
            target_user.set_password(new_password)
            target_user.save()
            ActivityLog.log(request.user, 'user.password_change', 'User', str(target_user.pk),
                         {'username': target_user.username}, getattr(request, 'client_ip', ''))

        update_detail = _user_audit_snapshot(target_user)
        update_detail.update({
            'old_first_name': old_first_name, 'new_first_name': target_user.first_name or '',
            'old_last_name':  old_last_name,  'new_last_name':  target_user.last_name or '',
            'old_email':      old_email,      'new_email':      target_user.email or '',
        })
        ActivityLog.log(request.user, 'user.update', 'User', str(target_user.pk),
                     update_detail, getattr(request, 'client_ip', ''))
        if is_ajax:
            return JsonResponse({'ok': True})
        messages.success(request, f"User '{target_user.username}' updated.")
    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def user_change_password(request, user_id):
    target_user = get_object_or_404(User, pk=user_id)

    # Superuser account password can only be changed by the superuser themselves
    if target_user.is_superuser and not request.user.is_superuser:
        messages.error(request, "You do not have permission to change this account's password.")
        return redirect('accounts:user_list')

    if target_user.profile.auth_source == 'ldap':
        messages.error(request, "Password cannot be changed for LDAP users.")
        return redirect('accounts:user_list')

    error = None
    if request.method == 'POST':
        new_password  = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')

        policy_error = validate_password_policy(new_password)
        if policy_error:
            messages.error(request, policy_error)
        elif new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            target_user.set_password(new_password)
            target_user.save()
            ActivityLog.log(request.user, 'user.password_change', 'User', str(target_user.pk),
                         {'username': target_user.username}, getattr(request, 'client_ip', ''))
            messages.success(request, f"Password updated for '{target_user.username}'.")

    return redirect('accounts:user_list')


@login_required_custom
@role_required('admin')
def generate_token(request):
    if request.method == 'POST':
        profile = request.user.profile
        # Capture whether the user was rotating an existing token (so the audit
        # trail distinguishes "first-time issue" from "rotation").
        had_previous_token = bool(profile.api_token_hash)
        raw_token = profile.generate_api_token()
        ActivityLog.log(
            request.user, 'user.token_generate_self', 'User', str(request.user.pk),
            {'username': request.user.username, 'rotated': had_previous_token},
            getattr(request, 'client_ip', ''),
        )
        messages.success(request, f"New API token generated. Copy it now — it will not be shown again: {raw_token}")
    return redirect('accounts:profile')


@login_required_custom
@role_required('admin')
def revoke_token(request):
    if request.method == 'POST':
        profile = request.user.profile
        had_token = bool(profile.api_token_hash)
        profile.revoke_api_token()
        ActivityLog.log(
            request.user, 'user.token_revoke_self', 'User', str(request.user.pk),
            {'username': request.user.username, 'had_token': had_token},
            getattr(request, 'client_ip', ''),
        )
        messages.success(request, "API token revoked.")
    return redirect('accounts:profile')


@login_required_custom
@role_required('admin')
def user_generate_token(request, user_id):
    """Generate (or regenerate) an API token for an api_user account. Admin only."""
    if request.method != 'POST':
        return JsonResponse({'ok': False, 'message': 'Method not allowed.'}, status=405)

    target_user = get_object_or_404(User, pk=user_id)
    profile = target_user.profile

    if profile.role is None or profile.role.name != 'api_user':
        return JsonResponse(
            {'ok': False, 'message': 'Token can only be generated for API User role accounts.'},
            status=400,
        )

    raw_token = profile.generate_api_token()
    ip = getattr(request, 'client_ip', '')
    ActivityLog.log(
        request.user, 'user.token_generate', 'User', str(target_user.pk),
        {'username': target_user.username, 'generated_by': request.user.username}, ip,
    )
    return JsonResponse({'ok': True, 'token': raw_token, 'username': target_user.username})


@login_required_custom
@role_required('admin')
def user_revoke_token(request, user_id):
    """Revoke the API token for a user. Admin only."""
    if request.method != 'POST':
        return JsonResponse({'ok': False, 'message': 'Method not allowed.'}, status=405)

    target_user = get_object_or_404(User, pk=user_id)
    profile = target_user.profile
    profile.revoke_api_token()

    ip = getattr(request, 'client_ip', '')
    ActivityLog.log(
        request.user, 'user.token_revoke', 'User', str(target_user.pk),
        {'username': target_user.username, 'revoked_by': request.user.username}, ip,
    )
    return JsonResponse({'ok': True})
