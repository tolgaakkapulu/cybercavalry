import logging
from functools import wraps
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

logger = logging.getLogger(__name__)


def role_required(*roles):
    """Decorator to restrict view access to users with specific roles."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:login')

            # Django superusers always have full access
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)

            try:
                profile = request.user.profile
                if profile.role and profile.role.name in roles:
                    return view_func(request, *args, **kwargs)
                logger.debug(
                    f"Access denied: user={request.user.username} "
                    f"role={getattr(profile.role, 'name', None)} "
                    f"required={roles}"
                )
            except Exception as e:
                logger.warning(f"role_required check error for {request.user.username}: {e}")

            raise PermissionDenied
        return wrapper
    return decorator


def login_required_custom(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        if not request.user.is_superuser:
            try:
                from django.urls import reverse
                profile_allowed = (
                    reverse('accounts:profile'),
                    reverse('accounts:generate_token'),
                    reverse('accounts:revoke_token'),
                    reverse('accounts:api_reference'),
                    reverse('accounts:api_reference_pdf'),
                )
                role = request.user.profile.role

                # No role assigned → can only access profile page
                if not role:
                    if request.path not in profile_allowed:
                        return redirect('accounts:profile')
                    return view_func(request, *args, **kwargs)

                # API User can only access profile and API reference pages
                if role.name == 'api_user':
                    if request.path not in profile_allowed:
                        return redirect('accounts:profile')
            except Exception as e:
                logger.warning(f"login_required_custom role check error for {request.user.username}: {e}")
        return view_func(request, *args, **kwargs)
    return wrapper
