import hashlib
import secrets
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class Role(models.Model):
    ADMIN = 'admin'
    OPERATOR = 'operator'
    VIEWER = 'viewer'
    API_USER = 'api_user'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (OPERATOR, 'Operator'),
        (VIEWER, 'Viewer'),
        (API_USER, 'API User'),
    ]

    name = models.CharField(max_length=50, unique=True, choices=ROLE_CHOICES)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.get_name_display()

    @property
    def can_manage_blacklist(self):
        return self.name in (self.ADMIN, self.OPERATOR)

    @property
    def can_manage_whitelist(self):
        return self.name in (self.ADMIN, self.OPERATOR)

    @property
    def can_manage_hashlist(self):
        return self.name in (self.ADMIN, self.OPERATOR)

    @property
    def can_manage_urllist(self):
        return self.name in (self.ADMIN, self.OPERATOR)

    @property
    def can_view(self):
        return self.name in (self.ADMIN, self.OPERATOR, self.VIEWER)

    @property
    def can_manage_settings(self):
        return self.name == self.ADMIN

    @property
    def can_use_api(self):
        return self.name in (self.ADMIN, self.API_USER)


class UserProfile(models.Model):
    AUTH_LOCAL = 'local'
    AUTH_LDAP = 'ldap'

    AUTH_CHOICES = [
        (AUTH_LOCAL, 'Local'),
        (AUTH_LDAP, 'LDAP'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    auth_source = models.CharField(max_length=10, choices=AUTH_CHOICES, default=AUTH_LOCAL)
    api_token_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)
    token_created_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    # First OU segment of the user's LDAP DN (e.g. "Staff", "Contractors"). Set
    # at LDAP-import and refreshed on every successful LDAP login. Empty for
    # local accounts and for LDAP accounts whose DN doesn't contain an OU.
    ldap_ou = models.CharField(max_length=128, blank=True, default='')

    def __str__(self):
        return f"{self.user.username} ({self.get_auth_source_display()})"

    @property
    def role_name(self):
        return self.role.name if self.role else None

    def generate_api_token(self):
        """Generate a new API token. Returns the raw token (shown once)."""
        from django.utils import timezone
        raw_token = secrets.token_hex(32)
        self.api_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        self.token_created_at = timezone.now()
        self.save(update_fields=['api_token_hash', 'token_created_at'])
        return raw_token

    def revoke_api_token(self):
        self.api_token_hash = None
        self.token_created_at = None
        self.save(update_fields=['api_token_hash', 'token_created_at'])

    @classmethod
    def get_by_token(cls, raw_token):
        """Look up a UserProfile by raw API token."""
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        try:
            return cls.objects.select_related('user', 'role').get(api_token_hash=token_hash)
        except cls.DoesNotExist:
            return None


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
