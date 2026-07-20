import json
import logging
from django.db import models
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)


class Setting(models.Model):
    TYPE_STR = 'str'
    TYPE_INT = 'int'
    TYPE_BOOL = 'bool'
    TYPE_JSON = 'json'

    TYPE_CHOICES = [
        (TYPE_STR, 'String'),
        (TYPE_INT, 'Integer'),
        (TYPE_BOOL, 'Boolean'),
        (TYPE_JSON, 'JSON'),
    ]

    CATEGORY_LDAP = 'ldap'
    CATEGORY_API = 'api'
    CATEGORY_SECURITY = 'security'
    CATEGORY_GENERAL = 'general'
    CATEGORY_THREAT_INTEL = 'threat_intel'
    CATEGORY_PASSWORD_POLICY = 'password_policy'
    CATEGORY_BACKUP = 'backup'

    CATEGORY_CHOICES = [
        (CATEGORY_LDAP, 'LDAP'),
        (CATEGORY_API, 'API'),
        (CATEGORY_SECURITY, 'Security'),
        (CATEGORY_GENERAL, 'General'),
        (CATEGORY_THREAT_INTEL, 'Threat Intelligence'),
        (CATEGORY_PASSWORD_POLICY, 'Password Policy'),
        (CATEGORY_BACKUP, 'Backup'),
    ]

    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    value_type = models.CharField(max_length=10, choices=TYPE_CHOICES, default=TYPE_STR)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default=CATEGORY_GENERAL)
    description = models.CharField(max_length=255, blank=True)
    is_secret = models.BooleanField(default=False, help_text="Mask value in UI")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['category', 'key']

    def __str__(self):
        return f"{self.key} = {'***' if self.is_secret else self.value}"

    def save(self, *args, **kwargs):
        if self.is_secret and self.value:
            from .crypto import encrypt
            if not self.value.startswith('enc:'):
                self.value = encrypt(self.value)
        super().save(*args, **kwargs)

    @property
    def plain_value(self):
        """Decrypted plain-text value (for secret fields)."""
        if self.is_secret and self.value:
            from .crypto import decrypt
            return decrypt(self.value, key_hint=self.key)
        return self.value

    def typed_value(self):
        """Return value cast to the appropriate Python type (decrypts secrets)."""
        raw = self.plain_value
        if self.value_type == self.TYPE_BOOL:
            return raw.lower() in ('true', '1', 'yes')
        elif self.value_type == self.TYPE_INT:
            try:
                return int(raw)
            except ValueError:
                return 0
        elif self.value_type == self.TYPE_JSON:
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}
        return raw

    @classmethod
    def get(cls, key, default=None):
        try:
            s = cls.objects.get(key=key)
            return s.typed_value()
        except cls.DoesNotExist:
            return default


class AllowedSourceIP(models.Model):
    """IPs/CIDRs allowed to call any API endpoint."""
    cidr = models.CharField(max_length=50, unique=True)
    label = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['cidr']

    def __str__(self):
        return f"{self.cidr} ({self.label})" if self.label else self.cidr


class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100, db_index=True)
    target_model = models.CharField(max_length=50)
    target_id = models.CharField(max_length=50)
    detail = models.JSONField(default=dict)
    ip_address = models.CharField(max_length=45, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        db_table = 'settings_app_auditlog'  # keep existing table — no data migration needed

    def __str__(self):
        user_str = self.user.username if self.user else 'system'
        return f"[{self.timestamp}] {user_str}: {self.action}"

    @classmethod
    def log(cls, user, action, target_model, target_id, detail=None, ip_address=''):
        try:
            entry = cls.objects.create(
                user=user,
                action=action,
                target_model=target_model,
                target_id=str(target_id),
                detail=detail or {},
                ip_address=ip_address or '',
            )
        except Exception as e:
            logger.error(f"Failed to write activity log: {e}")
            return

        # Mirror the just-persisted row to syslog when Settings → Actions →
        # Syslog → "Forward Activity Logs" is on. Running after the DB insert
        # ensures the syslog line matches exactly what the Activity Log UI
        # page shows for this event. Never raises: forwarding must not break
        # the caller path (login, blacklist add, etc.).
        try:
            from apps.settings_app.syslog_service import emit, stream_enabled
            if stream_enabled('activity'):
                user_str = user.username if user else 'system'
                parts = [
                    f'user={user_str}',
                    f'action={action}',
                    f'target={target_model}:{target_id}',
                ]
                if ip_address:
                    parts.append(f'ip={ip_address}')
                if entry.detail:
                    parts.append(f'detail={json.dumps(entry.detail, ensure_ascii=False, default=str)}')
                emit('activity', ' '.join(parts), severity='info')
        except Exception as exc:
            logger.error(f"Failed to forward activity log to syslog: {exc}")


# Backwards-compat alias so any cached/pickled references still resolve
AuditLog = ActivityLog
