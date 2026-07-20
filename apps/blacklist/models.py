from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


class BlacklistGroup(models.Model):
    DURATION_24H = 24
    DURATION_30D = 720  # 30 * 24

    name = models.CharField(max_length=50, unique=True)
    label = models.CharField(max_length=100)
    default_duration_hours = models.IntegerField(null=True, blank=True, help_text="Null = permanent")
    is_published = models.BooleanField(default=True, help_text="Show in public API endpoints")
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ['order', 'name']

    def __str__(self):
        return self.label

    @property
    def duration_display(self):
        if self.default_duration_hours is None:
            return "Permanent"
        hours = self.default_duration_hours
        if hours >= 720:
            return f"{hours // 720} month(s)"
        if hours >= 24:
            return f"{hours // 24} day(s)"
        return f"{hours} hour(s)"


class BlacklistEntry(models.Model):
    SOURCE_MANUAL = 'manual'
    SOURCE_API = 'api'
    SOURCE_IMPORT = 'import'

    SOURCE_CHOICES = [
        (SOURCE_MANUAL, 'Manual'),
        (SOURCE_API, 'API'),
        (SOURCE_IMPORT, 'Import'),
    ]

    ip_address = models.GenericIPAddressField()
    prefix_length = models.IntegerField(default=32)
    cidr = models.CharField(max_length=50, db_index=True)
    group = models.ForeignKey(BlacklistGroup, on_delete=models.CASCADE, related_name='entries')
    reason = models.TextField(blank=True)
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    added_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='blacklist_entries'
    )
    added_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    hit_count = models.IntegerField(default=1)
    # Rolling 7-day window: ISO timestamps of the most recent API reports for
    # this IP. Kept short by pruning entries older than 7 days on every write
    # (see apps/api/views.py). Powers the promotion threshold check — we want
    # "N reports in the last week", not "N reports ever".
    recent_hit_timestamps = models.JSONField(default=list, blank=True)
    reporter_ip = models.GenericIPAddressField(null=True, blank=True, help_text="Source IP of API reporter")
    abuse_confidence_score = models.IntegerField(null=True, blank=True, help_text="AbuseIPDB confidence score (0-100)")
    abuse_checked_at = models.DateTimeField(null=True, blank=True, help_text="Last AbuseIPDB query time")
    # AbuseIPDB enrichment metadata (populated on each check, shown in the IP tooltip)
    abuse_isp          = models.CharField(max_length=255, blank=True, default='')
    abuse_usage_type   = models.CharField(max_length=120, blank=True, default='')
    abuse_domain       = models.CharField(max_length=255, blank=True, default='')
    abuse_hostnames    = models.JSONField(default=list, blank=True)
    abuse_country_code = models.CharField(max_length=2,   blank=True, default='')
    abuse_country_name = models.CharField(max_length=100, blank=True, default='')
    abuse_asn          = models.CharField(max_length=32,  blank=True, default='')
    abuse_city         = models.CharField(max_length=120, blank=True, default='')
    abuse_total_reports    = models.IntegerField(null=True, blank=True, help_text="AbuseIPDB total report count")
    abuse_last_reported_at = models.DateTimeField(null=True, blank=True, help_text="AbuseIPDB last report time")
    is_pinned = models.BooleanField(default=False, help_text="Pinned entries are exempt from automatic score-based group reassignment and deactivation")

    class Meta:
        unique_together = ('cidr', 'group')
        indexes = [
            models.Index(fields=['is_active', 'expires_at']),
            models.Index(fields=['ip_address']),
        ]
        ordering = ['-added_at']

    def __str__(self):
        return f"{self.cidr} ({self.group.label})"

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

    @property
    def is_effectively_active(self):
        return self.is_active and not self.is_expired

    @property
    def abuse_hostnames_display(self):
        """Comma-joined hostname list for display."""
        if isinstance(self.abuse_hostnames, list):
            return ', '.join(h for h in self.abuse_hostnames if h)
        return ''

    @property
    def abuse_country_display(self):
        """'Country Name (CC)' if both known, else whichever is set."""
        if self.abuse_country_name and self.abuse_country_code:
            return f'{self.abuse_country_name} ({self.abuse_country_code})'
        return self.abuse_country_name or self.abuse_country_code or ''

    @property
    def abuse_last_reported_display(self):
        """'YYYY-mm-dd HH:MM' for the last AbuseIPDB report time, or ''."""
        if self.abuse_last_reported_at:
            return timezone.localtime(self.abuse_last_reported_at).strftime('%Y-%m-%d %H:%M')
        return ''

    @property
    def has_abuse_intel(self):
        """True when AbuseIPDB enrichment data exists to show in the tooltip."""
        return bool(self.abuse_checked_at and (
            self.abuse_isp or self.abuse_usage_type or self.abuse_domain
            or self.abuse_hostnames_display or self.abuse_country_display
            or self.abuse_asn or self.abuse_city
            or self.abuse_total_reports or self.abuse_last_reported_at
        ))

    def save(self, *args, **kwargs):
        # Entries with no_group must always remain inactive
        if self.group_id and self.group.name == 'no_group':
            self.is_active = False
        super().save(*args, **kwargs)

    def set_expiry_from_group(self):
        """Set expires_at based on group's default_duration_hours."""
        if self.group.default_duration_hours is not None:
            self.expires_at = timezone.now() + timedelta(hours=self.group.default_duration_hours)
        else:
            self.expires_at = None

    def extend_expiry(self):
        """Reset the expiry timer (used when same IP is reported again)."""
        if self.group.default_duration_hours is not None:
            self.expires_at = timezone.now() + timedelta(hours=self.group.default_duration_hours)
            self.save(update_fields=['expires_at', 'last_seen_at', 'hit_count'])

    # Cap for on-disk retention so an admin who lowers the promotion window
    # from 30 back down to 7 doesn't have to worry about the JSON column
    # growing unbounded. Storage horizon is fixed; the count query filters
    # to whatever the admin currently configured.
    RECENT_HIT_MAX_STORED_DAYS = 30

    def record_recent_hit(self, when=None):
        """Append `when` to the rolling report window and drop entries that
        fell out of the storage horizon (30 days). Does NOT save — caller
        decides when to persist so the write can be batched with other
        field updates. Safe to call even when the underlying JSON column
        was migrated as an empty list."""
        from datetime import datetime, timezone as _dt_tz
        stamp = (when or timezone.now())
        cutoff = stamp - timedelta(days=self.RECENT_HIT_MAX_STORED_DAYS)
        kept = []
        for raw in (self.recent_hit_timestamps or []):
            try:
                t = datetime.fromisoformat(raw)
                if t.tzinfo is None:
                    t = t.replace(tzinfo=_dt_tz.utc)
                if t >= cutoff:
                    kept.append(raw)
            except (ValueError, TypeError):
                # Malformed entry — drop it silently rather than crash the write path.
                continue
        kept.append(stamp.isoformat())
        self.recent_hit_timestamps = kept

    def count_recent_hits_within(self, days):
        """Number of API reports for this IP within the last `days` days.
        Re-computes the cutoff on read so a stale row (no writes for days)
        doesn't return a count inflated by entries that fell out of the
        window. `days` comes from the admin-configured promotion window
        setting; callers should clamp it to [1, 30] since that's the
        storage horizon (see RECENT_HIT_MAX_STORED_DAYS)."""
        from datetime import datetime, timezone as _dt_tz
        if not days or days <= 0:
            return 0
        cutoff = timezone.now() - timedelta(days=days)
        count = 0
        for raw in (self.recent_hit_timestamps or []):
            try:
                t = datetime.fromisoformat(raw)
                if t.tzinfo is None:
                    t = t.replace(tzinfo=_dt_tz.utc)
                if t >= cutoff:
                    count += 1
            except (ValueError, TypeError):
                continue
        return count
