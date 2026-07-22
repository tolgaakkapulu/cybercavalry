import re
from django.db import models
from django.contrib.auth.models import User

HASH_LENGTHS = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}


def detect_hash_type(value):
    v = value.strip().lower()
    if re.fullmatch(r'[0-9a-f]+', v):
        return HASH_LENGTHS.get(len(v), 'unknown')
    return 'unknown'


def is_valid_hash(value):
    v = value.strip().lower()
    return bool(re.fullmatch(r'[0-9a-f]+', v) and len(v) in (32, 40, 64, 128))


def normalize_hash(value):
    v = value.strip().lower()
    if not is_valid_hash(v):
        raise ValueError(f"Invalid hash: {value}")
    return v, detect_hash_type(v)


class HashEntry(models.Model):
    LIST_BLACK = 'black'
    LIST_WHITE = 'white'
    LIST_CHOICES = [(LIST_BLACK, 'Blacklist'), (LIST_WHITE, 'Whitelist')]

    SOURCE_MANUAL = 'manual'
    SOURCE_API = 'api'
    SOURCE_IMPORT = 'import'
    SOURCE_CHOICES = [
        (SOURCE_MANUAL, 'Manual'),
        (SOURCE_API, 'API'),
        (SOURCE_IMPORT, 'Import'),
    ]

    HASH_TYPE_CHOICES = [
        ('md5', 'MD5'),
        ('sha1', 'SHA1'),
        ('sha256', 'SHA256'),
        ('sha512', 'SHA512'),
        ('unknown', 'Unknown'),
    ]

    hash_value = models.CharField(max_length=128, db_index=True)
    hash_type  = models.CharField(max_length=10, choices=HASH_TYPE_CHOICES, default='unknown')
    list_type  = models.CharField(max_length=10, choices=LIST_CHOICES, default=LIST_BLACK, db_index=True)
    reason     = models.TextField(blank=True)
    source     = models.CharField(max_length=10, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    added_by   = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    added_at   = models.DateTimeField(auto_now_add=True)
    is_active  = models.BooleanField(default=True, db_index=True)
    is_pinned  = models.BooleanField(default=False, help_text="Pinned entries are exempt from automatic score-based deactivation")
    # VirusTotal
    vt_malicious   = models.IntegerField(null=True, blank=True, help_text="Number of engines detecting as malicious")
    vt_total       = models.IntegerField(null=True, blank=True, help_text="Total number of engines scanned")
    vt_checked_at  = models.DateTimeField(null=True, blank=True, help_text="Last VirusTotal query time")
    vt_unavailable = models.BooleanField(
        default=False,
        db_index=True,
        help_text=(
            "True when VirusTotal was queried but did not return a result "
            "(timeout, quota exhausted, network error). Such entries stay "
            "is_active=True for admin visibility but are excluded from the "
            "downstream /api/v1/hashlist/ feed until a valid score arrives."
        ),
    )
    # VirusTotal enrichment metadata (shown in the hash tooltip)
    vt_threat_label     = models.CharField(max_length=255, blank=True, default='')
    vt_type_description = models.CharField(max_length=120, blank=True, default='')
    vt_size             = models.BigIntegerField(null=True, blank=True)
    vt_meaningful_name  = models.CharField(max_length=255, blank=True, default='')
    vt_first_seen       = models.DateTimeField(null=True, blank=True)
    vt_last_analysis    = models.DateTimeField(null=True, blank=True)
    vt_times_submitted  = models.IntegerField(null=True, blank=True)

    class Meta:
        unique_together = ('hash_value', 'list_type')
        ordering = ['-added_at']
        indexes = [
            models.Index(fields=['is_active', 'list_type']),
        ]

    def __str__(self):
        return f"{self.hash_value[:16]}... ({self.list_type})"

    @property
    def vt_size_display(self):
        """Human-readable file size."""
        if not self.vt_size:
            return ''
        size = float(self.vt_size)
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size < 1024:
                return f'{size:.0f} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} TB'

    @property
    def has_vt_intel(self):
        """True when VirusTotal enrichment data exists to show in the tooltip."""
        return bool(self.vt_checked_at and (
            self.vt_threat_label or self.vt_type_description or self.vt_size
            or self.vt_meaningful_name or self.vt_first_seen or self.vt_times_submitted
        ))
