from django.db import models
from django.contrib.auth.models import User


class WhitelistEntry(models.Model):
    SOURCE_MANUAL = 'manual'
    SOURCE_IMPORT = 'import'
    SOURCE_CHOICES = [
        (SOURCE_MANUAL, 'Manual'),
        (SOURCE_IMPORT, 'Import'),
    ]

    ip_address = models.GenericIPAddressField()
    prefix_length = models.IntegerField(default=32)
    cidr = models.CharField(max_length=50, unique=True, db_index=True)
    reason = models.TextField(blank=True)
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default=SOURCE_MANUAL)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    added_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-added_at']

    def __str__(self):
        return self.cidr
