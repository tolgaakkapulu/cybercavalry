from django.contrib import admin
from .models import URLEntry


@admin.register(URLEntry)
class URLEntryAdmin(admin.ModelAdmin):
    list_display  = ('url_value', 'hostname', 'list_type', 'is_active', 'source', 'added_by', 'added_at')
    list_filter   = ('list_type', 'is_active', 'source', 'is_pinned', 'vt_unavailable')
    search_fields = ('url_value', 'hostname', 'reason')
    readonly_fields = ('added_at', 'url_hash')
