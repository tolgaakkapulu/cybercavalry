from django.contrib import admin
from .models import HashEntry


@admin.register(HashEntry)
class HashEntryAdmin(admin.ModelAdmin):
    list_display  = ('hash_value', 'hash_type', 'list_type', 'is_active', 'source', 'added_by', 'added_at')
    list_filter   = ('list_type', 'hash_type', 'is_active', 'source')
    search_fields = ('hash_value', 'reason')
    readonly_fields = ('added_at',)
