from django.contrib import admin
from .models import BlacklistGroup, BlacklistEntry

admin.site.register(BlacklistGroup)
admin.site.register(BlacklistEntry)
