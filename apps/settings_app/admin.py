from django.contrib import admin
from .models import Setting, AllowedSourceIP, ActivityLog

admin.site.register(Setting)
admin.site.register(AllowedSourceIP)
admin.site.register(ActivityLog)
