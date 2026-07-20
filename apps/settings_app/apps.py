from django.apps import AppConfig


class SettingsAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.settings_app'
    verbose_name = 'Settings'

    # Syslog forwarding is wired via Django LOGGING (settings/base.py) —
    # `SyslogMainHandler`, `SyslogErrorHandler`, and `SyslogAccessHandler`
    # attach to the same loggers as their file counterparts and self-guard
    # on the Settings → Actions → Syslog toggles. No app-ready hook needed.
