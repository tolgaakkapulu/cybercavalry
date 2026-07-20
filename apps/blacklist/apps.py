from django.apps import AppConfig


class BlacklistConfig(AppConfig):
    name = 'apps.blacklist'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        from . import scheduler
        scheduler.start()
