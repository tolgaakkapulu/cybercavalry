from django.apps import AppConfig


class TaxiiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.taxii'
    label = 'taxii'
    verbose_name = 'TAXII 2.0 Server'
