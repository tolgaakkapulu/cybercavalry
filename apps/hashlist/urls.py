from django.urls import path
from . import views

app_name = "hashlist"

urlpatterns = [
    path("", views.hashlist_list, name="list"),
    path("add/", views.hashlist_create, name="create"),
    path("bulk/", views.hashlist_bulk_create, name="bulk_create"),
    path("import/", views.hashlist_import_csv, name="import_csv"),
    path("export/", views.hashlist_export, name="export"),
    path("export/pdf/", views.hashlist_pdf_report, name="export_pdf"),
    path("bulk-delete/", views.hashlist_bulk_delete, name="bulk_delete"),
    path("bulk-deactivate/", views.hashlist_bulk_deactivate, name="bulk_deactivate"),
    path("bulk-activate/", views.hashlist_bulk_activate, name="bulk_activate"),
    path("<int:entry_id>/edit/", views.hashlist_edit, name="edit"),
    path("<int:entry_id>/delete/", views.hashlist_delete, name="delete"),
    path("<int:entry_id>/deactivate/", views.hashlist_deactivate_single, name="deactivate_single"),
    path("<int:entry_id>/activate/", views.hashlist_activate_single, name="activate_single"),
    path("<int:entry_id>/score/", views.hashlist_score_single, name="score_single"),
    path("bulk-score/", views.hashlist_bulk_score, name="bulk_score"),
    path("<int:entry_id>/pin/", views.hashlist_pin_toggle, name="pin_toggle"),
]
