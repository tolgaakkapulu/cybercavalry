from django.urls import path
from . import views

app_name = "urllist"

urlpatterns = [
    path("", views.urllist_list, name="list"),
    path("add/", views.urllist_create, name="create"),
    path("bulk/", views.urllist_bulk_create, name="bulk_create"),
    path("import/", views.urllist_import_csv, name="import_csv"),
    path("export/", views.urllist_export, name="export"),
    path("export/pdf/", views.urllist_pdf_report, name="export_pdf"),
    path("bulk-delete/", views.urllist_bulk_delete, name="bulk_delete"),
    path("bulk-deactivate/", views.urllist_bulk_deactivate, name="bulk_deactivate"),
    path("bulk-activate/", views.urllist_bulk_activate, name="bulk_activate"),
    path("bulk-pin/", views.urllist_bulk_pin, name="bulk_pin"),
    path("bulk-unpin/", views.urllist_bulk_unpin, name="bulk_unpin"),
    path("<int:entry_id>/edit/", views.urllist_edit, name="edit"),
    path("<int:entry_id>/delete/", views.urllist_delete, name="delete"),
    path("<int:entry_id>/deactivate/", views.urllist_deactivate_single, name="deactivate_single"),
    path("<int:entry_id>/activate/", views.urllist_activate_single, name="activate_single"),
    path("<int:entry_id>/score/", views.urllist_score_single, name="score_single"),
    path("bulk-score/", views.urllist_bulk_score, name="bulk_score"),
    path("<int:entry_id>/pin/", views.urllist_pin_toggle, name="pin_toggle"),
]
