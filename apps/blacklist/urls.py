from django.urls import path
from . import views

app_name = 'blacklist'

urlpatterns = [
    path('', views.blacklist_list, name='list'),
    path('add/', views.blacklist_create, name='create'),
    path('add/bulk/', views.blacklist_bulk_create, name='bulk_create'),
    path('import/', views.blacklist_import_csv, name='import_csv'),
    path('bulk-delete/', views.blacklist_bulk_delete, name='bulk_delete'),
    path('bulk-hard-delete/', views.blacklist_bulk_hard_delete, name='bulk_hard_delete'),
    path('bulk-edit-group/', views.blacklist_bulk_edit_group, name='bulk_edit_group'),
    path('bulk-activate/', views.blacklist_bulk_activate, name='bulk_activate'),
    path('bulk-deactivate/', views.blacklist_bulk_deactivate, name='bulk_deactivate'),
    path('bulk-pin/', views.blacklist_bulk_pin, name='bulk_pin'),
    path('bulk-unpin/', views.blacklist_bulk_unpin, name='bulk_unpin'),
    path('deactivate-all/', views.blacklist_deactivate_all, name='deactivate_all'),
    path('<int:entry_id>/edit/', views.blacklist_edit, name='edit'),
    path('<int:entry_id>/delete/', views.blacklist_delete, name='delete'),
    path('<int:entry_id>/deactivate/', views.blacklist_deactivate_single, name='deactivate_single'),
    path('<int:entry_id>/reactivate/', views.blacklist_reactivate, name='reactivate'),
    path('export/', views.blacklist_export, name='export'),
    path('export/pdf/', views.blacklist_pdf_report, name='export_pdf'),
    path('bulk-score/', views.blacklist_bulk_score, name='bulk_score'),
    path('<int:entry_id>/score/', views.blacklist_score_single, name='score_single'),
    path('<int:entry_id>/pin/', views.blacklist_pin_toggle, name='pin_toggle'),
]
