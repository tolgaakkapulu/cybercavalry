from django.urls import path
from . import views

app_name = 'whitelist'

urlpatterns = [
    path('', views.whitelist_list, name='list'),
    path('add/', views.whitelist_create, name='create'),
    path('add/bulk/', views.whitelist_bulk_create, name='bulk_create'),
    path('import/', views.whitelist_import_csv, name='import_csv'),
    path('export/', views.whitelist_export, name='export'),
    path('export/pdf/', views.whitelist_pdf_report, name='export_pdf'),
    path('bulk-delete/', views.whitelist_bulk_delete, name='bulk_delete'),
    path('bulk-deactivate/', views.whitelist_bulk_deactivate, name='bulk_deactivate'),
    path('bulk-activate/', views.whitelist_bulk_activate, name='bulk_activate'),
    path('<int:entry_id>/edit/', views.whitelist_edit, name='edit'),
    path('<int:entry_id>/delete/', views.whitelist_delete, name='delete'),
    path('<int:entry_id>/deactivate/', views.whitelist_deactivate_single, name='deactivate_single'),
    path('<int:entry_id>/activate/', views.whitelist_activate_single, name='activate_single'),
]
