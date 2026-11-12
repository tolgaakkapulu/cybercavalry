"""Collection management routes.

Mounted from `apps.settings_app.urls` so the pages live at
`/settings/taxii/collections/…` — deliberately NOT under `/taxii/`, which
is the public TAXII surface a subscriber polls.
"""
from django.urls import path
from . import admin_views

app_name = 'taxii_admin'

urlpatterns = [
    path('',                     admin_views.collection_list,   name='collection_list'),
    path('add/',                 admin_views.collection_add,    name='collection_add'),
    path('<int:pk>/edit/',       admin_views.collection_edit,   name='collection_edit'),
    path('<int:pk>/toggle/',     admin_views.collection_toggle, name='collection_toggle'),
    path('<int:pk>/delete/',     admin_views.collection_delete, name='collection_delete'),
]
