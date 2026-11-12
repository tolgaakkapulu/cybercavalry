"""TAXII 2.0 URL map.

Mounted at `/taxii/` in the root URLconf. Discovery MUST live at `/taxii/`
per the spec's endpoint table (TAXII 2.1 moved it to `/taxii2/` — a 2.0
client looking for `/taxii/` would miss it there). API roots only need a
unique URL, so nesting ours under the same prefix keeps the whole TAXII
surface in one namespace and clear of `/api/v1/`.
"""
from django.urls import path
from . import views

app_name = 'taxii'

urlpatterns = [
    path('',                                                   views.discovery,     name='discovery'),
    path('<str:root>/',                                        views.api_root,      name='api_root'),
    path('<str:root>/collections/',                            views.collections,   name='collections'),
    path('<str:root>/collections/<str:cid>/',                  views.collection,    name='collection'),
    path('<str:root>/collections/<str:cid>/objects/',          views.objects,       name='objects'),
    path('<str:root>/collections/<str:cid>/objects/<str:oid>/', views.object_by_id, name='object'),
    path('<str:root>/collections/<str:cid>/manifest/',         views.manifest,      name='manifest'),
]
