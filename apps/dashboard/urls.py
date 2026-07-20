from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/stats/', views.stats_api, name='stats_api'),
    path('api/timeline/', views.timeline_api, name='timeline_api'),
    path('export/pdf/', views.dashboard_pdf, name='export_pdf'),
]
