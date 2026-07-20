from django.urls import path
from . import views

app_name = 'api'

urlpatterns = [
    path('status/', views.api_status, name='status'),
    path('report/ip/', views.report_ip, name='report_ip'),
    path('blacklist/', views.get_blacklist, name='blacklist'),
    path('blacklist/24h/', lambda r: views.get_blacklist(r, group_filter='24h'), name='blacklist_24h'),
    path('blacklist/30d/', lambda r: views.get_blacklist(r, group_filter='30d'), name='blacklist_30d'),
    path('hashlist/', views.get_hashlist, name='hashlist'),
    path('report/hash/', views.report_hash, name='report_hash'),
]
