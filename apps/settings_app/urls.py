from django.urls import path
from . import views

app_name = 'settings_app'

urlpatterns = [
    path('', views.settings_index, name='index'),
    path('save/', views.settings_save, name='save'),
    path('ldap/test/', views.ldap_test, name='ldap_test'),
    path('source-ips/', views.source_ip_list, name='source_ip_list'),
    path('source-ips/add/', views.source_ip_add, name='source_ip_add'),
    path('source-ips/<int:entry_id>/activate/', views.source_ip_activate, name='source_ip_activate'),
    path('source-ips/<int:entry_id>/deactivate/', views.source_ip_deactivate, name='source_ip_deactivate'),
    path('source-ips/<int:entry_id>/delete/', views.source_ip_delete, name='source_ip_delete'),
    path('source-ips/<int:entry_id>/edit/', views.source_ip_edit, name='source_ip_edit'),
    path('source-ips/bulk-activate/', views.source_ip_bulk_activate, name='source_ip_bulk_activate'),
    path('source-ips/bulk-deactivate/', views.source_ip_bulk_deactivate, name='source_ip_bulk_deactivate'),
    path('source-ips/bulk-delete/', views.source_ip_bulk_delete, name='source_ip_bulk_delete'),
    path('backup/now/', views.backup_now, name='backup_now'),
    path('activity-log/', views.activity_log, name='activity_log'),
    path('activity-log/export/', views.activity_log_export, name='activity_log_export'),
    path('role-matrix/', views.role_matrix, name='role_matrix'),
    path('threat-intel/abuseipdb/check-key/', views.abuseipdb_check_key, name='abuseipdb_check_key'),
    path('threat-intel/abuseipdb/refresh/', views.abuseipdb_refresh, name='abuseipdb_refresh'),
    path('threat-intel/abuseipdb/cleanup/', views.abuseipdb_run_cleanup, name='abuseipdb_run_cleanup'),
    path('threat-intel/virustotal/check-key/', views.virustotal_check_key, name='virustotal_check_key'),
    path('threat-intel/virustotal/refresh/', views.virustotal_refresh, name='virustotal_refresh'),
    path('threat-intel/virustotal/cleanup/', views.virustotal_run_cleanup, name='virustotal_run_cleanup'),
    path('actions/quota-test-mail/', views.actions_quota_test_mail, name='actions_quota_test_mail'),
    path('actions/smtp-test/',       views.actions_smtp_test,       name='actions_smtp_test'),
    path('actions/rate-limit-test-mail/', views.actions_rate_limit_test_mail, name='actions_rate_limit_test_mail'),
    path('actions/syslog-test/',          views.actions_syslog_test,          name='actions_syslog_test'),
]
