from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('api-reference/', views.api_reference, name='api_reference'),
    path('api-reference/export-pdf/', views.api_reference_pdf, name='api_reference_pdf'),
    path('profile/token/generate/', views.generate_token, name='generate_token'),
    path('profile/token/revoke/', views.revoke_token, name='revoke_token'),
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:user_id>/role/', views.user_set_role, name='user_set_role'),
    path('users/<int:user_id>/toggle/', views.user_toggle_active, name='user_toggle_active'),
    path('users/bulk-activate/', views.user_bulk_activate, name='user_bulk_activate'),
    path('users/bulk-deactivate/', views.user_bulk_deactivate, name='user_bulk_deactivate'),
    path('users/bulk-delete/', views.user_bulk_delete, name='user_bulk_delete'),
    path('users/<int:user_id>/delete/', views.user_delete, name='user_delete'),
    path('users/<int:user_id>/update/', views.user_update, name='user_update'),
    path('users/ldap-import/', views.ldap_users_import, name='ldap_users_import'),
    path('users/<int:user_id>/password/', views.user_change_password, name='user_change_password'),
    path('users/<int:user_id>/token/generate/', views.user_generate_token, name='user_generate_token'),
    path('users/<int:user_id>/token/revoke/', views.user_revoke_token, name='user_revoke_token'),
]
