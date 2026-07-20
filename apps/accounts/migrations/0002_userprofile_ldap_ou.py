"""Add `UserProfile.ldap_ou` — first OU segment of the user's LDAP DN.

Populated on LDAP import and refreshed on every successful LDAP login so the
Users page (and the LDAP browse modal) can display which directory OU each
account belongs to. Empty for local accounts.
"""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('accounts', '0001_initial')]
    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='ldap_ou',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
    ]
