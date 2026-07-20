"""
Management command: python manage.py create_api_token --username <username>
Generates an API token for a user.
"""
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Generate an API token for a user'

    def add_arguments(self, parser):
        parser.add_argument('--username', required=True, help='Username to generate token for')

    def handle(self, *args, **options):
        from django.contrib.auth.models import User
        from apps.accounts.models import UserProfile

        username = options['username']
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist.")

        profile, _ = UserProfile.objects.get_or_create(user=user)
        raw_token = profile.generate_api_token()

        self.stdout.write(self.style.SUCCESS(f"\nAPI token generated for '{username}'."))
        self.stdout.write(self.style.WARNING(f"Copy this token now — it will NOT be shown again:\n"))
        self.stdout.write(f"  {raw_token}\n")
        self.stdout.write("Usage:  Authorization: Token <token>")
