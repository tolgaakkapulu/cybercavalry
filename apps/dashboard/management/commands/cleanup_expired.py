"""
Management command: python manage.py cleanup_expired
Deactivates expired blacklist entries and logs full entry details.
Add to cron: */15 * * * * /path/to/venv/bin/python manage.py cleanup_expired
"""
import logging

from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Deactivate expired blacklist entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Show what would be deactivated without making changes'
        )

    def handle(self, *args, **options):
        from apps.blacklist.models import BlacklistEntry
        from apps.settings_app.models import ActivityLog

        now = timezone.now()
        expired_qs = BlacklistEntry.objects.filter(
            is_active=True,
            expires_at__lt=now,
        ).select_related('group', 'added_by')

        # Materialise before update so we have full details for logging
        expired_entries = list(expired_qs)
        count = len(expired_entries)

        if options['dry_run']:
            self.stdout.write(f"[DRY RUN] Would deactivate {count} expired entries.")
            for e in expired_entries[:20]:
                self.stdout.write(f"  {e.cidr} | group={e.group.label} | expired={e.expires_at}")
            return

        if count == 0:
            logger.info("cleanup_expired: no expired blacklist entries found.")
            self.stdout.write("No expired blacklist entries found.")
            return

        # One ActivityLog row per entry — easier to filter/search than a single
        # bulk row carrying all of them inside a JSON list.
        for e in expired_entries:
            # Per-entry Python logger line (WARNING — security-relevant event)
            logger.warning(
                "Blacklist entry expired and deactivated: cidr=%s group=%s "
                "added_by=%s added_at=%s expires_at=%s hit_count=%d source=%s reason=%r",
                e.cidr,
                e.group.name,
                e.added_by.username if e.added_by else 'system',
                e.added_at.isoformat() if e.added_at else 'N/A',
                e.expires_at.isoformat() if e.expires_at else 'N/A',
                e.hit_count,
                e.source,
                e.reason,
            )
            ActivityLog.log(
                user=None,
                action='blacklist.entry_expired',
                target_model='BlacklistEntry',
                target_id=str(e.id),
                detail={
                    'cidr':                   e.cidr,
                    'ip_address':             e.ip_address,
                    'prefix_length':          e.prefix_length,
                    'group':                  e.group.name,
                    'group_label':            e.group.label,
                    'reason':                 e.reason,
                    'source':                 e.source,
                    'added_by':               e.added_by.username if e.added_by else None,
                    'added_at':               e.added_at.isoformat() if e.added_at else None,
                    'expires_at':             e.expires_at.isoformat() if e.expires_at else None,
                    'hit_count':              e.hit_count,
                    'last_seen_at':           e.last_seen_at.isoformat() if e.last_seen_at else None,
                    'abuse_confidence_score': e.abuse_confidence_score,
                    'reporter_ip':            e.reporter_ip,
                    'is_pinned':              e.is_pinned,
                    'deactivated_at':         now.isoformat(),
                    'trigger':                'manual',
                },
            )

        # Bulk deactivate
        BlacklistEntry.objects.filter(
            id__in=[e.id for e in expired_entries]
        ).update(is_active=False)

        logger.warning(
            "cleanup_expired: deactivated %d expired blacklist entries.", count
        )
        self.stdout.write(
            self.style.SUCCESS(f"Deactivated {count} expired blacklist entries.")
        )
