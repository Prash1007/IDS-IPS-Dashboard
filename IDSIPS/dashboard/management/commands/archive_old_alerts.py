from django.core.management.base import BaseCommand

from dashboard.models import Alert
from dashboard.services import archive_alert_queryset, archive_expired_alerts


class Command(BaseCommand):
    help = "Archive old alerts into OldAlertLog and clear them from the live alert table."

    def add_arguments(self, parser):
        parser.add_argument("--all", action="store_true", help="Archive every active alert, not only 30-day-old alerts.")
        parser.add_argument("--actor", default="system", help="Name stored in OldAlertLog.archived_by.")

    def handle(self, *args, **options):
        if options["all"]:
            count = archive_alert_queryset(Alert.objects.all(), reason="manual-command", actor=options["actor"])
        else:
            count = archive_expired_alerts()
        self.stdout.write(self.style.SUCCESS(f"Archived and cleared {count} alert(s)."))
