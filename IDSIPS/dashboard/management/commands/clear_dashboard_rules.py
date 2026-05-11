import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from dashboard.models import SuricataRule, SystemConfig
from dashboard.suricata_sync import next_custom_sid, serialize_rule, sync_suricata_assets


class Command(BaseCommand):
    help = "Backup and delete dashboard-managed Suricata rules from the local database."

    def add_arguments(self, parser):
        parser.add_argument("--sync", action="store_true", help="Push the empty dashboard rule file to remote Suricata.")
        parser.add_argument("--no-reload", action="store_true", help="Do not reload Suricata when --sync is used.")
        parser.add_argument("--no-backup", action="store_true", help="Skip writing a JSON backup before deletion.")

    def handle(self, *args, **options):
        rules = list(SuricataRule.objects.order_by("sid", "created_at"))
        backup_path = None

        if rules and not options["no_backup"]:
            stamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            backup_path = settings.BASE_DIR / f"dashboard_rule_backup_{stamp}.json"
            backup_path.write_text(
                json.dumps([serialize_rule(rule) for rule in rules], indent=2),
                encoding="utf-8",
            )
            self.stdout.write(f"Backup written: {backup_path}")

        deleted_count, _ = SuricataRule.objects.all().delete()
        config = SystemConfig.get_solo()
        config.next_rule_sid = next_custom_sid()
        config.save(update_fields=["next_rule_sid", "updated"])

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} dashboard rule row(s)."))
        self.stdout.write(f"Next dashboard SID: {config.next_rule_sid}")

        if options["sync"]:
            result = sync_suricata_assets(
                reason="Dashboard rules cleared from management command",
                reload_engine=not options["no_reload"],
            )
            if not result.success:
                raise CommandError(result.message)
            self.stdout.write(self.style.SUCCESS(result.message))

        if backup_path:
            self.stdout.write(f"Restore source if needed: {backup_path}")
