from django.core.management.base import BaseCommand, CommandError

from dashboard.suricata_sync import connection_snapshot, sync_suricata_assets


class Command(BaseCommand):
    help = "Push dashboard rule files and block rules to the remote Suricata host."

    def add_arguments(self, parser):
        parser.add_argument("--no-reload", action="store_true")

    def handle(self, *args, **options):
        snapshot = connection_snapshot()
        key_state = "configured" if snapshot.get("key_path") else "agent/password"
        self.stdout.write(
            f"Remote host: {snapshot['user']}@{snapshot['host']}:{snapshot['port']} | key={key_state}"
        )
        result = sync_suricata_assets(
            reason="Manual sync from management command",
            reload_engine=not options["no_reload"],
        )
        if result.success:
            self.stdout.write(self.style.SUCCESS(result.message))
            return
        raise CommandError(result.message)
