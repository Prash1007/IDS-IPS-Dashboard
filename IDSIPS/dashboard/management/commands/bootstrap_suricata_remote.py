from django.core.management.base import BaseCommand, CommandError

from dashboard.suricata_sync import bootstrap_remote_suricata, connection_snapshot


class Command(BaseCommand):
    help = "Bootstrap Suricata remote config over SSH: rule files, YAML includes, and optional NFQUEUE rules."

    def add_arguments(self, parser):
        parser.add_argument("--queue-num", type=int, default=0)
        parser.add_argument("--skip-nfqueue", action="store_true")
        parser.add_argument("--suricata-config", default="/etc/suricata/suricata.yaml")
        parser.add_argument("--skip-validate", action="store_true")

    def handle(self, *args, **options):
        snapshot = connection_snapshot()
        self.stdout.write(
            f"Bootstrapping remote host: {snapshot['user']}@{snapshot['host']}:{snapshot['port']} | rules_dir={snapshot['rules_dir']}"
        )
        result = bootstrap_remote_suricata(
            queue_num=options["queue_num"],
            enable_nfq=not options["skip_nfqueue"],
            validate_after=not options["skip_validate"],
            suricata_config_path=options["suricata_config"],
        )
        if result.success:
            self.stdout.write(self.style.SUCCESS(result.message))
            return
        raise CommandError(result.message)
