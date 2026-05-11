import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Write local Suricata remote-sync configuration for SSH automation."

    def add_arguments(self, parser):
        parser.add_argument("--host", default=settings.SURICATA_SSH_HOST)
        parser.add_argument("--port", type=int, default=settings.SURICATA_SSH_PORT or 22)
        parser.add_argument("--user", required=True)
        parser.add_argument("--key-path", default=settings.SURICATA_SSH_KEY_PATH or str((settings.BASE_DIR / "ssh.txt").resolve()))
        parser.add_argument("--rules-dir", default=settings.SURICATA_REMOTE_RULES_DIR)
        parser.add_argument("--reload-command", default=settings.SURICATA_REMOTE_RELOAD_COMMAND)
        parser.add_argument("--validate-command", default=settings.SURICATA_REMOTE_VALIDATE_COMMAND or "sudo suricata -T -c /etc/suricata/suricata.yaml")
        parser.add_argument("--home-net", default=settings.SURICATA_HOME_NET)

    def handle(self, *args, **options):
        if not options["host"]:
            raise CommandError("Provide --host or set SURICATA_SSH_HOST.")
        target = Path(settings.BASE_DIR) / "suricata_remote.local.json"
        key_path = Path(options["key_path"]).expanduser()
        if not key_path.is_absolute():
            key_path = (Path.cwd() / key_path).resolve()
        payload = {
            "suricata_ssh_host": options["host"],
            "suricata_ssh_port": options["port"],
            "suricata_ssh_user": options["user"],
            "suricata_ssh_key_path": str(key_path),
            "suricata_remote_rules_dir": options["rules_dir"],
            "suricata_remote_custom_rules_file": settings.SURICATA_REMOTE_CUSTOM_RULES_FILE,
            "suricata_remote_block_rules_file": settings.SURICATA_REMOTE_BLOCK_RULES_FILE,
            "suricata_remote_reload_command": options["reload_command"],
            "suricata_remote_validate_command": options["validate_command"],
            "suricata_home_net": options["home_net"],
        }
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Saved Suricata sync config to {target}"))
