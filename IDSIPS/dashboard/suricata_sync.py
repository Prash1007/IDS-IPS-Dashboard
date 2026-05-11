from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass, field
from textwrap import dedent
from pathlib import PurePosixPath

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import BlockedIP, SecurityAction, SuricataRule, SystemConfig

VALID_RULE_ACTIONS = {"alert", "drop", "reject", "pass"}
RULE_PROTOCOL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
RULE_HEADER_TOKEN_RE = re.compile(r"^[!$A-Za-z0-9_./:\[\],-]{1,128}$")
RULE_OPTION_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.,-]{1,128}$")
RULE_REFERENCE_RE = re.compile(r"^[A-Za-z0-9_.,:/?&=%#+-]{0,200}$")
CUSTOM_RULE_SID_MIN = 1_000_001
BLOCK_RULE_SID_BASE = 9_800_000
SID_REV_RE = re.compile(r"\b(?:sid|rev):\s*\d+\s*;\s*")


class SuricataSyncError(Exception):
    pass


@dataclass
class SyncResult:
    configured: bool
    success: bool
    message: str
    files_synced: bool = False
    reloaded: bool = False
    details: dict = field(default_factory=dict)


def sync_configured() -> bool:
    return bool(getattr(settings, "SURICATA_SYNC_ENABLED", False))


def _to_int(value, default=0, *, minimum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    return parsed


def _safe_text(value, default=""):
    selected = default if value in (None, "") else value
    return str(selected).strip()


def _single_line(value, max_length=255, default=""):
    return " ".join(_safe_text(value, default).splitlines())[:max_length]


def _validate_rule_id(value: str) -> str:
    rule_id = _single_line(value, 64)
    if not RULE_ID_RE.match(rule_id):
        raise ValueError("Rule id may only contain letters, numbers, dot, dash, or underscore.")
    return rule_id


def _validate_header_token(value: str, field_name: str, default="any") -> str:
    token = _single_line(value, 128, default) or default
    if not RULE_HEADER_TOKEN_RE.match(token):
        raise ValueError(f"Invalid {field_name}. Avoid spaces, quotes, semicolons, and parentheses.")
    return token


def _validate_option_token(value: str, field_name: str, *, required=False) -> str:
    token = _single_line(value, 128)
    if not token:
        if required:
            raise ValueError(f"{field_name} is required")
        return ""
    if not RULE_OPTION_TOKEN_RE.match(token):
        raise ValueError(f"Invalid {field_name}.")
    return token


def _validate_reference(value: str) -> str:
    ref = _single_line(value, 200)
    if ref and not RULE_REFERENCE_RE.match(ref):
        raise ValueError("Invalid reference value.")
    return ref


def _quote_rule_value(value: str) -> str:
    cleaned = _single_line(value, 255)
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def _safe_rule_filename(value: str, default: str) -> str:
    filename = _single_line(value, 120, default) or default
    path = PurePosixPath(filename)
    if filename in {".", ".."} or path.name != filename:
        raise SuricataSyncError("Remote rule file names must be simple file names.")
    if not re.match(r"^[A-Za-z0-9_.-]{1,120}$", filename):
        raise SuricataSyncError("Remote rule file name contains unsafe characters.")
    return filename


def _option_line(name, value):
    return f"{name}:{value}; "


def _first_available_sid(*, start=CUSTOM_RULE_SID_MIN, excluding_pk=None) -> int:
    qs = SuricataRule.objects.all()
    if excluding_pk:
        qs = qs.exclude(pk=excluding_pk)
    used_sids = set(qs.values_list("sid", flat=True))
    sid = max(CUSTOM_RULE_SID_MIN, start)
    while sid in used_sids:
        sid += 1
    return sid


def next_custom_sid(*, excluding_pk=None) -> int:
    return _first_available_sid(excluding_pk=excluding_pk)


def _reserve_sid(value, *, instance: SuricataRule | None = None) -> int:
    sid = _to_int(value, default=0)
    if sid and sid < CUSTOM_RULE_SID_MIN:
        raise ValueError(f"SID must be >= {CUSTOM_RULE_SID_MIN}")

    excluding_pk = instance.pk if instance and instance.pk else None
    if sid:
        in_use = SuricataRule.objects.filter(sid=sid)
        if excluding_pk:
            in_use = in_use.exclude(pk=excluding_pk)
        if not in_use.exists():
            return sid
        return _first_available_sid(start=sid + 1, excluding_pk=excluding_pk)

    return next_custom_sid(excluding_pk=excluding_pk)


def bump_next_rule_sid(sid: int):
    config = SystemConfig.get_solo()
    next_sid = max(CUSTOM_RULE_SID_MIN, (sid or CUSTOM_RULE_SID_MIN) + 1)
    if config.next_rule_sid < next_sid:
        config.next_rule_sid = next_sid
        config.save(update_fields=["next_rule_sid", "updated"])


def _rule_signature_fingerprint(raw_rule: str) -> str:
    signatures = []
    for line in (raw_rule or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        compact = re.sub(r"\s+", " ", stripped)
        compact = SID_REV_RE.sub("", compact)
        signatures.append(compact.strip())
    return "\n".join(signatures)


def _ensure_unique_signature(normalized: dict, *, instance: SuricataRule | None = None):
    if not normalized.get("enabled", True):
        return
    fingerprint = _rule_signature_fingerprint(normalized.get("rawRule", ""))
    if not fingerprint:
        return

    qs = SuricataRule.objects.filter(enabled=True)
    if instance and instance.pk:
        qs = qs.exclude(pk=instance.pk)
    for existing in qs:
        if _rule_signature_fingerprint(existing.raw_rule) == fingerprint:
            raise ValueError(f"Duplicate rule signature already exists as SID {existing.sid}: {existing.msg}")


def normalize_rule_payload(payload: dict, *, fallback_rule_id: str | None = None) -> dict:
    action = _safe_text(payload.get("action"), "alert").lower()
    proto = _safe_text(payload.get("proto"), "tcp").lower()
    if action not in VALID_RULE_ACTIONS:
        raise ValueError("Invalid rule action")
    if not RULE_PROTOCOL_RE.match(proto):
        raise ValueError("Invalid rule protocol. Use letters, numbers, underscore, or dash only.")

    sid = _to_int(payload.get("sid"), default=0)
    if sid < CUSTOM_RULE_SID_MIN:
        raise ValueError(f"SID must be >= {CUSTOM_RULE_SID_MIN}")

    msg = _safe_text(payload.get("msg"))
    if not msg:
        raise ValueError("Message (msg) is required")
    msg = _single_line(msg, 255)

    direction = _single_line(payload.get("dir"), 2, "->") or "->"
    if direction not in {"->", "<>"}:
        raise ValueError("Invalid rule direction")

    thresh_type = _single_line(payload.get("threshType"), 20, "both") or "both"
    thresh_track = _single_line(payload.get("threshTrack"), 20, "by_src") or "by_src"
    if thresh_type not in {"both", "threshold", "limit"}:
        raise ValueError("Invalid threshold type")
    if thresh_track not in {"by_src", "by_dst"}:
        raise ValueError("Invalid threshold track")

    rule_id = _validate_rule_id(payload.get("id") or fallback_rule_id or f"r{uuid.uuid4().hex[:12]}")

    definition = {
        "rule_id": rule_id,
        "action": action,
        "proto": proto,
        "srcIp": _validate_header_token(payload.get("srcIp"), "source IP", "any"),
        "srcPort": _validate_header_token(payload.get("srcPort"), "source port", "any"),
        "dir": direction,
        "dstIp": _validate_header_token(payload.get("dstIp"), "destination IP", "any"),
        "dstPort": _validate_header_token(payload.get("dstPort"), "destination port", "any"),
        "msg": msg,
        "sid": sid,
        "rev": _to_int(payload.get("rev"), default=1, minimum=1),
        "classtype": _validate_option_token(payload.get("classtype"), "classtype"),
        "content": _single_line(payload.get("content"), 255),
        "flags": _validate_option_token(payload.get("flags"), "flags"),
        "flow": _validate_option_token(payload.get("flow"), "flow"),
        "priority": _to_int(payload.get("priority"), default=0, minimum=0),
        "ref": _validate_reference(payload.get("ref")),
        "comment": _single_line(payload.get("comment"), 255),
        "enabled": bool(payload.get("enabled", True)),
        "thresh": bool(payload.get("thresh", False)),
        "threshType": thresh_type,
        "threshTrack": thresh_track,
        "threshCount": _to_int(payload.get("threshCount"), default=5, minimum=1),
        "threshSecs": _to_int(payload.get("threshSecs"), default=60, minimum=1),
    }
    if definition["priority"] > 4:
        raise ValueError("Priority must be between 1 and 4")
    definition["rawRule"] = render_rule_entry(definition)
    return definition


def render_rule_entry(definition: dict) -> str:
    options = ""
    options += _option_line("msg", f'"{_quote_rule_value(definition["msg"])}"')
    if definition.get("content"):
        options += _option_line("content", f'"{_quote_rule_value(definition["content"])}"')
    if definition.get("flags"):
        options += _option_line("flags", definition["flags"])
    if definition.get("flow"):
        options += _option_line("flow", definition["flow"])
    if definition.get("thresh"):
        options += (
            "threshold:type "
            f'{definition.get("threshType", "both")}, '
            f'track {definition.get("threshTrack", "by_src")}, '
            f'count {definition.get("threshCount", 5)}, '
            f'seconds {definition.get("threshSecs", 60)}; '
        )
    if definition.get("classtype"):
        options += _option_line("classtype", definition["classtype"])
    if definition.get("priority"):
        options += _option_line("priority", definition["priority"])
    if definition.get("ref"):
        options += _option_line("reference", definition["ref"])
    options += _option_line("sid", definition["sid"])
    options += _option_line("rev", definition.get("rev", 1))

    rule = (
        f'{definition.get("action", "alert")} '
        f'{definition.get("proto", "tcp")} '
        f'{definition.get("srcIp", "any")} '
        f'{definition.get("srcPort", "any")} '
        f'{definition.get("dir", "->")} '
        f'{definition.get("dstIp", "any")} '
        f'{definition.get("dstPort", "any")} '
        f"({options})"
    )

    lines = []
    comment = definition.get("comment", "")
    if comment:
        comment = _single_line(comment, 255)
        border = "# " + "-" * min(50, len(comment) + 4)
        lines.extend([border, f"# {comment}", border])
    lines.append(rule if definition.get("enabled", True) else f"# DISABLED: {rule}")
    return "\n".join(lines)


def serialize_rule(rule: SuricataRule) -> dict:
    payload = dict(rule.definition or {})
    payload.update(
        {
            "id": rule.rule_id,
            "sid": rule.sid,
            "msg": rule.msg,
            "action": rule.action,
            "proto": rule.proto,
            "enabled": rule.enabled,
            "comment": rule.comment,
            "rawRule": rule.raw_rule,
            "syncStatus": rule.sync_status,
            "lastSyncError": rule.last_sync_error,
            "lastSyncedAt": rule.last_synced_at.isoformat() if rule.last_synced_at else None,
        }
    )
    return payload


@transaction.atomic
def save_rule_payload(payload: dict, *, instance: SuricataRule | None = None) -> SuricataRule:
    prepared = dict(payload)
    prepared["sid"] = _reserve_sid(prepared.get("sid"), instance=instance)
    normalized = normalize_rule_payload(prepared, fallback_rule_id=instance.rule_id if instance else None)
    _ensure_unique_signature(normalized, instance=instance)
    rule = instance or SuricataRule(rule_id=normalized["rule_id"])
    rule.rule_id = normalized["rule_id"]
    rule.sid = normalized["sid"]
    rule.msg = normalized["msg"]
    rule.action = normalized["action"]
    rule.proto = normalized["proto"]
    rule.enabled = normalized["enabled"]
    rule.comment = normalized["comment"]
    rule.definition = normalized
    rule.raw_rule = normalized["rawRule"]
    rule.sync_status = "pending"
    rule.last_sync_error = ""
    rule.save()
    bump_next_rule_sid(rule.sid)
    return rule


def generate_custom_rules_content(rules=None) -> str:
    rules = rules if rules is not None else SuricataRule.objects.order_by("sid")
    lines = [
        "# ======================================================",
        "# Dashboard managed Suricata rules",
        f"# Updated: {timezone.now().isoformat()}",
        "# ======================================================",
        "",
    ]
    seen_signatures = set()
    for rule in rules:
        fingerprint = _rule_signature_fingerprint(rule.raw_rule) if rule.enabled else ""
        if fingerprint:
            if fingerprint in seen_signatures:
                continue
            seen_signatures.add(fingerprint)
        lines.append(rule.raw_rule.strip())
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _render_block_rule(blocked_ip: BlockedIP, sid: int) -> str:
    msg = _quote_rule_value(f"Dashboard blocked IP {blocked_ip.ip}")
    home_net = _validate_header_token(getattr(settings, "SURICATA_HOME_NET", "$HOME_NET"), "HOME_NET", "$HOME_NET")
    return (
        f'drop ip {blocked_ip.ip} any <> {home_net} any '
        f'(msg:"{msg}"; sid:{sid}; rev:{max(blocked_ip.block_count, 1)};)'
    )


def generate_block_rules_content(blocked_ips=None) -> str:
    blocked_ips = blocked_ips if blocked_ips is not None else BlockedIP.objects.filter(active=True).order_by("ip")
    lines = [
        "# ======================================================",
        "# Dashboard managed blocked IP rules",
        f"# Updated: {timezone.now().isoformat()}",
        "# ======================================================",
        "",
    ]
    for index, blocked_ip in enumerate(blocked_ips):
        lines.append(f"# {blocked_ip.ip} | {blocked_ip.reason or blocked_ip.attack_type or 'Dashboard block'}")
        lines.append(_render_block_rule(blocked_ip, BLOCK_RULE_SID_BASE + index))
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def rules_file_snapshot() -> dict:
    custom_file = _safe_rule_filename(settings.SURICATA_REMOTE_CUSTOM_RULES_FILE, "dashboard_custom.rules")
    block_file = _safe_rule_filename(settings.SURICATA_REMOTE_BLOCK_RULES_FILE, "dashboard_block.rules")
    rules_dir = PurePosixPath(settings.SURICATA_REMOTE_RULES_DIR)
    custom_path = str(rules_dir / custom_file)
    block_path = str(rules_dir / block_file)
    return {
        "custom": {"path": custom_path, "content": generate_custom_rules_content()},
        "block": {"path": block_path, "content": generate_block_rules_content()},
        "configured": sync_configured(),
    }


def _connect_ssh():
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise SuricataSyncError("paramiko is not installed. Please install it before enabling remote sync.") from exc

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    known_hosts = getattr(settings, "SURICATA_SSH_KNOWN_HOSTS", "")
    if known_hosts:
        client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    elif getattr(settings, "SURICATA_SSH_ALLOW_UNKNOWN_HOSTS", False):
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    connect_kwargs = {
        "hostname": settings.SURICATA_SSH_HOST,
        "port": settings.SURICATA_SSH_PORT,
        "username": settings.SURICATA_SSH_USER,
        "timeout": 15,
        "look_for_keys": True,
        "allow_agent": True,
    }
    if settings.SURICATA_SSH_KEY_PATH:
        connect_kwargs["key_filename"] = settings.SURICATA_SSH_KEY_PATH
    if settings.SURICATA_SSH_PASSWORD:
        connect_kwargs["password"] = settings.SURICATA_SSH_PASSWORD
    client.connect(**connect_kwargs)
    return client


def _write_remote_file(sftp, remote_path: str, content: str):
    with sftp.file(remote_path, "w") as handle:
        handle.write(content)
        handle.flush()

def _run_remote_command(client, command: str) -> dict:
    stdin, stdout, stderr = client.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    return {
        "command": command,
        "exit_code": exit_code,
        "stdout": stdout.read().decode("utf-8", errors="replace").strip(),
        "stderr": stderr.read().decode("utf-8", errors="replace").strip(),
    }


def _record_sync_action(reason: str, status: str, details: dict):
    SecurityAction.objects.create(
        action_type="AUTOMATION",
        source="system",
        reason=reason,
        status=status,
        details=details,
    )


def sync_suricata_assets(*, reason: str, reload_engine: bool = True, rule_queryset=None) -> SyncResult:
    if not sync_configured():
        if rule_queryset is not None:
            rule_queryset.update(sync_status="local-only", last_sync_error="")
        result = SyncResult(
            configured=False,
            success=True,
            message="Saved locally. Remote Suricata sync is not configured yet.",
        )
        
        _record_sync_action(reason, "skipped", {"configured": False})
        
        return result

    snapshot = rules_file_snapshot()
    details = {
        "custom_path": snapshot["custom"]["path"],
        "block_path": snapshot["block"]["path"],
    }

    try:
        client = _connect_ssh()
        try:
            sftp = client.open_sftp()
            _write_remote_file(sftp, snapshot["custom"]["path"], snapshot["custom"]["content"])
            _write_remote_file(sftp, snapshot["block"]["path"], snapshot["block"]["content"])
            sftp.close()

            files_synced = True
            reloaded = False
            validate_command = getattr(settings, "SURICATA_REMOTE_VALIDATE_COMMAND", "")
            if validate_command:
                validate_result = _run_remote_command(client, validate_command)
                details["validate"] = validate_result
                if validate_result["exit_code"] != 0:
                    raise SuricataSyncError(validate_result["stderr"] or validate_result["stdout"] or "Remote validation failed")

            if reload_engine and getattr(settings, "SURICATA_REMOTE_RELOAD_COMMAND", ""):
                reload_result = _run_remote_command(client, settings.SURICATA_REMOTE_RELOAD_COMMAND)
                
                details["reload"] = reload_result
                if reload_result["exit_code"] != 0:
                    raise SuricataSyncError(reload_result["stderr"] or reload_result["stdout"] or "Remote reload failed")
                reloaded = True
        finally:
            client.close()
    except Exception as exc:
        if rule_queryset is not None:
            rule_queryset.update(sync_status="failed", last_sync_error=str(exc))
        _record_sync_action(reason, "failed", {**details, "error": str(exc)})
        return SyncResult(
            configured=True,
            success=False,
            message=f"Remote Suricata sync failed: {exc}",
            details=details,
        )

    if rule_queryset is not None:
        rule_queryset.update(sync_status="synced", last_sync_error="", last_synced_at=timezone.now())
    _record_sync_action(reason, "success", details)
    return SyncResult(
        configured=True,
        success=True,
        message="Remote Suricata sync completed successfully.",
        files_synced=files_synced,
        reloaded=reloaded,
        details=details,
    )


def connection_snapshot() -> dict:
    return {
        "configured": sync_configured(),
        "host": getattr(settings, "SURICATA_SSH_HOST", ""),
        "port": getattr(settings, "SURICATA_SSH_PORT", 22),
        "user": getattr(settings, "SURICATA_SSH_USER", ""),
        "key_path": getattr(settings, "SURICATA_SSH_KEY_PATH", ""),
        "rules_dir": getattr(settings, "SURICATA_REMOTE_RULES_DIR", "/etc/suricata/rules"),
        "custom_rules_file": getattr(settings, "SURICATA_REMOTE_CUSTOM_RULES_FILE", "dashboard_custom.rules"),
        "block_rules_file": getattr(settings, "SURICATA_REMOTE_BLOCK_RULES_FILE", "dashboard_block.rules"),
        "reload_command": getattr(settings, "SURICATA_REMOTE_RELOAD_COMMAND", ""),
        "validate_command": getattr(settings, "SURICATA_REMOTE_VALIDATE_COMMAND", ""),
    }


def _bootstrap_script(*, queue_num: int, enable_nfq: bool, suricata_config_path: str, rule_files: list[str], rules_dir: str) -> str:
    rule_items = ", ".join(repr(item) for item in rule_files)
    rules_dir = _single_line(rules_dir, 200, "/etc/suricata/rules")
    rules_dir_q = shlex.quote(rules_dir)
    custom_file = _safe_rule_filename(settings.SURICATA_REMOTE_CUSTOM_RULES_FILE, "dashboard_custom.rules")
    block_file = _safe_rule_filename(settings.SURICATA_REMOTE_BLOCK_RULES_FILE, "dashboard_block.rules")
    custom_path_q = shlex.quote(str(PurePosixPath(rules_dir) / custom_file))
    block_path_q = shlex.quote(str(PurePosixPath(rules_dir) / block_file))
    nfqueue_commands = ""
    if enable_nfq:
        nfqueue_commands = dedent(
            f"""
            sudo iptables -C INPUT -j NFQUEUE --queue-num {queue_num} >/dev/null 2>&1 || sudo iptables -I INPUT -j NFQUEUE --queue-num {queue_num}
            sudo iptables -C OUTPUT -j NFQUEUE --queue-num {queue_num} >/dev/null 2>&1 || sudo iptables -I OUTPUT -j NFQUEUE --queue-num {queue_num}
            """
        ).strip()

    python_script = dedent(
        f"""
        python3 - <<'PY'
        import re
        from pathlib import Path

        config_path = Path({suricata_config_path!r})
        text = config_path.read_text(encoding="utf-8")

        def replace_or_append(pattern, replacement, source):
            if re.search(pattern, source, flags=re.MULTILINE):
                return re.sub(pattern, replacement, source, count=1, flags=re.MULTILINE)
            source = source.rstrip() + "\\n"
            return source + replacement + "\\n"

        text = replace_or_append(
            r"^default-rule-path:\\s*.*$",
            "default-rule-path: {rules_dir}",
            text,
        )

        if "rule-files:" not in text:
            text = text.rstrip() + "\\n\\nrule-files:\\n"
        lines = text.splitlines()
        start = None
        for idx, line in enumerate(lines):
            if line.strip() == "rule-files:":
                start = idx
                break
        if start is None:
            raise RuntimeError("rule-files section could not be created")
        end = len(lines)
        for idx in range(start + 1, len(lines)):
            line = lines[idx]
            if line and not line.startswith(" ") and not line.startswith("\\t") and not line.startswith("-"):
                end = idx
                break
        existing = set()
        for idx in range(start + 1, end):
            stripped = lines[idx].strip()
            if stripped.startswith("- "):
                existing.add(stripped[2:].strip())
        for item in [{rule_items}]:
            if item not in existing:
                lines.insert(end, f"  - {{item}}")
                end += 1

        text = "\\n".join(lines) + "\\n"

        if "nfq:" not in text:
            text += "\\nnfq:\\n  mode: accept\\n"
        elif not re.search(r"^nfq:\\n(?:  .*\\n)*?  mode:\\s*accept\\s*$", text, flags=re.MULTILINE):
            text += "\\n# Dashboard bootstrap fallback\\nnfq:\\n  mode: accept\\n"

        if "unix-command:" not in text:
            text += "\\nunix-command:\\n  enabled: yes\\n  filename: /var/run/suricata-command.socket\\n"
        else:
            if not re.search(r"^unix-command:\\n(?:  .*\\n)*?  enabled:\\s*yes\\s*$", text, flags=re.MULTILINE):
                text += "\\n# Dashboard bootstrap fallback\\nunix-command:\\n  enabled: yes\\n  filename: /var/run/suricata-command.socket\\n"
            elif "/var/run/suricata-command.socket" not in text:
                text += "\\n# Dashboard bootstrap fallback\\nunix-command:\\n  enabled: yes\\n  filename: /var/run/suricata-command.socket\\n"

        config_path.write_text(text, encoding="utf-8")
        PY
        """
    ).strip()

    mkdirs = dedent(
        f"""
        sudo mkdir -p {rules_dir_q}
        sudo touch {custom_path_q}
        sudo touch {block_path_q}
        """
    ).strip()

    parts = [mkdirs, python_script]
    if nfqueue_commands:
        parts.append(nfqueue_commands)
    return "\n".join(parts)


def bootstrap_remote_suricata(
    *,
    queue_num: int = 0,
    enable_nfq: bool = True,
    validate_after: bool = True,
    suricata_config_path: str = "/etc/suricata/suricata.yaml",
) -> SyncResult:
    if not sync_configured():
        return SyncResult(
            configured=False,
            success=False,
            message="Remote Suricata sync is not configured. Set SSH host/user/key first.",
        )

    details = {
        "queue_num": queue_num,
        "enable_nfq": enable_nfq,
        "suricata_config_path": suricata_config_path,
    }
    rule_files = [
        "local.rules",
        _safe_rule_filename(settings.SURICATA_REMOTE_CUSTOM_RULES_FILE, "dashboard_custom.rules"),
        _safe_rule_filename(settings.SURICATA_REMOTE_BLOCK_RULES_FILE, "dashboard_block.rules"),
    ]

    script = _bootstrap_script(
        queue_num=queue_num,
        enable_nfq=enable_nfq,
        suricata_config_path=suricata_config_path,
        rule_files=rule_files,
        rules_dir=settings.SURICATA_REMOTE_RULES_DIR,
    )
    try:
        client = _connect_ssh()
        try:
            bootstrap_result = _run_remote_command(client, script)
            details["bootstrap"] = bootstrap_result
            if bootstrap_result["exit_code"] != 0:
                raise SuricataSyncError(bootstrap_result["stderr"] or bootstrap_result["stdout"] or "Remote bootstrap failed")

            if validate_after and getattr(settings, "SURICATA_REMOTE_VALIDATE_COMMAND", ""):
                validate_result = _run_remote_command(client, settings.SURICATA_REMOTE_VALIDATE_COMMAND)
                details["validate"] = validate_result
                if validate_result["exit_code"] != 0:
                    raise SuricataSyncError(validate_result["stderr"] or validate_result["stdout"] or "Remote validation failed after bootstrap")
        finally:
            client.close()
    except Exception as exc:
        _record_sync_action("Remote Suricata bootstrap", "failed", {**details, "error": str(exc)})
        return SyncResult(
            configured=True,
            success=False,
            message=f"Remote Suricata bootstrap failed: {exc}",
            details=details,
        )

    _record_sync_action("Remote Suricata bootstrap", "success", details)
    return SyncResult(
        configured=True,
        success=True,
        message="Remote Suricata bootstrap completed successfully.",
        details=details,
    )
