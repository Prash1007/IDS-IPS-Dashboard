from __future__ import annotations

import uuid
import re
from datetime import timedelta
from ipaddress import ip_address

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Alert, BlockedIP, OldAlertLog, SecurityAction, SystemConfig

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

AUTO_BLOCK_KEYWORDS = (
    "scan",
    "brute",
    "inject",
    "exploit",
    "malware",
    "payload",
    "traversal",
    "ddos",
    "flood",
    "botnet",
    "shell",
    "ransom",
    "dos",
    "recon",
)

HYBRID_REPEAT_WINDOW = timedelta(minutes=10)
HYBRID_REPEAT_THRESHOLD = 3
ALERT_RETENTION_DAYS = 30
MAX_ATTACK_TYPE_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 4000
MAX_REASON_LENGTH = 255
MAX_PROTOCOL_LENGTH = 10
PROTOCOL_RE = re.compile(r"^[a-z0-9_-]{1,10}$")
DASHBOARD_CONTROL_PLANE_PREFIXES = ("172.17.",)
DASHBOARD_CONTROL_PLANE_DEFAULT_PORTS = {9092}


def normalize_severity(value: str | None) -> str:
    severity = (value or "low").strip().lower()
    return severity if severity in SEVERITY_RANK else "low"


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK[normalize_severity(value)]


def attack_is_aggressive(attack_type: str | None) -> bool:
    name = (attack_type or "").strip().lower()
    return any(keyword in name for keyword in AUTO_BLOCK_KEYWORDS)


def safe_port(value):
    try:
        port = int(value) if value not in ("", None) else None
    except (TypeError, ValueError):
        return None
    if port is None or not 0 <= port <= 65535:
        return None
    return port


def truncate_text(value, max_length: int, default: str = "") -> str:
    cleaned = str(value or default).strip()
    cleaned = " ".join(cleaned.splitlines())
    return cleaned[:max_length]


def clean_ip(value, *, required=False):
    raw = str(value or "").strip()
    if not raw:
        if required:
            raise ValueError("IP address is required")
        return None
    try:
        return str(ip_address(raw))
    except ValueError as exc:
        if required:
            raise ValueError("Invalid IP address") from exc
        return None


def clean_protocol(value) -> str:
    protocol = truncate_text(value, MAX_PROTOCOL_LENGTH, "tcp").lower() or "tcp"
    return protocol if PROTOCOL_RE.match(protocol) else "tcp"


def dashboard_control_plane_ports() -> set[int]:
    ports = set(DASHBOARD_CONTROL_PLANE_DEFAULT_PORTS)
    for server in str(getattr(settings, "KAFKA_BOOTSTRAP_SERVERS", "") or "").split(","):
        server = server.strip()
        if ":" not in server:
            continue
        port = safe_port(server.rsplit(":", 1)[-1])
        if port is not None:
            ports.add(port)
    return ports


def is_dashboard_control_plane_alert(payload: dict) -> bool:
    ports = {
        safe_port(payload.get("src_port")),
        safe_port(payload.get("dest_port")),
    }
    ports.discard(None)
    if not ports.intersection(dashboard_control_plane_ports()):
        return False

    ips = [
        clean_ip(payload.get("src_ip")),
        clean_ip(payload.get("dest_ip")),
    ]
    return any(
        ip and ip.startswith(DASHBOARD_CONTROL_PLANE_PREFIXES)
        for ip in ips
    )


def build_hop_path(src_ip: str | None, dest_ip: str | None) -> list[str]:
    path = []
    if src_ip:
        path.append(src_ip)
    if src_ip and dest_ip and src_ip != dest_ip:
        path.extend(["Edge Gateway", "Perimeter Firewall"])
    if dest_ip:
        path.append(dest_ip)
    return path


def record_security_action(
    *,
    action_type: str,
    source: str = "system",
    ip: str | None = None,
    mode: str = "",
    reason: str = "",
    attack_type: str = "",
    severity: str = "",
    status: str = "success",
    details: dict | None = None,
    alert: Alert | None = None,
) -> SecurityAction:
    clean_action_ip = clean_ip(ip) if ip else None
    return SecurityAction.objects.create(
        action_type=truncate_text(action_type, 20),
        source=truncate_text(source, 20, "system"),
        ip=clean_action_ip,
        mode=truncate_text(mode, 10),
        reason=truncate_text(reason, MAX_REASON_LENGTH),
        attack_type=truncate_text(attack_type, MAX_ATTACK_TYPE_LENGTH),
        severity=normalize_severity(severity) if severity else "",
        status=truncate_text(status, 20, "success"),
        details=details or {},
        alert=alert,
    )


def _alert_archive_payload(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "src_ip": alert.src_ip,
        "dest_ip": alert.dest_ip,
        "src_port": alert.src_port,
        "dest_port": alert.dest_port,
        "protocol": alert.protocol,
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "description": alert.description,
        "handled": alert.handled,
        "blocked": alert.blocked,
        "mode_at_detection": alert.mode_at_detection,
        "response_action": alert.response_action,
        "source": alert.source,
    }


@transaction.atomic
def archive_alert_queryset(queryset, *, reason: str = "manual-admin", actor: str = "system") -> int:
    alerts = list(queryset.order_by("timestamp", "id"))
    if not alerts:
        return 0

    batch_id = str(uuid.uuid4())
    now = timezone.now()
    OldAlertLog.objects.bulk_create(
        [
            OldAlertLog(
                archived_at=now,
                archive_batch_id=batch_id,
                archive_reason=reason,
                archived_by=actor or "system",
                original_alert_id=alert.id,
                original_timestamp=alert.timestamp,
                src_ip=alert.src_ip,
                dest_ip=alert.dest_ip,
                src_port=alert.src_port,
                dest_port=alert.dest_port,
                protocol=alert.protocol,
                attack_type=alert.attack_type,
                severity=alert.severity,
                description=alert.description,
                handled=alert.handled,
                blocked=alert.blocked,
                mode_at_detection=alert.mode_at_detection,
                response_action=alert.response_action,
                source=alert.source,
                payload=_alert_archive_payload(alert),
            )
            for alert in alerts
        ]
    )
    Alert.objects.filter(id__in=[alert.id for alert in alerts]).delete()
    record_security_action(
        action_type="AUTOMATION",
        source="system",
        reason=f"Archived and cleared {len(alerts)} alert(s).",
        status="success",
        details={"batch_id": batch_id, "count": len(alerts), "reason": reason, "actor": actor or "system"},
    )
    return len(alerts)


def archive_expired_alerts(*, now=None) -> int:
    cutoff = (now or timezone.now()) - timedelta(days=ALERT_RETENTION_DAYS)
    return archive_alert_queryset(
        Alert.objects.filter(timestamp__lt=cutoff),
        reason=f"retention-{ALERT_RETENTION_DAYS}d",
        actor="system",
    )


def sync_remote_suricata(reason: str):
    from .suricata_sync import sync_suricata_assets

    return sync_suricata_assets(reason=reason)


def should_auto_block(
    *,
    src_ip: str | None,
    attack_type: str | None,
    severity: str | None,
    mode: str,
) -> tuple[bool, str]:
    if not src_ip:
        return False, ""

    sev_value = normalize_severity(severity)
    sev_rank = severity_rank(sev_value)
    aggressive = attack_is_aggressive(attack_type)

    if mode == "IPS":
        if sev_rank >= 2 or aggressive:
            return True, "IPS mode automatically blocked the source IP."
        return False, ""

    if mode != "HYBRID":
        return False, ""

    if sev_rank >= 3:
        return True, "Hybrid mode blocked a high-severity attack source."

    repeat_count = Alert.objects.filter(
        src_ip=src_ip,
        timestamp__gte=timezone.now() - HYBRID_REPEAT_WINDOW,
    ).count()
    if sev_rank >= 2 and repeat_count >= HYBRID_REPEAT_THRESHOLD:
        return True, "Hybrid mode blocked a repeated medium-severity source."

    if aggressive and sev_rank >= 2:
        return True, "Hybrid mode blocked an aggressive attack pattern."

    return False, ""


@transaction.atomic
def apply_block(
    *,
    ip: str,
    reason: str = "",
    source: str = "manual",
    alert: Alert | None = None,
    attack_type: str = "",
    severity: str = "",
    mode: str = "",
    details: dict | None = None,
) -> BlockedIP:
    ip = clean_ip(ip, required=True)
    reason = truncate_text(reason, 200)
    attack_type = truncate_text(attack_type, MAX_ATTACK_TYPE_LENGTH)
    source = truncate_text(source, 20, "manual")
    now = timezone.now()
    blocked_ip, created = BlockedIP.objects.get_or_create(
        ip=ip,
        defaults={
            "reason": reason,
            "attack_type": attack_type,
            "severity": normalize_severity(severity),
            "source": source,
            "active": True,
            "first_seen": now,
            "last_seen": now,
            "last_blocked_at": now,
            "block_count": 1,
        },
    )

    if not created:
        was_active = blocked_ip.active
        blocked_ip.active = True
        blocked_ip.reason = reason or blocked_ip.reason
        blocked_ip.attack_type = attack_type or blocked_ip.attack_type
        blocked_ip.severity = normalize_severity(severity or blocked_ip.severity)
        blocked_ip.source = source
        blocked_ip.last_seen = now
        blocked_ip.last_blocked_at = now
        if not was_active:
            blocked_ip.block_count += 1
        blocked_ip.save()

    Alert.objects.filter(src_ip=ip).update(
        blocked=True,
        handled=True,
        response_action="blocked-manual" if source == "manual" else "blocked-auto",
    )
    if alert:
        alert.blocked = True
        alert.handled = True
        alert.response_action = "blocked-manual" if source == "manual" else "blocked-auto"
        alert.save(update_fields=["blocked", "handled", "response_action"])

    record_security_action(
        action_type="BLOCK",
        source=source,
        ip=ip,
        mode=mode,
        reason=reason,
        attack_type=attack_type,
        severity=severity,
        details=details or {},
        alert=alert,
    )
    return blocked_ip


@transaction.atomic
def remove_block(*, ip: str, source: str = "manual", mode: str = "") -> BlockedIP:
    ip = clean_ip(ip, required=True)
    blocked_ip = BlockedIP.objects.get(ip=ip)
    blocked_ip.active = False
    blocked_ip.last_seen = timezone.now()
    blocked_ip.last_unblocked_at = timezone.now()
    blocked_ip.save(update_fields=["active", "last_seen", "last_unblocked_at"])

    record_security_action(
        action_type="UNBLOCK",
        source=source,
        ip=ip,
        mode=mode,
        reason="IP manually unblocked.",
        attack_type=blocked_ip.attack_type,
        severity=blocked_ip.severity,
        details={"block_count": blocked_ip.block_count},
    )
    return blocked_ip


@transaction.atomic
def ingest_alert(payload: dict, *, source: str = "kafka") -> Alert | None:
    if is_dashboard_control_plane_alert(payload):
        return None

    config = SystemConfig.get_solo()
    src_ip = clean_ip(payload.get("src_ip"), required=True)
    dest_ip = clean_ip(payload.get("dest_ip"))
    severity = normalize_severity(payload.get("severity"))
    attack_type = truncate_text(payload.get("attack_type"), MAX_ATTACK_TYPE_LENGTH, "unknown") or "unknown"
    description = truncate_text(payload.get("description"), MAX_DESCRIPTION_LENGTH)
    protocol = clean_protocol(payload.get("protocol"))

    blocked_existing = src_ip and BlockedIP.objects.filter(ip=src_ip, active=True).exists()

    response_action = "alerted"
    handled = False
    blocked = False
    if blocked_existing:
        blocked = True
        handled = True
        response_action = "blocked-existing"
    elif config.mode == "HYBRID" and severity_rank(severity) == 2:
        response_action = "watched"

    alert = Alert.objects.create(
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=safe_port(payload.get("src_port")),
        dest_port=safe_port(payload.get("dest_port")),
        protocol=protocol,
        attack_type=attack_type,
        severity=severity,
        description=description,
        handled=handled,
        blocked=blocked,
        mode_at_detection=config.mode,
        response_action=response_action,
        source=source,
    )

    should_block, reason = should_auto_block(
        src_ip=src_ip,
        attack_type=attack_type,
        severity=severity,
        mode=config.mode,
    )
    if should_block:
        apply_block(
            ip=src_ip,
            reason=reason or description or f"{attack_type} detected",
            source="automatic",
            alert=alert,
            attack_type=attack_type,
            severity=severity,
            mode=config.mode,
            details={
                "path": build_hop_path(src_ip, dest_ip),
                "protocol": alert.protocol,
                "source": source,
            },
        )
        sync_remote_suricata(f"Automatic block sync for {src_ip}")

    return alert
