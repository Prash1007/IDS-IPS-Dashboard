import json
from collections import Counter, defaultdict
from datetime import timedelta
from functools import wraps
from hmac import compare_digest
from hashlib import md5

from django.conf import settings
from django.db.models import Count, Q
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_POST

from .models import Alert, BlockedIP, SecurityAction, SuricataRule, SystemConfig
from .services import (
    apply_block,
    archive_alert_queryset,
    attack_is_aggressive,
    build_hop_path,
    ingest_alert,
    normalize_severity,
    record_security_action,
    remove_block,
    severity_rank,
)
from .suricata_sync import (
    next_custom_sid,
    rules_file_snapshot,
    save_rule_payload,
    serialize_rule,
    sync_suricata_assets,
)

NETWORK_PORT_TYPES = {
    22: "workstation",
    25: "mailserver",
    53: "dns",
    80: "webserver",
    110: "mailserver",
    143: "mailserver",
    443: "webserver",
    587: "mailserver",
    993: "mailserver",
    995: "mailserver",
    3306: "dbserver",
    3389: "workstation",
    5432: "dbserver",
    6379: "dbserver",
    8080: "webserver",
    8443: "webserver",
}

PAGE_META = {
    "dashboard": ("Security Dashboard", "Live IDS/IPS telemetry and response controls"),
    "alerts": ("Alerts", "All detections, responses, and blocked-IP activity in one place"),
    "network-traffic": ("Network Traffic", "Live attack flows, traversal paths, and node activity"),
    "rule-manager": ("Rule Manager", "Manage Suricata rules without changing the dashboard styling"),
    "threat-map": ("Threat Map", "Threat corridors built from attack source and target IPs"),
    "reports": ("Reports", "Operational summaries and AI handoff readiness for future automation"),
}

TOPOLOGY_SPECIAL_NODES = (
    {
        "id": "edge-gateway",
        "ip": "gateway",
        "name": "Edge Gateway",
        "type": "router",
    },
    {
        "id": "perimeter-firewall",
        "ip": "firewall",
        "name": "Perimeter Firewall",
        "type": "firewall",
    },
    {
        "id": "monitored-assets",
        "ip": "internal-assets",
        "name": "Monitored Assets",
        "type": "workstation",
    },
)


def _staff_required_response(request):
    if not getattr(settings, "DASHBOARD_REQUIRE_STAFF_FOR_MUTATIONS", False):
        return None
    if request.user.is_authenticated and request.user.is_staff:
        return None
    return JsonResponse({"status": "error", "message": "Admin permission required"}, status=403)


def _read_required_response(request):
    if not getattr(settings, "DASHBOARD_REQUIRE_STAFF_FOR_READ_APIS", False):
        return None
    if request.user.is_authenticated and request.user.is_staff:
        return None
    return JsonResponse({"status": "error", "message": "Admin permission required"}, status=403)


def staff_mutation_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        denied = _staff_required_response(request)
        if denied:
            return denied
        return view_func(request, *args, **kwargs)

    return wrapped


def staff_read_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        denied = _read_required_response(request)
        if denied:
            return denied
        return view_func(request, *args, **kwargs)

    return wrapped


def _ingest_token_response(request):
    expected = getattr(settings, "IDS_INGEST_API_TOKEN", "")
    token_required = getattr(settings, "DASHBOARD_REQUIRE_INGEST_TOKEN", False) or bool(expected)
    if not token_required:
        return None

    supplied = request.headers.get("X-IDS-Token", "")
    auth_header = request.headers.get("Authorization", "")
    if not supplied and auth_header.lower().startswith("bearer "):
        supplied = auth_header[7:].strip()

    if expected and supplied and compare_digest(supplied, expected):
        return None
    return JsonResponse({"status": "error", "message": "Valid ingest token required"}, status=403)


def build_page_context(active_nav):
    config = SystemConfig.get_solo()
    title, subtitle = PAGE_META[active_nav]
    return {
        "mode": config.mode,
        "active_nav": active_nav,
        "page_title": title,
        "page_subtitle": subtitle,
    }


@ensure_csrf_cookie
def index(request):
    return render(request, "dashboard/index.html", build_page_context("dashboard"))


@ensure_csrf_cookie
def alerts_page(request):
    return render(request, "dashboard/alerts.html", build_page_context("alerts"))


@ensure_csrf_cookie
def network_traffic(request):
    return render(request, "dashboard/network_traffic.html", build_page_context("network-traffic"))


@ensure_csrf_cookie
def rule_manager(request):
    return render(request, "dashboard/rule_manager.html", build_page_context("rule-manager"))


@ensure_csrf_cookie
def threat_map(request):
    return render(request, "dashboard/threat_map.html", build_page_context("threat-map"))


@ensure_csrf_cookie
def reports_page(request):
    return render(request, "dashboard/reports.html", build_page_context("reports"))


def serialize_alert(alert):
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
        "blocked": alert.blocked,
        "handled": alert.handled,
        "mode_at_detection": alert.mode_at_detection,
        "response_action": alert.response_action,
        "source": alert.source,
        "path": build_hop_path(alert.src_ip, alert.dest_ip),
    }


def serialize_blocked_ip(blocked_ip):
    return {
        "id": blocked_ip.id,
        "ip": blocked_ip.ip,
        "first_seen": blocked_ip.first_seen.isoformat(),
        "last_seen": blocked_ip.last_seen.isoformat(),
        "last_blocked_at": blocked_ip.last_blocked_at.isoformat(),
        "last_unblocked_at": blocked_ip.last_unblocked_at.isoformat() if blocked_ip.last_unblocked_at else None,
        "reason": blocked_ip.reason,
        "attack_type": blocked_ip.attack_type,
        "severity": blocked_ip.severity,
        "source": blocked_ip.source,
        "block_count": blocked_ip.block_count,
        "active": blocked_ip.active,
    }


def serialize_action(action):
    return {
        "id": action.id,
        "timestamp": action.timestamp.isoformat(),
        "action_type": action.action_type,
        "source": action.source,
        "ip": action.ip,
        "mode": action.mode,
        "reason": action.reason,
        "attack_type": action.attack_type,
        "severity": action.severity,
        "status": action.status,
        "details": action.details,
        "alert_id": action.alert_id,
    }


def parse_int(value, default, *, minimum=None, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def parse_limit(value, default=None, *, minimum=1, maximum=None, allow_all=True):
    if value in (None, ""):
        return default
    if allow_all and str(value).strip().lower() in {"all", "none", "0"}:
        return None
    return parse_int(value, default if default is not None else minimum, minimum=minimum, maximum=maximum)


def limited_alerts_queryset(limit=None):
    qs = Alert.objects.order_by("-timestamp", "-id")
    if limit is None:
        return list(qs)
    return list(qs[:limit])


def build_stats_payload():
    config = SystemConfig.get_solo()
    last_24h_cutoff = timezone.now() - timedelta(hours=24)

    alerts = Alert.objects.all()
    last_24h_alerts = alerts.filter(timestamp__gte=last_24h_cutoff)
    blocked_qs = BlockedIP.objects.filter(active=True)
    recent_actions = SecurityAction.objects.order_by("-timestamp")[:6]

    severity_breakdown = {
        severity: alerts.filter(severity=severity).count()
        for severity in ("critical", "high", "medium", "low")
    }
    top_attacks = list(
        alerts.values("attack_type")
        .annotate(count=Count("attack_type"))
        .order_by("-count", "attack_type")[:8]
    )
    top_ips = list(
        alerts.values("src_ip")
        .annotate(count=Count("src_ip"))
        .order_by("-count", "src_ip")[:10]
    )

    auto_blocks = SecurityAction.objects.filter(action_type="BLOCK", source="automatic").count()
    manual_blocks = SecurityAction.objects.filter(action_type="BLOCK", source="manual").count()

    return {
        "total_alerts": alerts.count(),
        "last_24h": last_24h_alerts.count(),
        "blocked_ips": blocked_qs.count(),
        "auto_blocks": auto_blocks,
        "manual_blocks": manual_blocks,
        "top_ips": top_ips,
        "top_attacks": top_attacks,
        "severity_breakdown": severity_breakdown,
        "recent_actions": [serialize_action(action) for action in recent_actions],
        "mode": config.mode,
        "latest_alert_id": alerts.order_by("-id").values_list("id", flat=True).first() or 0,
        "latest_action_id": SecurityAction.objects.order_by("-id").values_list("id", flat=True).first() or 0,
    }


def classify_node_type(ip, related_alerts, *, dest_port=None, src_port=None, is_source=False, is_target=False):
    if not ip:
        return "workstation"

    high_signal = any(
        alert.blocked or severity_rank(alert.severity) >= 3 or attack_is_aggressive(alert.attack_type)
        for alert in related_alerts
    )

    is_external = not ip.startswith(("10.", "172.", "192.168.", "127."))
    if is_external:
        return "attacker" if high_signal else "external"

    if is_source and not is_target and high_signal:
        return "attacker"

    port = dest_port or src_port
    return NETWORK_PORT_TYPES.get(port, "workstation")


def build_topology_payload(limit=None):
    alerts = limited_alerts_queryset(limit)
    source_counts = Counter(alert.src_ip for alert in alerts if alert.src_ip)
    target_counts = Counter(alert.dest_ip for alert in alerts if alert.dest_ip)
    node_map = {
        node["id"]: {
            **node,
            "label": node["name"],
            "role": "network-path",
            "role_label": "Network Path",
            "source_count": 0,
            "target_count": 0,
            "alert_count": 0,
            "blocked": False,
            "severity": "low",
            "recent_attack_type": "",
            "connections": 0,
        }
        for node in TOPOLOGY_SPECIAL_NODES
    }
    edge_map = {}
    flow_items = []

    grouped_by_ip = defaultdict(list)
    for alert in alerts:
        grouped_by_ip[alert.src_ip].append(alert)
        if alert.dest_ip:
            grouped_by_ip[alert.dest_ip].append(alert)

    def role_for_ip(ip):
        source_count = source_counts.get(ip, 0)
        target_count = target_counts.get(ip, 0)
        if source_count and target_count:
            return "source-target", "Attack Source and Target"
        if source_count:
            return "attack-source", "Attack Source"
        if target_count:
            return "target", "Target IP"
        return "host", "Host"

    def ensure_node(ip, *, dest_port=None, src_port=None):
        if not ip:
            return node_map["monitored-assets"]
        node_id = f"node-{ip.replace('.', '-')}"
        if node_id not in node_map:
            related = grouped_by_ip[ip]
            role, role_label = role_for_ip(ip)
            node_type = classify_node_type(
                ip,
                related,
                dest_port=dest_port,
                src_port=src_port,
                is_source=source_counts.get(ip, 0) > 0,
                is_target=target_counts.get(ip, 0) > 0,
            )
            node_map[node_id] = {
                "id": node_id,
                "ip": ip,
                "name": ip,
                "label": ip,
                "type": node_type,
                "role": role,
                "role_label": role_label,
                "source_count": source_counts.get(ip, 0),
                "target_count": target_counts.get(ip, 0),
                "alert_count": 0,
                "blocked": False,
                "severity": "low",
                "recent_attack_type": "",
                "connections": 0,
            }
        return node_map[node_id]

    def flow_type(alert):
        if alert.blocked:
            return "blocked"
        if severity_rank(alert.severity) >= 3:
            return "attack"
        if severity_rank(alert.severity) == 2:
            return "scan"
        return "normal"

    def add_edge(from_node, to_node, alert):
        key = (from_node["id"], to_node["id"], flow_type(alert))
        if key not in edge_map:
            edge_map[key] = {
                "id": f"{from_node['id']}::{to_node['id']}::{flow_type(alert)}",
                "from": from_node["id"],
                "to": to_node["id"],
                "type": flow_type(alert),
                "count": 0,
                "protocols": set(),
                "latest_alert": "",
                "blocked": False,
            }
        edge = edge_map[key]
        edge["count"] += 1
        edge["protocols"].add(alert.protocol or "tcp")
        edge["latest_alert"] = alert.attack_type
        edge["blocked"] = edge["blocked"] or alert.blocked
        from_node["connections"] += 1
        to_node["connections"] += 1

    for alert in alerts:
        src_node = ensure_node(alert.src_ip, src_port=alert.src_port)
        dest_node = ensure_node(alert.dest_ip, dest_port=alert.dest_port)

        src_node["alert_count"] += 1
        src_node["blocked"] = src_node["blocked"] or alert.blocked
        src_node["recent_attack_type"] = alert.attack_type
        if severity_rank(alert.severity) >= severity_rank(src_node["severity"]):
            src_node["severity"] = alert.severity

        dest_node["alert_count"] += 1
        dest_node["blocked"] = dest_node["blocked"] or alert.blocked
        dest_node["recent_attack_type"] = alert.attack_type
        if severity_rank(alert.severity) >= severity_rank(dest_node["severity"]):
            dest_node["severity"] = alert.severity

        path_nodes = [src_node["id"]]
        src_external = src_node["type"] in {"attacker", "external"}
        if src_external:
            path_nodes.extend(["edge-gateway", "perimeter-firewall"])
        if dest_node["id"] != path_nodes[-1]:
            path_nodes.append(dest_node["id"])

        for from_id, to_id in zip(path_nodes, path_nodes[1:]):
            add_edge(node_map[from_id], node_map[to_id], alert)

        flow_items.append(
            {
                "alert_id": alert.id,
                "src_ip": alert.src_ip,
                "dest_ip": alert.dest_ip,
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "blocked": alert.blocked,
                "protocol": alert.protocol,
                "timestamp": alert.timestamp.isoformat(),
                "mode_at_detection": alert.mode_at_detection,
                "response_action": alert.response_action,
                "source_label": "Attack Source",
                "target_label": "Target IP",
                "path": build_hop_path(alert.src_ip, alert.dest_ip),
                "path_nodes": path_nodes,
                "description": alert.description,
            }
        )

    edges = []
    for edge in edge_map.values():
        edge["protocols"] = sorted(edge["protocols"])
        edges.append(edge)

    threat_flows = [edge for edge in edges if edge["type"] in {"attack", "blocked", "scan"}]
    clean_flows = [edge for edge in edges if edge["type"] == "normal"]

    return {
        "nodes": list(node_map.values()),
        "edges": edges,
        "flows": flow_items[:40],
        "meta": {
            "total_alerts": Alert.objects.count(),
            "included_alerts": len(alerts),
            "limit": limit,
        },
        "stats": {
            "active_flows": len(edges),
            "threat_flows": len(threat_flows),
            "clean_flows": len(clean_flows),
            "blocked_flows": len([edge for edge in edges if edge["blocked"]]),
            "unique_sources": len({alert.src_ip for alert in alerts if alert.src_ip}),
        },
    }


def stable_point(seed, left, width, top, height):
    digest = md5(seed.encode("utf-8")).hexdigest()
    x = left + (int(digest[:8], 16) % 1000) / 1000 * width
    y = top + (int(digest[8:16], 16) % 1000) / 1000 * height
    return round(x, 2), round(y, 2)


def build_threat_map_payload(limit=None):
    alerts = limited_alerts_queryset(limit)
    point_map = {}
    path_map = {}

    def ensure_point(ip, *, is_target=False):
        if not ip:
            ip = "monitored-assets"
            is_target = True

        point_id = f"point-{ip.replace('.', '-')}"
        if point_id not in point_map:
            if is_target:
                x, y = stable_point(ip, 58, 30, 18, 64)
                point_type = "target"
            else:
                x, y = stable_point(ip, 8, 36, 12, 72)
                point_type = "origin"
            point_map[point_id] = {
                "id": point_id,
                "ip": ip,
                "x": x,
                "y": y,
                "type": point_type,
                "role_label": "Target IP" if is_target else "Attack Source",
                "count": 0,
                "blocked": False,
                "latest_attack": "",
                "severity": "low",
            }
        return point_map[point_id]

    for alert in alerts:
        origin = ensure_point(alert.src_ip)
        target = ensure_point(alert.dest_ip, is_target=True)
        origin["count"] += 1
        origin["blocked"] = origin["blocked"] or alert.blocked
        origin["latest_attack"] = alert.attack_type
        if severity_rank(alert.severity) >= severity_rank(origin["severity"]):
            origin["severity"] = alert.severity

        target["count"] += 1
        target["latest_attack"] = alert.attack_type
        if severity_rank(alert.severity) >= severity_rank(target["severity"]):
            target["severity"] = alert.severity

        path_key = (origin["id"], target["id"], alert.blocked)
        if path_key not in path_map:
            path_map[path_key] = {
                "id": f"{origin['id']}::{target['id']}::{int(alert.blocked)}",
                "from": origin["id"],
                "to": target["id"],
                "source_ip": alert.src_ip,
                "target_ip": alert.dest_ip,
                "count": 0,
                "blocked": alert.blocked,
                "severity": alert.severity,
                "attack_type": alert.attack_type,
            }
        path_map[path_key]["count"] += 1
        if severity_rank(alert.severity) >= severity_rank(path_map[path_key]["severity"]):
            path_map[path_key]["severity"] = alert.severity
            path_map[path_key]["attack_type"] = alert.attack_type

    hotspots = sorted(
        [point for point in point_map.values() if point["type"] == "origin"],
        key=lambda item: (-item["count"], item["ip"]),
    )[:8]
    campaigns = Counter(alert.attack_type for alert in alerts).most_common(6)

    return {
        "points": list(point_map.values()),
        "paths": list(path_map.values()),
        "hotspots": hotspots,
        "campaigns": [{"attack_type": attack_type, "count": count} for attack_type, count in campaigns],
        "meta": {
            "total_alerts": Alert.objects.count(),
            "included_alerts": len(alerts),
            "limit": limit,
        },
        "summary": {
            "total_origins": len([point for point in point_map.values() if point["type"] == "origin"]),
            "total_targets": len([point for point in point_map.values() if point["type"] == "target"]),
            "blocked_origins": len([point for point in point_map.values() if point["type"] == "origin" and point["blocked"]]),
            "active_paths": len(path_map),
        },
    }


def build_reports_payload():
    now = timezone.now()
    alerts = list(Alert.objects.order_by("-timestamp")[:250])
    actions = list(SecurityAction.objects.order_by("-timestamp")[:120])
    blocked_ips = list(BlockedIP.objects.order_by("-last_blocked_at")[:20])

    daily_buckets = []
    for offset in range(6, -1, -1):
        day = (now - timedelta(days=offset)).date()
        count = Alert.objects.filter(timestamp__date=day).count()
        daily_buckets.append({"label": day.strftime("%d %b"), "count": count})

    action_breakdown = Counter(action.action_type for action in actions)
    source_breakdown = Counter(action.source for action in actions)

    recent_critical = [
        alert for alert in alerts
        if severity_rank(alert.severity) >= 3 and not alert.blocked
    ][:5]
    repeat_offenders = Counter(alert.src_ip for alert in alerts if alert.src_ip).most_common(5)

    automation_queue = []
    for alert in recent_critical:
        automation_queue.append(
            {
                "type": "Containment Candidate",
                "status": "pending",
                "title": f"Evaluate isolation playbook for {alert.src_ip}",
                "detail": f"{alert.attack_type} seen in {alert.mode_at_detection} mode at {alert.timestamp.strftime('%H:%M:%S')}.",
            }
        )
    for ip, count in repeat_offenders:
        if count < 3:
            continue
        automation_queue.append(
            {
                "type": "Behavior Model",
                "status": "watch",
                "title": f"Train repeat-offender response for {ip}",
                "detail": f"{count} alerts in the recent report window. Candidate for automated escalation.",
            }
        )
    if not automation_queue:
        automation_queue.append(
            {
                "type": "Readiness",
                "status": "ready",
                "title": "AI action queue is ready for model outputs",
                "detail": "Connect your trained model to these APIs to replace heuristics with real AI actions.",
            }
        )

    return {
        "summary": {
            "total_alerts": Alert.objects.count(),
            "last_24h": Alert.objects.filter(timestamp__gte=now - timedelta(hours=24)).count(),
            "active_blocks": BlockedIP.objects.filter(active=True).count(),
            "auto_blocks": SecurityAction.objects.filter(action_type="BLOCK", source="automatic").count(),
            "manual_blocks": SecurityAction.objects.filter(action_type="BLOCK", source="manual").count(),
            "mode": SystemConfig.get_solo().mode,
        },
        "daily_alerts": daily_buckets,
        "action_breakdown": [{"label": label, "count": count} for label, count in action_breakdown.items()],
        "source_breakdown": [{"label": label, "count": count} for label, count in source_breakdown.items()],
        "top_attacks": [{"attack_type": label, "count": count} for label, count in Counter(alert.attack_type for alert in alerts).most_common(6)],
        "blocked_ips": [serialize_blocked_ip(blocked_ip) for blocked_ip in blocked_ips],
        "recent_actions": [serialize_action(action) for action in actions[:10]],
        "automation_queue": automation_queue[:8],
    }


@staff_read_required
def api_rules_list(request):
    if request.method == "GET":
        rules = [serialize_rule(rule) for rule in SuricataRule.objects.order_by("sid", "created_at")]
        return JsonResponse({"rules": rules, "next_sid": next_custom_sid()})

    if request.method == "POST":
        return api_rules_create(request)

    return HttpResponseBadRequest("Unsupported method")


@require_POST
@staff_mutation_required
def api_rules_create(request):
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    try:
        rule = save_rule_payload(payload)
    except ValueError as exc:
        return JsonResponse({"status": "error", "message": str(exc)}, status=400)
    except Exception:
        return JsonResponse({"status": "error", "message": "Could not save rule"}, status=400)

    sync_result = sync_suricata_assets(
        reason=f"Rule {rule.sid} created from dashboard",
        rule_queryset=SuricataRule.objects.filter(pk=rule.pk),
    )
    rule.refresh_from_db()
    return JsonResponse(
        {
            "status": "ok" if sync_result.success else "warning",
            "id": rule.rule_id,
            "rule": serialize_rule(rule),
            "sync": {
                "configured": sync_result.configured,
                "success": sync_result.success,
                "message": sync_result.message,
                "reloaded": sync_result.reloaded,
            },
            "next_sid": next_custom_sid(),
        }
    )


@staff_read_required
def api_rules_detail(request, rule_id):
    try:
        rule = SuricataRule.objects.get(rule_id=rule_id)
    except SuricataRule.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Rule not found"}, status=404)

    if request.method == "GET":
        return JsonResponse({"status": "ok", "rule": serialize_rule(rule)})

    if request.method in {"PUT", "PATCH"}:
        denied = _staff_required_response(request)
        if denied:
            return denied
        try:
            payload = json.loads(request.body)
        except json.JSONDecodeError:
            return HttpResponseBadRequest("Invalid JSON")

        merged_payload = dict(rule.definition or {})
        merged_payload.update(payload)
        merged_payload["id"] = rule.rule_id
        if request.method == "PATCH" and "enabled" in payload and len(payload.keys()) == 1:
            merged_payload["enabled"] = bool(payload["enabled"])
        try:
            rule = save_rule_payload(merged_payload, instance=rule)
        except ValueError as exc:
            return JsonResponse({"status": "error", "message": str(exc)}, status=400)
        except Exception:
            return JsonResponse({"status": "error", "message": "Could not save rule"}, status=400)

        sync_result = sync_suricata_assets(
            reason=f"Rule {rule.sid} updated from dashboard",
            rule_queryset=SuricataRule.objects.filter(pk=rule.pk),
        )
        rule.refresh_from_db()
        return JsonResponse(
            {
                "status": "ok" if sync_result.success else "warning",
                "id": rule.rule_id,
                "rule": serialize_rule(rule),
                "sync": {
                    "configured": sync_result.configured,
                    "success": sync_result.success,
                    "message": sync_result.message,
                    "reloaded": sync_result.reloaded,
                },
                "next_sid": next_custom_sid(),
            }
        )

    if request.method == "DELETE":
        denied = _staff_required_response(request)
        if denied:
            return denied
        sid = rule.sid
        rule.delete()
        sync_result = sync_suricata_assets(reason=f"Rule {sid} deleted from dashboard")
        return JsonResponse(
            {
                "status": "ok" if sync_result.success else "warning",
                "id": rule_id,
                "sync": {
                    "configured": sync_result.configured,
                    "success": sync_result.success,
                    "message": sync_result.message,
                    "reloaded": sync_result.reloaded,
                },
                "next_sid": next_custom_sid(),
            }
        )

    return HttpResponseBadRequest("Unsupported method")


@staff_read_required
def api_rules_file(request):
    snapshot = rules_file_snapshot()
    return JsonResponse(
        {
            "configured": snapshot["configured"],
            "files": {
                "custom": snapshot["custom"],
                "block": snapshot["block"],
            },
        }
    )


@require_POST
@staff_mutation_required
def api_reload_suricata(request):
    sync_result = sync_suricata_assets(reason="Manual Suricata reload triggered from dashboard")
    return JsonResponse(
        {
            "message": sync_result.message,
            "configured": sync_result.configured,
            "success": sync_result.success,
            "reloaded": sync_result.reloaded,
        }
    )


@staff_read_required
def alerts_api(request):
    """
    Returns alerts as JSON.

    Filters:
      ?limit=200 or ?limit=all
      ?ip=10.0.0.1
      ?attack_type=scan
      ?severity=high
      ?response_action=blocked-auto
      ?blocked_only=1
      ?start=ISO_DATETIME
      ?end=ISO_DATETIME
    """
    limit = parse_limit(request.GET.get("limit"), None, minimum=1, maximum=20000)
    qs = Alert.objects.all()

    ip = request.GET.get("ip")
    if ip:
        qs = qs.filter(Q(src_ip__icontains=ip) | Q(dest_ip__icontains=ip))

    attack_type = request.GET.get("attack_type")
    if attack_type:
        qs = qs.filter(attack_type__icontains=attack_type)

    severity = request.GET.get("severity")
    if severity:
        qs = qs.filter(severity=normalize_severity(severity))

    response_action = request.GET.get("response_action")
    if response_action:
        qs = qs.filter(response_action=response_action)

    blocked_only = request.GET.get("blocked_only")
    if blocked_only in {"1", "true", "True"}:
        qs = qs.filter(blocked=True)

    start = request.GET.get("start")
    end = request.GET.get("end")
    if start:
        dt = parse_datetime(start)
        if dt:
            qs = qs.filter(timestamp__gte=dt)
    if end:
        dt = parse_datetime(end)
        if dt:
            qs = qs.filter(timestamp__lte=dt)

    total = qs.count()
    ordered = qs.order_by("-timestamp", "-id")
    alerts = list(ordered if limit is None else ordered[:limit])
    return JsonResponse(
        {
            "alerts": [serialize_alert(alert) for alert in alerts],
            "total": total,
            "returned": len(alerts),
            "limit": limit,
        }
    )


@staff_read_required
def blocked_ips_api(request):
    limit = parse_int(request.GET.get("limit"), 100, minimum=1, maximum=500)
    active_only = request.GET.get("active_only") in {"1", "true", "True"}
    qs = BlockedIP.objects.all()
    if active_only:
        qs = qs.filter(active=True)
    blocked_ips = qs.order_by("-active", "-last_blocked_at")[:limit]
    return JsonResponse({"blocked_ips": [serialize_blocked_ip(blocked_ip) for blocked_ip in blocked_ips]})


@staff_read_required
def security_actions_api(request):
    limit = parse_int(request.GET.get("limit"), 50, minimum=1, maximum=200)
    actions = SecurityAction.objects.order_by("-timestamp", "-id")[:limit]
    return JsonResponse({"actions": [serialize_action(action) for action in actions]})


@staff_read_required
def live_feed_api(request):
    since_alert_id = parse_int(request.GET.get("since_alert_id"), 0, minimum=0)
    since_action_id = parse_int(request.GET.get("since_action_id"), 0, minimum=0)

    new_alerts = Alert.objects.filter(id__gt=since_alert_id).order_by("-id")[:80]
    new_actions = SecurityAction.objects.filter(id__gt=since_action_id).order_by("-id")[:40]

    latest_alert_id = Alert.objects.order_by("-id").values_list("id", flat=True).first() or 0
    latest_action_id = SecurityAction.objects.order_by("-id").values_list("id", flat=True).first() or 0

    return JsonResponse(
        {
            "alerts": [serialize_alert(alert) for alert in new_alerts],
            "actions": [serialize_action(action) for action in new_actions],
            "stats": build_stats_payload(),
            "latest_alert_id": latest_alert_id,
            "latest_action_id": latest_action_id,
        }
    )


@staff_read_required
def stats_api(request):
    return JsonResponse(build_stats_payload())


@require_POST
def api_clear_alerts(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return JsonResponse({"status": "error", "message": "Admin permission required"}, status=403)

    count = archive_alert_queryset(
        Alert.objects.all(),
        reason="manual-admin",
        actor=request.user.get_username() or "admin",
    )
    return JsonResponse({"status": "ok", "archived": count})


@staff_read_required
def network_topology_api(request):
    limit = parse_limit(request.GET.get("limit"), None, minimum=10, maximum=20000)
    return JsonResponse(build_topology_payload(limit=limit))


@staff_read_required
def threat_map_api(request):
    limit = parse_limit(request.GET.get("limit"), None, minimum=10, maximum=20000)
    return JsonResponse(build_threat_map_payload(limit=limit))


@staff_read_required
def reports_api(request):
    return JsonResponse(build_reports_payload())


@require_POST
@staff_mutation_required
def block_ip(request):
    try:
        payload = json.loads(request.body)
        ip = payload.get("ip")
        reason = payload.get("reason", "")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    if not ip:
        return HttpResponseBadRequest("Missing ip")

    config = SystemConfig.get_solo()
    try:
        blocked_ip = apply_block(
            ip=ip,
            reason=reason or "Manual block from dashboard",
            source="manual",
            mode=config.mode,
            details={"via": "dashboard-api"},
        )
    except ValueError as exc:
        return JsonResponse({"status": "error", "message": str(exc)}, status=400)
    sync_result = sync_suricata_assets(reason=f"Manual block sync for {ip}")
    return JsonResponse(
        {
            "status": "ok" if sync_result.success else "warning",
            "ip": ip,
            "block_count": blocked_ip.block_count,
            "sync": {
                "configured": sync_result.configured,
                "success": sync_result.success,
                "message": sync_result.message,
                "reloaded": sync_result.reloaded,
            },
        }
    )


@require_POST
@staff_mutation_required
def unblock_ip(request):
    try:
        payload = json.loads(request.body)
        ip = payload.get("ip")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    if not ip:
        return HttpResponseBadRequest("Missing ip")

    try:
        blocked_ip = remove_block(ip=ip, source="manual", mode=SystemConfig.get_solo().mode)
    except ValueError as exc:
        return JsonResponse({"status": "error", "message": str(exc)}, status=400)
    except BlockedIP.DoesNotExist:
        return HttpResponseBadRequest("IP not blocked")

    sync_result = sync_suricata_assets(reason=f"Manual unblock sync for {ip}")
    return JsonResponse(
        {
            "status": "ok" if sync_result.success else "warning",
            "ip": ip,
            "active": blocked_ip.active,
            "sync": {
                "configured": sync_result.configured,
                "success": sync_result.success,
                "message": sync_result.message,
                "reloaded": sync_result.reloaded,
            },
        }
    )


@require_POST
@staff_mutation_required
def toggle_mode(request):
    try:
        payload = json.loads(request.body)
        mode = payload.get("mode")
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    if mode not in dict(SystemConfig.MODE_CHOICES):
        return HttpResponseBadRequest("Invalid mode")

    config = SystemConfig.get_solo()
    previous_mode = config.mode
    config.mode = mode
    config.save()

    record_security_action(
        action_type="MODE_CHANGE",
        source="manual",
        mode=mode,
        reason=f"Mode changed from {previous_mode} to {mode}.",
        details={"previous_mode": previous_mode, "next_mode": mode},
    )
    return JsonResponse({"status": "ok", "mode": mode, "previous_mode": previous_mode})


@csrf_exempt
@require_POST
def ingest_suricata(request):
    denied = _ingest_token_response(request)
    if denied:
        return denied

    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    try:
        alert = ingest_alert(payload, source="api")
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        return JsonResponse({"error": str(exc)}, status=400)

    if alert is None:
        return JsonResponse({"status": "ignored", "reason": "dashboard-control-plane"})

    return JsonResponse({"status": "ingested", "alert": serialize_alert(alert)})
