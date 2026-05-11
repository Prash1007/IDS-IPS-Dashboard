# dashboard/urls.py
from django.urls import path
from . import views

urlpatterns = [

    path("", views.index, name="index"),
    path("alerts/", views.alerts_page, name="alerts"),

    # Pages
    path("network-traffic/", views.network_traffic, name="network_traffic"),
    path("rule-manager/", views.rule_manager, name="rule_manager"),
    path("threat-map/", views.threat_map, name="threat_map"),
    path("reports/", views.reports_page, name="reports"),

    # APIs
    path("api/alerts/", views.alerts_api),
    path("api/stats/", views.stats_api),
    path("api/live-feed/", views.live_feed_api),
    path("api/block/", views.block_ip),
    path("api/unblock/", views.unblock_ip),
    path("api/mode/", views.toggle_mode),
    path("api/alerts/clear/", views.api_clear_alerts),
    path("api/ingest/", views.ingest_suricata),
    path("api/blocked-ips/", views.blocked_ips_api),
    path("api/actions/", views.security_actions_api),
    path("api/network-topology/", views.network_topology_api),
    path("api/threat-map/", views.threat_map_api),
    path("api/reports/", views.reports_api),

    # Rules
    path("api/rules/", views.api_rules_list),
    path("api/rules/create/", views.api_rules_create),
    path("api/rules/<str:rule_id>/", views.api_rules_detail),
    path("api/rules/file/", views.api_rules_file),

    # Suricata reload
    path("api/reload/", views.api_reload_suricata),
]
