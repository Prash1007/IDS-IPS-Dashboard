# dashboard/admin.py
from django.contrib import admin
from .models import Alert, BlockedIP, OldAlertLog, SecurityAction, SuricataRule, SystemConfig
from .services import archive_alert_queryset

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "src_ip",
        "attack_type",
        "severity",
        "mode_at_detection",
        "response_action",
        "blocked",
        "handled",
    )
    list_filter = ("severity", "attack_type", "mode_at_detection", "blocked", "handled")
    search_fields = ("src_ip", "attack_type", "description", "dest_ip")
    actions = ("archive_and_clear_selected",)

    @admin.action(description="Archive and clear selected alerts")
    def archive_and_clear_selected(self, request, queryset):
        count = archive_alert_queryset(
            queryset,
            reason="manual-admin",
            actor=request.user.get_username() or "admin",
        )
        self.message_user(request, f"Archived and cleared {count} alert(s).")

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ("ip", "last_blocked_at", "attack_type", "severity", "source", "active")
    list_filter = ("active", "severity", "source")
    search_fields = ("ip", "reason", "attack_type")

@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    list_display = ("mode", "next_rule_sid", "updated")


@admin.register(SecurityAction)
class SecurityActionAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "action_type", "ip", "mode", "source", "status")
    list_filter = ("action_type", "mode", "source", "status")
    search_fields = ("ip", "reason", "attack_type")


@admin.register(SuricataRule)
class SuricataRuleAdmin(admin.ModelAdmin):
    list_display = ("sid", "msg", "action", "proto", "enabled", "sync_status", "last_synced_at")
    list_filter = ("action", "proto", "enabled", "sync_status")
    search_fields = ("msg", "comment", "rule_id")


@admin.register(OldAlertLog)
class OldAlertLogAdmin(admin.ModelAdmin):
    list_display = (
        "archived_at",
        "original_timestamp",
        "src_ip",
        "attack_type",
        "severity",
        "archive_reason",
        "archived_by",
    )
    list_filter = ("archive_reason", "severity", "blocked", "mode_at_detection", "source")
    search_fields = ("src_ip", "dest_ip", "attack_type", "description", "archive_batch_id")
    readonly_fields = (
        "archived_at",
        "archive_batch_id",
        "archive_reason",
        "archived_by",
        "original_alert_id",
        "original_timestamp",
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
        "protocol",
        "attack_type",
        "severity",
        "description",
        "handled",
        "blocked",
        "mode_at_detection",
        "response_action",
        "source",
        "payload",
    )
