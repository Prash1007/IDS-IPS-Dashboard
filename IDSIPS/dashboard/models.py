# dashboard/models.py
from django.db import models
from django.utils import timezone

ALERT_SEVERITY_CHOICES = [
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]

SYSTEM_MODE_CHOICES = [
    ("IDS", "IDS"),
    ("IPS", "IPS"),
    ("HYBRID", "HYBRID"),
]


class Alert(models.Model):
    SEVERITY_CHOICES = ALERT_SEVERITY_CHOICES
    RESPONSE_CHOICES = [
        ("alerted", "Alerted"),
        ("watched", "Watched"),
        ("blocked-auto", "Blocked Automatically"),
        ("blocked-manual", "Blocked Manually"),
        ("blocked-existing", "Blocked By Existing Rule"),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    src_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    dest_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, default="tcp")
    attack_type = models.CharField(max_length=100, default="unknown")
    severity = models.CharField(max_length=10, choices=ALERT_SEVERITY_CHOICES, default="low")
    description = models.TextField(blank=True)
    handled = models.BooleanField(default=False)  # whether action taken (blocked)
    blocked = models.BooleanField(default=False)
    mode_at_detection = models.CharField(
        max_length=10,
        choices=SYSTEM_MODE_CHOICES,
        default="IDS",
    )
    response_action = models.CharField(
        max_length=30,
        choices=RESPONSE_CHOICES,
        default="alerted",
    )
    source = models.CharField(max_length=30, default="kafka")

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.timestamp} {self.src_ip} -> {self.attack_type}"


class BlockedIP(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    last_blocked_at = models.DateTimeField(default=timezone.now)
    last_unblocked_at = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=200, blank=True)
    attack_type = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=10, choices=ALERT_SEVERITY_CHOICES, default="low")
    source = models.CharField(max_length=20, default="manual")
    block_count = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.ip} ({'active' if self.active else 'inactive'})"


class SystemConfig(models.Model):
    MODE_CHOICES = SYSTEM_MODE_CHOICES
    # single-row config
    mode = models.CharField(max_length=10, choices=SYSTEM_MODE_CHOICES, default="IDS")
    next_rule_sid = models.PositiveIntegerField(default=1000001)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Mode: {self.mode}"

    def save(self, *args, **kwargs):
        # Ensure single row constraint (simple approach)
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_solo(cls):
        obj, created = cls.objects.get_or_create(pk=1, defaults={"mode": "IDS"})
        return obj


class SecurityAction(models.Model):
    ACTION_CHOICES = [
        ("BLOCK", "Block"),
        ("UNBLOCK", "Unblock"),
        ("MODE_CHANGE", "Mode Change"),
        ("AUTOMATION", "Automation"),
    ]

    SOURCE_CHOICES = [
        ("manual", "Manual"),
        ("automatic", "Automatic"),
        ("system", "System"),
        ("kafka", "Kafka"),
        ("api", "API"),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    action_type = models.CharField(max_length=20, choices=ACTION_CHOICES)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="system")
    ip = models.GenericIPAddressField(null=True, blank=True)
    mode = models.CharField(max_length=10, choices=SYSTEM_MODE_CHOICES, blank=True)
    reason = models.CharField(max_length=255, blank=True)
    attack_type = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=10, choices=ALERT_SEVERITY_CHOICES, blank=True)
    status = models.CharField(max_length=20, default="success")
    details = models.JSONField(default=dict, blank=True)
    alert = models.ForeignKey(
        Alert,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_actions",
    )

    class Meta:
        ordering = ["-timestamp", "-id"]

    def __str__(self):
        label = self.ip or self.mode or "system"
        return f"{self.action_type} {label}"


class SuricataRule(models.Model):
    SYNC_STATUS_CHOICES = [
        ("pending", "Pending"),
        ("synced", "Synced"),
        ("failed", "Failed"),
        ("local-only", "Local Only"),
    ]

    rule_id = models.CharField(max_length=64, unique=True)
    sid = models.PositiveIntegerField(unique=True)
    msg = models.CharField(max_length=255)
    action = models.CharField(max_length=20, default="alert")
    proto = models.CharField(max_length=20, default="tcp")
    enabled = models.BooleanField(default=True)
    comment = models.TextField(blank=True)
    definition = models.JSONField(default=dict, blank=True)
    raw_rule = models.TextField()
    sync_status = models.CharField(max_length=20, choices=SYNC_STATUS_CHOICES, default="pending")
    last_sync_error = models.TextField(blank=True)
    last_synced_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["sid", "created_at"]

    def __str__(self):
        return f"{self.sid} {self.msg}"


class OldAlertLog(models.Model):
    archived_at = models.DateTimeField(default=timezone.now)
    archive_batch_id = models.CharField(max_length=36, db_index=True)
    archive_reason = models.CharField(max_length=40, default="manual-admin")
    archived_by = models.CharField(max_length=150, blank=True)

    original_alert_id = models.PositiveIntegerField(db_index=True)
    original_timestamp = models.DateTimeField(db_index=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dest_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    dest_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, default="tcp")
    attack_type = models.CharField(max_length=100, default="unknown")
    severity = models.CharField(max_length=10, choices=ALERT_SEVERITY_CHOICES, default="low")
    description = models.TextField(blank=True)
    handled = models.BooleanField(default=False)
    blocked = models.BooleanField(default=False)
    mode_at_detection = models.CharField(
        max_length=10,
        choices=SYSTEM_MODE_CHOICES,
        default="IDS",
    )
    response_action = models.CharField(max_length=30, default="alerted")
    source = models.CharField(max_length=30, default="kafka")
    payload = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-archived_at", "-original_timestamp", "-id"]

    def __str__(self):
        return f"Archived alert {self.original_alert_id} ({self.attack_type})"
