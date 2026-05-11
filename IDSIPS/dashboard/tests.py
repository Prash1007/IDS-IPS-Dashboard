from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Alert, BlockedIP, OldAlertLog, SecurityAction, SuricataRule, SystemConfig
from .suricata_sync import next_custom_sid


class DashboardPageTests(TestCase):
    def setUp(self):
        config = SystemConfig.get_solo()
        config.mode = "IPS"
        config.save()

    def test_pages_include_mode_and_active_nav_context(self):
        cases = [
            ("index", "dashboard"),
            ("alerts", "alerts"),
            ("rule_manager", "rule-manager"),
            ("network_traffic", "network-traffic"),
            ("threat_map", "threat-map"),
            ("reports", "reports"),
        ]

        for route_name, active_nav in cases:
            with self.subTest(route_name=route_name):
                response = self.client.get(reverse(route_name))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["mode"], "IPS")
                self.assertEqual(response.context["active_nav"], active_nav)


class DashboardApiTests(TestCase):
    def setUp(self):
        config = SystemConfig.get_solo()
        config.mode = "HYBRID"
        config.save()

    def test_stats_api_returns_totals_and_mode(self):
        now = timezone.now()
        Alert.objects.create(
            src_ip="203.0.113.10",
            dest_ip="192.168.1.10",
            attack_type="port-scan",
            severity="high",
            timestamp=now,
        )
        Alert.objects.create(
            src_ip="203.0.113.10",
            dest_ip="192.168.1.11",
            attack_type="sql-injection",
            severity="medium",
            timestamp=now - timedelta(days=2),
        )
        BlockedIP.objects.create(ip="203.0.113.10", active=True)

        response = self.client.get("/api/stats/")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(payload["total_alerts"], 2)
        self.assertEqual(payload["last_24h"], 1)
        self.assertEqual(payload["blocked_ips"], 1)
        self.assertEqual(payload["mode"], "HYBRID")
        self.assertEqual(payload["top_ips"][0]["src_ip"], "203.0.113.10")
        self.assertEqual(payload["top_ips"][0]["count"], 2)

    def test_alerts_api_serializes_null_destination_ip(self):
        Alert.objects.create(
            src_ip="198.51.100.15",
            dest_ip=None,
            attack_type="ping",
            severity="low",
        )

        response = self.client.get("/api/alerts/?limit=1")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(len(payload["alerts"]), 1)
        self.assertIsNone(payload["alerts"][0]["dest_ip"])

    def test_alerts_api_can_return_all_active_alerts(self):
        for index in range(3):
            Alert.objects.create(
                src_ip=f"198.51.100.{index + 1}",
                dest_ip="192.168.1.10",
                attack_type="web-test",
                severity="low",
            )

        response = self.client.get("/api/alerts/?limit=all")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total"], 3)
        self.assertEqual(payload["returned"], 3)
        self.assertEqual(len(payload["alerts"]), 3)

    def test_old_alerts_stay_live_until_admin_archives(self):
        Alert.objects.create(
            src_ip="198.51.100.200",
            dest_ip="192.168.1.200",
            attack_type="old-but-live",
            severity="medium",
            timestamp=timezone.now() - timedelta(days=60),
        )

        stats_response = self.client.get("/api/stats/")
        alerts_response = self.client.get("/api/alerts/?limit=all")

        self.assertEqual(stats_response.status_code, 200)
        self.assertEqual(alerts_response.status_code, 200)
        self.assertEqual(stats_response.json()["total_alerts"], 1)
        self.assertEqual(alerts_response.json()["alerts"][0]["attack_type"], "old-but-live")

    def test_ingest_ignores_dashboard_kafka_docker_alerts(self):
        response = self.client.post(
            "/api/ingest/",
            data='{"src_ip":"172.17.0.1","dest_ip":"172.17.0.2","src_port":44106,"dest_port":9092,"attack_type":"XSS script tag","severity":"medium"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ignored")
        self.assertEqual(Alert.objects.count(), 0)

    def test_ips_mode_auto_blocks_medium_alert(self):
        config = SystemConfig.get_solo()
        config.mode = "IPS"
        config.save()

        response = self.client.post(
            "/api/ingest/",
            data='{"src_ip":"203.0.113.9","dest_ip":"192.168.1.10","attack_type":"port-scan","severity":"medium"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

        alert = Alert.objects.get(src_ip="203.0.113.9")
        self.assertTrue(alert.blocked)
        self.assertEqual(alert.response_action, "blocked-auto")
        self.assertTrue(BlockedIP.objects.filter(ip="203.0.113.9", active=True).exists())
        self.assertTrue(SecurityAction.objects.filter(action_type="BLOCK", ip="203.0.113.9").exists())

    def test_hybrid_mode_blocks_repeated_medium_alert_source(self):
        config = SystemConfig.get_solo()
        config.mode = "HYBRID"
        config.save()

        payload = '{"src_ip":"198.51.100.77","dest_ip":"192.168.1.12","attack_type":"anomalous-session","severity":"medium"}'
        for expected_count in (1, 2):
            response = self.client.post("/api/ingest/", data=payload, content_type="application/json")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(Alert.objects.filter(src_ip="198.51.100.77").count(), expected_count)
            self.assertFalse(BlockedIP.objects.filter(ip="198.51.100.77", active=True).exists())

        response = self.client.post("/api/ingest/", data=payload, content_type="application/json")
        self.assertEqual(response.status_code, 200)

        alerts = Alert.objects.filter(src_ip="198.51.100.77").order_by("id")
        self.assertEqual(alerts.count(), 3)
        self.assertTrue(all(alert.blocked for alert in alerts))
        self.assertTrue(BlockedIP.objects.filter(ip="198.51.100.77", active=True).exists())

    def test_staff_clear_alerts_archives_to_old_logs(self):
        Alert.objects.create(
            src_ip="198.51.100.42",
            dest_ip="192.168.1.42",
            attack_type="ssh-bruteforce",
            severity="high",
        )
        user = get_user_model().objects.create_user(
            username="admin",
            password="pass",
            is_staff=True,
        )
        self.client.force_login(user)

        response = self.client.post("/api/alerts/clear/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["archived"], 1)
        self.assertEqual(Alert.objects.count(), 0)
        self.assertEqual(OldAlertLog.objects.count(), 1)
        self.assertEqual(OldAlertLog.objects.first().attack_type, "ssh-bruteforce")


@override_settings(SURICATA_SYNC_ENABLED=False, SURICATA_SSH_HOST="", SURICATA_SSH_USER="")
class RuleManagerApiTests(TestCase):
    def test_rule_create_and_list_work_with_local_only_sync(self):
        payload = {
            "id": "rule-1",
            "action": "alert",
            "proto": "tcp",
            "srcIp": "any",
            "srcPort": "any",
            "dir": "->",
            "dstIp": "$HOME_NET",
            "dstPort": "80",
            "msg": "HTTP probe",
            "sid": 1000501,
            "rev": 1,
            "enabled": True,
            "comment": "Local test rule",
        }

        response = self.client.post("/api/rules/", data=payload, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        response_payload = response.json()
        self.assertEqual(response_payload["status"], "ok")
        self.assertFalse(response_payload["sync"]["configured"])
        self.assertTrue(SuricataRule.objects.filter(rule_id="rule-1", sid=1000501).exists())

        list_response = self.client.get("/api/rules/")
        self.assertEqual(list_response.status_code, 200)
        rules = list_response.json()["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["msg"], "HTTP probe")
        self.assertEqual(rules[0]["syncStatus"], "local-only")

    def test_rule_create_route_rejects_missing_csrf_and_accepts_token(self):
        client = Client(enforce_csrf_checks=True)
        payload = {
            "id": "rule-csrf-check",
            "action": "alert",
            "proto": "tcp",
            "srcIp": "any",
            "srcPort": "any",
            "dir": "->",
            "dstIp": "$HOME_NET",
            "dstPort": "443",
            "msg": "HTTPS probe",
            "sid": 1000502,
            "rev": 1,
            "enabled": True,
        }

        response = client.post("/api/rules/", data=payload, content_type="application/json")
        self.assertEqual(response.status_code, 403)

        client.get(reverse("rule_manager"))
        csrf_token = client.cookies["csrftoken"].value
        response = client.post(
            "/api/rules/",
            data=payload,
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf_token,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(SuricataRule.objects.filter(rule_id="rule-csrf-check", sid=1000502).exists())

    def test_manual_block_api_returns_sync_status(self):
        response = self.client.post(
            "/api/block/",
            data='{"ip":"203.0.113.88","reason":"test block"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["sync"]["configured"])
        self.assertTrue(BlockedIP.objects.filter(ip="203.0.113.88", active=True).exists())

    @override_settings(DASHBOARD_REQUIRE_STAFF_FOR_MUTATIONS=True)
    def test_manual_block_requires_staff_when_enabled(self):
        response = self.client.post(
            "/api/block/",
            data='{"ip":"203.0.113.89","reason":"test block"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

        user = get_user_model().objects.create_user(
            username="mutator",
            password="pass",
            is_staff=True,
        )
        self.client.force_login(user)
        response = self.client.post(
            "/api/block/",
            data='{"ip":"203.0.113.89","reason":"test block"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(BlockedIP.objects.filter(ip="203.0.113.89", active=True).exists())

    @override_settings(DASHBOARD_REQUIRE_INGEST_TOKEN=True, IDS_INGEST_API_TOKEN="secret-token")
    def test_ingest_api_requires_configured_token(self):
        payload = '{"src_ip":"203.0.113.90","dest_ip":"192.168.1.90","attack_type":"scan","severity":"low"}'
        response = self.client.post("/api/ingest/", data=payload, content_type="application/json")
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/api/ingest/",
            data=payload,
            content_type="application/json",
            HTTP_X_IDS_TOKEN="secret-token",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Alert.objects.filter(src_ip="203.0.113.90").exists())

    def test_duplicate_sid_is_auto_reassigned_on_create(self):
        first_payload = {
            "id": "rule-first",
            "action": "alert",
            "proto": "tcp",
            "srcIp": "any",
            "srcPort": "any",
            "dir": "->",
            "dstIp": "$HOME_NET",
            "dstPort": "8080",
            "msg": "HTTP app probe",
            "sid": 1000600,
            "rev": 1,
            "enabled": True,
        }
        second_payload = {
            **first_payload,
            "id": "rule-second",
            "dstPort": "8443",
            "msg": "HTTPS app probe",
            "sid": 1000600,
        }

        self.client.post("/api/rules/", data=first_payload, content_type="application/json")
        response = self.client.post("/api/rules/", data=second_payload, content_type="application/json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["rule"]["sid"], 1000601)
        self.assertTrue(SuricataRule.objects.filter(rule_id="rule-second", sid=1000601).exists())

    def test_deleted_rule_sid_becomes_available_again(self):
        first_payload = {
            "id": "rule-reuse-first",
            "action": "alert",
            "proto": "tcp",
            "srcIp": "any",
            "srcPort": "any",
            "dir": "->",
            "dstIp": "$HOME_NET",
            "dstPort": "22",
            "msg": "SSH first",
            "sid": 1000001,
            "rev": 1,
            "enabled": True,
        }
        second_payload = {
            **first_payload,
            "id": "rule-reuse-second",
            "dstPort": "80",
            "msg": "HTTP second",
            "sid": 1000002,
        }

        self.client.post("/api/rules/", data=first_payload, content_type="application/json")
        self.client.post("/api/rules/", data=second_payload, content_type="application/json")
        response = self.client.delete("/api/rules/rule-reuse-first/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["next_sid"], 1000001)
        self.assertEqual(next_custom_sid(), 1000001)

    def test_custom_protocol_token_is_accepted(self):
        payload = {
            "id": "rule-custom-proto",
            "action": "alert",
            "proto": "modbus",
            "srcIp": "any",
            "srcPort": "any",
            "dir": "->",
            "dstIp": "$HOME_NET",
            "dstPort": "502",
            "msg": "Modbus probe",
            "sid": 1000700,
            "rev": 1,
            "enabled": True,
        }

        response = self.client.post("/api/rules/", data=payload, content_type="application/json")

        self.assertEqual(response.status_code, 200)
        rule = SuricataRule.objects.get(rule_id="rule-custom-proto")
        self.assertEqual(rule.proto, "modbus")
        self.assertIn("alert modbus", rule.raw_rule)
