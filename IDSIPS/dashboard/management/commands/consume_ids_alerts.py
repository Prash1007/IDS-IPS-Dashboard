import json
from django.conf import settings
from django.core.management.base import BaseCommand
from confluent_kafka import Consumer
from dashboard.services import ingest_alert

class Command(BaseCommand):
    help = "Consume IDS alerts from Kafka, filter noisy ones, and save genuine ones to DB"

    def handle(self, *args, **kwargs):
        consumer_config = {
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": settings.KAFKA_CONSUMER_GROUP,
            "auto.offset.reset": settings.KAFKA_AUTO_OFFSET_RESET,
            "enable.auto.commit": settings.KAFKA_ENABLE_AUTO_COMMIT,
        }
        
        if getattr(settings, 'KAFKA_SECURITY_PROTOCOL', None):
            consumer_config["security.protocol"] = settings.KAFKA_SECURITY_PROTOCOL
        if getattr(settings, 'KAFKA_SASL_MECHANISM', None):
            consumer_config["sasl.mechanism"] = settings.KAFKA_SASL_MECHANISM
        if getattr(settings, 'KAFKA_SASL_USERNAME', None):
            consumer_config["sasl.username"] = settings.KAFKA_SASL_USERNAME
        if getattr(settings, 'KAFKA_SASL_PASSWORD', None):
            consumer_config["sasl.password"] = settings.KAFKA_SASL_PASSWORD

        consumer = Consumer(consumer_config)
        consumer.subscribe([settings.KAFKA_ALERT_TOPIC])
        
        self.stdout.write(self.style.SUCCESS(f"Kafka consumer started for topic {settings.KAFKA_ALERT_TOPIC}"))

        try:
            while True:
                msg = consumer.poll(1.0)

                if msg is None:
                    continue

                if msg.error():
                    self.stderr.write(str(msg.error()))
                    continue

                try:
                    alert = json.loads(msg.value().decode("utf-8"))
                    
                    # --- FILTERING LOGIC  ---
                    protocol = alert.get('protocol', '').lower()
                    attack_type = alert.get('attack_type', '')
                    src_ip = alert.get('src_ip', '') or ''
                    dest_ip = alert.get('dest_ip', '') or ''

                    # Drop IPv6, Test ICMP Pings, and Localhost (127.x.x.x) traffic
                    if (
                        'ipv6' in protocol or 
                        attack_type == 'TEST ICMP Ping Detected' or 
                        src_ip.startswith('127.') or 
                        dest_ip.startswith('127.')
                    ):
                        continue

                    # This section is used for genuine alerts based on my rules
                    saved_alert = ingest_alert(alert, source="kafka")
                    
                    if saved_alert is not None:
                        self.stdout.write(self.style.SUCCESS(f"Alert saved: {attack_type} from {src_ip}"))

                except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                    self.stderr.write(f"Skipped invalid alert message: {exc}")
                    continue

        finally:
            consumer.close()
            self.stdout.write(self.style.WARNING("Kafka consumer closed."))