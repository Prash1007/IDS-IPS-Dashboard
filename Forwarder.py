"""

Suricata  Kafka Alert Producer 

----------------------------------

Reads Suricata eve.json in real-time

Sends ONLY alerts that involve our Protected Target IPs

"""



import json

import time

from confluent_kafka import Producer



# ==============================

# CONFIGURATION

# ==============================



EVE_FILE = "/var/log/suricata/eve.json"

KAFKA_BROKER = "10.114.98.28:9092"  # Update as needed

KAFKA_TOPIC = "ids-alerts"



#Setting the target Server IP that is needed to be monitored.

TARGET_IPS = [

    "IP_ADDRESS_Of_Protected_Device",#Kindly give IP where your kafka and suricata is running and also you can add multiple IPs here if you want to monitor more than one device.

]



producer = Producer({

    "bootstrap.servers": KAFKA_BROKER

})



# ==============================

# DELIVERY CALLBACK

# ==============================



def delivery_report(err, msg):

    if err is not None:

        print("[ERROR] Delivery failed:", err)

    else:

        print(f"Delivered to {msg.topic()} [{msg.partition()}] @ {msg.offset()}")



# ==============================

# FILE FOLLOW FUNCTION

# ==============================



def follow(file):

    file.seek(0, 2)  # Go to the end of the file

    while True:

        line = file.readline()

        if not line:

            time.sleep(0.5)

            continue

        yield line



# ==============================

# MAIN LOG PROCESSOR

# ==============================



def process_alerts():

    print("Starting Suricata Forwarder (Production Mode)...")

    print("Watching:", EVE_FILE)

    print(f"Protected Target IPs: {TARGET_IPS}")



    with open(EVE_FILE, "r") as f:

        loglines = follow(f)



        for line in loglines:

            try:

                data = json.loads(line)



                if data.get("event_type") == "alert":

                    

                    # 1. Map Severity

                    sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}

                    severity_number = data.get("alert", {}).get("severity")

                    severity = sev_map.get(severity_number, "medium")



                    # 2. Extract Data

                    src_ip = str(data.get("src_ip", ""))

                    dest_ip = str(data.get("dest_ip", ""))

                    protocol = data.get("proto", "UNKNOWN").lower()

                    attack_type = data.get("alert", {}).get("signature", "Unknown")

                    src_port = data.get("src_port", 0)

                    dest_port = data.get("dest_port", 0)



                    

                    # Drop useless protocols and normal Ping Checks

                    if "ipv6" in protocol or attack_type == "TEST ICMP Ping Detected":

                        continue

                        

                    # Drop Localhost and Kafka loopback noise (Port 9092)

                    if src_ip.startswith("127.") or dest_ip.startswith("127.") or src_port == 9092 or dest_port == 9092:

                        continue



                    if src_ip not in TARGET_IPS and dest_ip not in TARGET_IPS:

                        continue



                    print(f"\nALERT DETECTED: {attack_type} | {src_ip} -> {dest_ip}")



                    # 4. Build Optimized Payload

                    alert_payload = {

                        "timestamp": data.get("timestamp"),

                        "src_ip": src_ip,

                        "dest_ip": dest_ip,

                        "src_port": src_port,

                        "dest_port": dest_port,

                        "protocol": protocol,

                        "attack_type": attack_type,

                        "severity": severity,

                        "description": data.get("alert", {}).get("category", ""),

                        "action": data.get("alert", {}).get("action", "allowed")

                    }



                    print("Sending to Kafka...")

                    producer.produce(

                        topic=KAFKA_TOPIC,

                        key=src_ip,

                        value=json.dumps(alert_payload),

                        callback=delivery_report

                    )

                    producer.poll(0)



            except json.JSONDecodeError:

                continue

            except Exception as e:

                print(f"[ERROR] Processing line: {e}")



# ==============================

# ENTRY POINT

# ==============================



if __name__ == "__main__":

    try:

        process_alerts()

    except KeyboardInterrupt:

        print("\nStopping Forwarder...")

    finally:

        producer.flush(5)