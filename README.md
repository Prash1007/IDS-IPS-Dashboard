# IDSIPS — Intrusion Detection & Prevention System Dashboard

A real-time network security dashboard built with Django that integrates with **Suricata IDS/IPS** and **Apache Kafka** to monitor, alert, and block malicious network traffic. Supports three operational modes: IDS (alert-only), IPS (auto-block), and HYBRID.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Project](#running-the-project)
- [Management Commands](#management-commands)
- [Rule Manager](#rule-manager)
- [API Endpoints](#api-endpoints)
- [Lab Testing Setup](#lab-testing-setup)
- [Security Notes](#security-notes)

---

## Features

- **Real-time Alert Dashboard** — live feed of network intrusion alerts polled from Kafka
- **Three Detection Modes**
  - `IDS` — detect and alert only, no automatic blocking
  - `IPS` — automatically block medium+ severity and aggressive attack sources
  - `HYBRID` — watch medium alerts, auto-block on repeat or high severity
- **IP Blocking / Unblocking** — manual and automatic, tracked in `BlockedIP` table
- **Rule Manager** — CRUD interface for Suricata rules stored in Django DB and synced over SSH
- **Remote Suricata Sync** — push custom rule files and block rules to Suricata machine via SSH
- **Alert Archiving** — move old alerts to `OldAlertLog` with batch tracking
- **Security Action Log** — full audit trail of every BLOCK, UNBLOCK, MODE_CHANGE event
- **Security Headers Middleware** — CSP, Permissions-Policy, COOP headers auto-applied
- **Kafka Consumer Pipeline** — filters noisy/IPv6/localhost alerts before persistence

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Attack Traffic                      │
│          (Kali Linux / Termux on same network)          │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────┐
              │  Suricata IDS    │  ← rules synced via SSH
              │  (network tap)   │
              │  (On ubuntu)     │              
              └────────┬─────────┘
                       │ eve.json alerts
                       ▼
              ┌──────────────────┐
              │  Apache Kafka    │
              │  (ids-alerts)    │
              │  (topic)         │
              │  (On ubuntu)     │
              └────────┬─────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │    Django Dashboard (IDSIPS) │
        │  ┌────────────────────────┐  │
        │  │  consume_ids_alerts    │  │  ← management command
        │  │  (Kafka consumer)      │  │
        │  └──────────┬─────────────┘  │
        │             │                │
        │  ┌──────────▼─────────────┐  │
        │  │  services.ingest_alert │  │  ← filtering + auto-block logic
        │  └──────────┬─────────────┘  │
        │             │                │
        │  ┌──────────▼─────────────┐  │
        │  │  SQLite / PostgreSQL   │  │
        │  │  Alert, BlockedIP,     │  │
        │  │  SuricataRule, etc.    │  │
        │  └────────────────────────┘  │
        │                              │
        │  REST API (/api/*)           │
        │  Web Dashboard (/)           │
        └──────────────────────────────┘
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Web Framework | Django 6.0+ |
| Alert Pipeline | Apache Kafka + confluent-kafka |
| IDS/IPS Engine | Suricata |
| Remote Sync | Paramiko (SSH) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| API | Django REST Framework |
| Frontend | Vanilla JS, Chart.js, CSS |
| Security | Custom middleware, python-decouple |

---

## Project Structure

```
MajorProject/
├── IDSIPS/                          # Django project root
│   ├── dashboard/                   # Main app
│   │   ├── management/
│   │   │   └── commands/
│   │   │       ├── archive_old_alerts.py
│   │   │       ├── bootstrap_suricata_remote.py
│   │   │       ├── clear_dashboard_rules.py
│   │   │       ├── configure_suricata_sync.py
│   │   │       ├── consume_ids_alerts.py
│   │   │       └── sync_suricata_remote.py
│   │   ├── migrations/              # DB schema migrations
│   │   │   ├── 0001_initial.py
│   │   │   ├── 0002_alert_mode_...py
│   │   │   ├── 0003_suricatarule.py
│   │   │   └── 0004_oldalertlog_...py
│   │   ├── static/dashboard/        # Frontend decoratives
│   │   │   ├── base.css 
│   │   │   ├── index.css 
│   │   │   └── alerts.css 
│   │   │   └── alerts.css
│   │   │   └── alerts.js
│   │   │   └── base.css
│   │   │   └── base.js
│   │   │   └── index.css
│   │   │   └── index.js
│   │   │   └── main.js
│   │   │   └── network_traffic.css
│   │   │   └── network_traffic.js
│   │   │   └── reports.css
│   │   │   └── reports.js
│   │   │   └── rule_manager.css
│   │   │   └── rule_manager.js
│   │   │   └── style.css
│   │   │   └── threat_map.css
│   │   │   └── threat_map.js
│   │   ├── static/templates/dashboard/        # Frontend Structure
│   │   │   └──alerts.html
│   │   │   └──base.html
│   │   │   └──index.html
│   │   │   └──network_traffic.html
│   │   │   └──reports.html
│   │   │   └──rule_manager.html
│   │   │   └──threat_map.html
│   │   ├── admin.py                 # Django admin config
│   │   ├── apps.py
│   │   ├── middleware.py            # Security headers
│   │   ├── models.py                # Alert, BlockedIP, SuricataRule, etc.
│   │   ├── services.py              # Business logic (ingest, block, archive)
│   │   ├── views.py                 # API + page views
│   │   └── urls.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── .env.example                     # ← copy to .env and fill values
├── .gitignore
├── requirements.txt
└── README.md
└── Suricata_SETUP
└── Shifting network new kafka setup
```
└── Forwarder.py #Make sure yoy add this in your ubuntu machine where you set up your kafka and suricata server
---

## Prerequisites

Make sure the following are installed on your system:

- **Python 3.11+**
- **pip**
- **Apache Kafka** (with Zookeeper or KRaft) — for alert ingestion
- **Suricata** — on the monitored network machine
- **PostgreSQL** (optional, SQLite works for dev)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Prash1007/IDS-IPS-Dashboard
cd IDS-IPS-Dashboard

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment template and fill in your values
cp .env.example .env
nano .env

# 5. Apply database migrations
cd IDSIPS
python manage.py migrate

# 6. Create Django superuser (for /admin panel)
python manage.py createsuperuser

# 7. Collect static files
python manage.py collectstatic --noinput
```

---

## Configuration

All configuration is done via the `.env` file. Key settings:

### Django

```env
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost,10.114.98.28
```

### Kafka

```env
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_CONSUMER_GROUP=idsips-dashboard
KAFKA_ALERT_TOPIC=ids-alerts
KAFKA_AUTO_OFFSET_RESET=latest
KAFKA_ENABLE_AUTO_COMMIT=True
```

### Suricata SSH Sync

```env
SURICATA_SSH_HOST=192.168.1.50
SURICATA_SSH_PORT=22
SURICATA_SSH_KEY_PATH=/home/kali/.ssh/suricata_key
SURICATA_REMOTE_RULES_DIR=/etc/suricata/rules
SURICATA_REMOTE_CUSTOM_RULES_FILE=dashboard_custom.rules
SURICATA_REMOTE_BLOCK_RULES_FILE=dashboard_blocks.rules
SURICATA_REMOTE_RELOAD_COMMAND=sudo systemctl reload suricata
SURICATA_HOME_NET=[10.0.0.0/8,192.168.0.0/16]
```

---

## Running the Project

### Development Server

```bash
cd IDSIPS
python manage.py runserver 0.0.0.0:8000
```

### Start Kafka Alert Consumer (separate terminal)

```bash
cd IDSIPS
python manage.py consume_ids_alerts
```

The consumer listens to the Kafka topic and automatically ingests, filters, and saves alerts to the database. It also triggers auto-blocking logic based on the current mode (IDS/IPS/HYBRID).

---

## Management Commands

| Command | Description |
|---------|-------------|
| `python manage.py consume_ids_alerts` | Start Kafka consumer — main alert ingestion loop |
| `python manage.py configure_suricata_sync --host <IP> --user <user>` | Write SSH sync config for Suricata remote |
| `python manage.py bootstrap_suricata_remote` | First-time bootstrap of Suricata rule files and YAML includes via SSH |
| `python manage.py sync_suricata_remote` | Push current rules and block list to remote Suricata |
| `python manage.py archive_old_alerts` | Archive alerts older than 30 days to `OldAlertLog` |
| `python manage.py archive_old_alerts --all` | Archive ALL current alerts |
| `python manage.py clear_dashboard_rules` | Backup and delete all rules from the DB |
| `python manage.py clear_dashboard_rules --sync` | Clear rules and also push empty rule file to Suricata |

---

## Rule Manager

The Rule Manager stores Suricata rules in Django's database (`SuricataRule` model) and syncs them to the remote Suricata machine over SSH.

### SuricataRule Fields

| Field | Description | Example |
|-------|-------------|---------|
| `sid` | Unique Suricata rule ID (auto from 1000001+) | `1000001` |
| `msg` | Human-readable alert name | `ET SCAN Nmap SYN Stealth Scan` |
| `action` | Rule action | `alert` / `drop` / `reject` |
| `proto` | Protocol | `tcp` / `udp` / `icmp` / `http` |
| `raw_rule` | Full Suricata rule text | *(see below)* |
| `enabled` | Whether rule is active | `True` |
| `sync_status` | Sync state | `pending` / `synced` / `failed` |

### Suricata Rule Syntax

```
action proto src_ip src_port -> dest_ip dest_port (msg:"TEXT"; options; sid:N; rev:1;)
```

**Example rules for common attacks:**

```
# Nmap SYN Scan
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Nmap SYN Scan"; flags:S,12; threshold:type threshold, track by_src, count 20, seconds 3; classtype:attempted-recon; sid:1000001; rev:1;)

# SSH Brute Force
alert tcp any any -> $HOME_NET 22 (msg:"ET BRUTE SSH Brute Force"; flow:to_server,established; content:"SSH"; depth:3; threshold:type threshold, track by_src, count 8, seconds 30; classtype:attempted-admin; sid:1000007; rev:1;)

# SQL Injection UNION SELECT
alert tcp any any -> $HOME_NET 4444 (msg:"ET WEB SQLi UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; http.uri; classtype:web-application-attack; sid:1000012; rev:1;)
```

### Adding Rules via Django Admin

1. Go to `http://localhost:8000/admin/dashboard/suricatarule/add/`
2. Fill in `sid`, `msg`, `action`, `proto`, `raw_rule`
3. Set `enabled = True`, `sync_status = pending`
4. Run `python manage.py sync_suricata_remote` to push to Suricata

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts/` | List alerts (filterable, paginated) |
| GET | `/api/stats/` | Dashboard KPIs and chart data |
| GET | `/api/live-feed/` | Recent alerts for live feed widget |
| GET | `/api/blocked-ips/` | List blocked IPs |
| POST | `/api/block/` | Block an IP manually |
| POST | `/api/unblock/` | Unblock an IP |
| POST | `/api/mode/` | Switch IDS/IPS/HYBRID mode |
| GET | `/api/actions/` | Security action audit log |

---

## Lab Testing Setup

This project was tested against a local vulnerable Django web application on the same hotspot network.

### Network Layout

```
Phone (Termux attacker)  ─┐
                           ├──► 10.114.98.28:4444  (Vulnerable web app)
Kali Linux (attacker)    ─┘         │
                                    │
                              Suricata (monitoring)
                                    │
                              Kafka → IDSIPS Dashboard
```

### Sample Attack Commands per Rule Category

**Nmap Scans (SID 1000001–1000006)**
```bash
sudo nmap -sS 10.114.98.28 -p 1-1000          # SYN stealth scan
sudo nmap -sN 10.114.98.28                    # NULL scan
sudo nmap -sX 10.114.98.28                    # XMAS scan
sudo nmap -sF 10.114.98.28                    # FIN scan
nmap -T5 --open 10.114.98.28 -p-              # Port sweep
```

**SSH Brute Force (SID 1000007–1000009)**
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 10.114.98.28 ssh -t 4 -V
```

**SQL Injection (SID 1000012–1000014)**
```bash
sqlmap -u "http://10.114.98.28:4444/search/?q=1" --dbs --batch
curl "http://10.114.98.28:4444/login/?id=1'+UNION+SELECT+1,2,3--"
```

**DoS / Flood (SID 1000023–1000026)**
```bash
sudo hping3 -S --flood -p 4444 10.114.98.28   # SYN flood
sudo hping3 --icmp --flood 10.114.98.28       # ICMP flood
ab -n 5000 -c 100 http://10.114.98.28:4444/   # HTTP flood
```

**From Termux (Android):**
```bash
pkg install nmap hydra python apache2-utils
nmap -sV 10.114.98.28 -p 4444,22,23
hydra -l admin -P ~/wordlist.txt 10.114.98.28 -s 4444 http-post-form "/login/:username=^USER^&password=^PASS^:F=Invalid"
```

---
## Security Notes

- Never commit `.env`, SSH keys, or `suricata_remote.local.json` to Git
- Change `SECRET_KEY` before any deployment
- Set `DEBUG=False` in production and configure `ALLOWED_HOSTS` strictly
- Use PostgreSQL instead of SQLite for production deployments
- The Django admin (`/admin/`) should be protected with a strong password
- Suricata SSH key should have minimal permissions (rule file write + reload only)
- This project is intended for educational and lab environments — not for production network deployment without additional hardening

---

## License

This project is submitted as a Major Academic Project. All rights reserved by the Prashant Mall.
