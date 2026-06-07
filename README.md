# ThreatHunt — OSINT Automated Security Platform

<div align="center">

![ThreatHunt Logo](assets/logo.png)

![Status](https://img.shields.io/badge/status-in%20development-yellow?style=flat-square)
![Python](https://img.shields.io/badge/backend-Python%20%2F%20Flask-blue?style=flat-square)
![Platform](https://img.shields.io/badge/infrastructure-AWS-orange?style=flat-square)
![Database](https://img.shields.io/badge/database-MongoDB-green?style=flat-square)

</div>

**ThreatHunt** is an OSINT-focused cybersecurity web platform designed for automated open-source intelligence gathering and analysis. Users can configure passive and active scans against domains, IP addresses or organizations, selecting from a suite of integrated tools — and receive structured, downloadable HTML reports with all findings.

---

## Demo

> 📹 Full platform walkthrough — registration → scan configuration → tool execution → report download.

[![ThreatHunt Demo](https://img.youtube.com/vi/VIDEO_ID/maxresdefault.jpg)](https://www.youtube.com/watch?v=VIDEO_ID)

> ⚠️ *Replace `VIDEO_ID` with the actual YouTube video ID before publishing.*

---

## How it works

1. Register at [threathunt.solutions](https://threathunt.solutions) and create your account.
2. Log in and access the dashboard.
3. Click **New Scan**, enter a target domain and select the scan type (passive or active).
4. Choose the tools you want to run and configure your API keys if needed.
5. The platform executes all selected tools autonomously, organising results by asset.
6. Download the full HTML report from **My Scans**.

---

## Architecture overview

- **Infrastructure:** AWS-based deployment using EC2 instances (t4g.medium, Graviton), VPC with public/private subnets, and an Application Load Balancer (ALB) with Auto Scaling (1–2 instances on demand).
- **Backend:** Python + Flask orchestrator (`main.py`) running OSINT tools in sequence, storing structured results in MongoDB. Each scan creates entries for assets, findings and relationships.
- **Frontend:** Web dashboard built with a 3-step scan wizard (target → tool selection → review & launch), real-time scan status updates every 5 seconds, and report export.
- **Database:** MongoDB Replica Set (primary + secondary nodes) deployed in private subnets for high availability. Collections: `scans`, `assets`, `relationships`, `users`.
- **Security:** AWS WAF with Anonymous IP list, Core rule set, Known bad inputs and Amazon IP reputation list. Authentication system with per-user profile and API key management. S3 bucket with AES-256 encryption and versioning for backups.
- **Monitoring:** AWS CloudWatch with CPU and latency alarms, access and error logging per scan execution via Python's logging module.

---

## Integrated tools

| Tool | Type | Description |
|------|------|-------------|
| Crt.sh | Passive | Certificate transparency log search |
| DNSRecon | Passive | DNS enumeration and zone transfer analysis |
| Shodan | Passive | Internet-connected device and service discovery |
| VirusTotal | Passive | Subdomain discovery and reputation analysis |
| Wappalyzer | Passive | Web technology fingerprinting |
| WHOIS (apilayer) | Passive | Domain registration information |
| Hunter.how | Passive | Complementary device and service data |
| Subfinder | Planned | Subdomain enumeration |
| Gobuster | Planned | Directory and file enumeration |
| Nikto | Planned | Web server vulnerability scanning |
| Google Dorks | Planned | Advanced indexed data discovery |
| Intelligence X | Planned | Dark web and historical data search |
| Nuclei | Planned | Template-based vulnerability detection |
| CloudEnum | Planned | Cloud infrastructure enumeration |

---

## Key features

- **Passive & active scans:** Passive mode collects information without interacting with the target. Active mode (in development) enables deeper auditing and exploitation validation.
- **Per-user scan history:** Every scan is persisted in MongoDB, accessible and deletable from the user dashboard.
- **HTML reports:** Results are exported as downloadable HTML files with an integrated search bar to filter by IP, domain or other attributes.
- **API key management:** Users configure their own API keys per tool from their profile, maximising scan quality without sharing credentials.
- **Asset-centric data model:** Scans are structured around discovered assets — subdomains, IPs, services — each with its own findings from every selected tool.

---

## Tech stack

| Layer | Technologies |
|-------|-------------|
| Backend | Python, Flask, OOP tool modules |
| Frontend | HTML/CSS/JS, 3-step scan wizard |
| Database | MongoDB Replica Set (HA), S3 (backups) |
| Infrastructure | AWS EC2, VPC, ALB, Auto Scaling, CloudFormation |
| Security | AWS WAF, CloudWatch, CloudTrail |
| OSINT toolkit | Crt.sh, DNSRecon, Shodan, VirusTotal, Wappalyzer, WHOIS, Hunter.how |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/gvmmo/threathunt.git
cd threathunt

# Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start MongoDB with Docker
docker-compose up -d

# Configure environment variables
cp .env.example .env
# Edit .env with your MongoDB URI and API keys

# Install system tools
sudo apt-get install -y gobuster subfinder nuclei nikto dnsrecon
# Or use the provided installer:
python install.py

# Run the application
python run.py
# App runs at http://localhost:3000
```

---

## Team

| Name | Role |
|------|------|
| Ayman Dghoughi Nouri | AWS infrastructure · VPC & networking · MongoDB HA · WAF · S3 · Security |
| Ian Díaz | Backend development · OSINT tool integration · MongoDB setup |
| Amritpal Singh | Frontend development · UI/UX · Authentication system |

---

## docs/

| File | Description |
|------|-------------|
| [architecture.md](docs/architecture.md) | AWS infrastructure and system design |
| [tools.md](docs/tools.md) | OSINT tools reference and API key setup |
| [security.md](docs/security.md) | WAF rules, authentication and security measures |
