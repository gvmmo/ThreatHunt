# Architecture — ThreatHunt

## Overview

ThreatHunt is deployed on AWS using a multi-tier architecture with separated public and private subnets, high-availability database replication, and a Flask-based backend orchestrating all OSINT tool execution.

---

## Infrastructure diagram

```
                        ┌─────────────────────────────────────┐
                        │              Internet               │
                        └──────────────────┬──────────────────┘
                                           │
                        ┌──────────────────▼──────────────────┐
                        │     Application Load Balancer (ALB) │
                        │         HTTP / HTTPS traffic        │
                        └──────────┬───────────────┬──────────┘
                                   │               │
               ┌───────────────────▼──┐    ┌───────▼───────────────────┐
               │   EC2 WebInstance A  │    │   EC2 WebInstance B       │
               │   t4g.medium (ARM)   │    │   t4g.medium (ARM)        │
               │   Public subnet      │    │   Public subnet           │
               │   Flask + Frontend   │    │   Flask + Frontend        │
               └──────────┬───────────┘    └───────────┬───────────────┘
                          │                            │
               ┌──────────▼────────────────────────────▼──────────────┐
               │                 Private Subnets                      │
               │                                                      │
               │  ┌──────────────────┐    ┌───────────────────┐       │
               │  │  MongoDB Primary │◄──►│ MongoDB Secondary │       │
               │  │  EC2 t4g.medium  │    │  EC2 t4g.medium   │       │
               │  │  Replica Set     │    │  Replica Set      │       │
               │  └──────────────────┘    └───────────────────┘       │
               │                                                      │
               │  ┌──────────────────┐                                │
               │  │   S3 Bucket      │  AES-256 · versioning          │
               │  │   (backups)      │                                │
               │  └──────────────────┘                                │
               └──────────────────────────────────────────────────────┘
```

---

## Components

### Web tier (public subnets)

- Two EC2 `t4g.medium` instances (AWS Graviton2, ARM64) running Flask + frontend
- Auto Scaling configured: 1–2 instances based on CPU demand
- ALB distributes traffic across both instances
- CloudFormation used for initial infrastructure deployment

### Database tier (private subnets)

- Two EC2 `t4g.medium` instances running MongoDB in Replica Set mode (primary + secondary)
- No direct internet access — reachable only from web tier
- NAT Gateway used during setup for package installation; removed post-configuration
- Keyfile-based authentication between replica nodes
- Collections: `scans`, `assets`, `relationships`, `users`

### Storage

- S3 bucket for scan result backups and static data
- AES-256 server-side encryption enabled by default
- Object versioning enabled to prevent accidental data loss

### Monitoring

- AWS CloudWatch configured with alarms:
  - CPU > 80% for 5 minutes on web instances
  - ALB latency > 500ms
- Python `logging` module generates per-scan log files with timestamps
- Log files stored in `logs/` directory: `access.log`, `error.log`, per-scan execution logs

---

## Network architecture

| Subnet type | Contents | Internet access |
|-------------|----------|-----------------|
| Public | Web instances, ALB | Yes (via IGW) |
| Private | MongoDB nodes | No (isolated) |

Security groups per tier:
- **Web instances:** inbound HTTP (80), HTTPS (443), SSH from specific IPs
- **MongoDB instances:** inbound MongoDB port (27017) from web instances only

---

## Backend architecture

The core orchestration logic lives in `automated_recon/mainMongo.py`. The `AutomatedRecon` class coordinates the full scan lifecycle:

```
User request (POST /api/scan/start)
         │
         ▼
  AutomatedRecon.run()
         │
         ├── Validate target and scan type
         ├── Instantiate selected tool modules
         ├── Execute tools in sequence (OOP, one class per tool)
         ├── Parse and normalise results per asset
         ├── MongoDBHandler.store_results()
         └── Generate HTML report → store to disk
```

Each tool is implemented as an independent Python class following a common interface, making it straightforward to add new tools without modifying the orchestrator.

### MongoDB data model

```
scans           → scan metadata, status, timestamps, config
assets          → discovered assets per scan (subdomains, IPs, services)
relationships   → links between assets
users           → user accounts, hashed passwords, API keys per tool
```

---

## Scan status flow

```
PENDING → RUNNING → COMPLETED
                 └→ FAILED
```

Status is updated in MongoDB throughout execution. The frontend polls `/api/scan/{scan_id}` every 5 seconds to reflect current progress.

---

## Local development setup

For development and testing, MongoDB runs in a Docker container instead of the AWS replica set:

```bash
docker-compose up -d   # starts MongoDB locally
python run.py          # starts Flask at http://localhost:3000
```

The `.env` file controls which MongoDB URI is used, making the switch between local and production transparent to the application.
