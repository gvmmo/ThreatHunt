# Architecture — ThreatHunt

## Overview

ThreatHunt is deployed on AWS using a multi-tier architecture with separated public and private subnets, high-availability database replication, and a Flask-based backend orchestrating all OSINT tool execution.

---

## Infrastructure diagram

```mermaid
graph TD
    Internet([Internet]) --> ALB

    subgraph AWS [" "]
        direction TB

        ALB["Application Load Balancer
        HTTP / HTTPS"]

        subgraph Public ["Public Subnets"]
            direction LR
            WebA["EC2 WebInstance A
            t4g.medium · Graviton2
            Flask + Frontend"]
            WebB["EC2 WebInstance B
            t4g.medium · Graviton2
            Flask + Frontend"]
        end

        subgraph Private ["Private Subnets"]
            direction LR
            MongoPrimary["MongoDB Primary
            EC2 t4g.medium
            Replica Set"]
            MongoSecondary["MongoDB Secondary
            EC2 t4g.medium
            Replica Set"]
            S3["S3 Bucket
            AES-256 · Versioning
            Backups"]
        end

        subgraph Monitoring ["Monitoring"]
            CloudWatch["CloudWatch
            CPU · Latency alarms"]
        end
    end

    ALB --> WebA
    ALB --> WebB
    WebA <--> MongoPrimary
    WebB <--> MongoPrimary
    MongoPrimary <--> MongoSecondary
    WebA --> S3
    WebB --> S3
    WebA -.-> CloudWatch
    WebB -.-> CloudWatch
    MongoPrimary -.-> CloudWatch

    style AWS fill:#1a1a2e,stroke:#4a9eff,stroke-width:2px,color:#fff
    style Public fill:#16213e,stroke:#4a9eff,stroke-width:1px,color:#4a9eff
    style Private fill:#0f3460,stroke:#4a9eff,stroke-width:1px,color:#4a9eff
    style Monitoring fill:#2d1b69,stroke:#9b72cf,stroke-width:1px,color:#9b72cf
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
- No direct internet access — reachable only from web tier via port 27017
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
- **Web instances:** inbound HTTP (80), HTTPS (443), SSH from specific IPs only
- **MongoDB instances:** inbound port 27017 from web instances only

---

## Backend orchestration flow

```mermaid
flowchart TD
    Request["POST /api/scan/start"] --> Validate["Validate
    target & config"]
    Validate --> AutoRecon["AutomatedRecon
    orchestrator"]

    AutoRecon --> T1["Crt.sh"]
    AutoRecon --> T2["DNSRecon"]
    AutoRecon --> T3["Shodan"]
    AutoRecon --> T4["VirusTotal"]
    AutoRecon --> T5["Wappalyzer"]
    AutoRecon --> T6["WHOIS"]
    AutoRecon --> T7["Hunter.how"]

    T1 & T2 & T3 & T4 & T5 & T6 & T7 --> Normalise["Normalise
    results per asset"]
    Normalise --> MongoDB["MongoDBHandler
    store results"]
    MongoDB --> Report["Generate
    HTML report"]
    Report --> Done["COMPLETED"]

    style Request fill:#0f3460,stroke:#4a9eff,color:#fff
    style Done fill:#1a5c38,stroke:#4a9eff,color:#fff
    style AutoRecon fill:#16213e,stroke:#4a9eff,color:#fff
    style MongoDB fill:#16213e,stroke:#4a9eff,color:#fff
```

---

## Scan status flow

```mermaid
flowchart TD
    Start(( )) --> PENDING

    PENDING["PENDING
    scan created"] --> RUNNING

    RUNNING["RUNNING
    orchestrator executing"] --> COMPLETED
    RUNNING --> FAILED

    COMPLETED["COMPLETED
    all tools finished"] --> End1(( ))
    FAILED["FAILED
    tool error / timeout"] --> End2(( ))

    style Start fill:#4a9eff,stroke:#4a9eff
    style End1 fill:#4a9eff,stroke:#4a9eff
    style End2 fill:#4a9eff,stroke:#4a9eff
    style PENDING fill:#16213e,stroke:#4a9eff,color:#fff
    style RUNNING fill:#0f3460,stroke:#4a9eff,color:#fff
    style COMPLETED fill:#1a5c38,stroke:#2ecc71,color:#fff
    style FAILED fill:#5c1a1a,stroke:#e74c3c,color:#fff
```

---

## MongoDB data model

```
scans        → scan metadata, status, timestamps, config
assets       → discovered assets per scan (subdomains, IPs, services)
relationships → links between assets
users        → user accounts, hashed passwords, API keys per tool
```

---

## Local development setup

For development and testing, MongoDB runs in a Docker container instead of the AWS replica set:

```bash
docker-compose up -d   # starts MongoDB locally
python run.py          # starts Flask at http://localhost:3000
```

The `.env` file controls which MongoDB URI is used, making the switch between local and production transparent to the application.
