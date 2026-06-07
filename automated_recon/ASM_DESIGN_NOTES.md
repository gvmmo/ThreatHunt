# ASM Tool Design Notes (2024-04-30)

## Key Design Decisions

### 1. Asset-Centric Data Structure
- Each discovered asset (domain, subdomain, IP) gets its own comprehensive OSINT data
- All findings are directly associated with their respective assets
- Clear relationship tracking between assets
- Timestamps for all discoveries and findings

### 2. Comprehensive Passive Scanning
- All OSINT tools run on each discovered asset
- Tools include:
  - DNS tools (DNSRecon)
  - Certificate transparency (crt.sh)
  - Web technology detection (Wappalyzer)
  - Internet scanning (Shodan)
  - Reputation services (VirusTotal)
  - WHOIS information

### 3. Recursive Discovery Process
- Start with initial target
- Run all applicable OSINT tools
- Extract new assets from results
- Process each new asset with all tools
- Continue until no new assets discovered

## Data Structure Example

```json
{
  "assets": {
    "_id": ObjectId("..."),
    "identifier": "sub1.example.com",
    "type": "domain",
    "discovery_context": {
      "source": "dnsrecon",
      "parent_asset": "example.com",
      "discovery_timestamp": ISODate("2024-04-30T13:45:00Z")
    },
    "osint_data": {
      "dns": {
        "a_records": ["192.168.1.1"],
        "cname_records": [],
        "mx_records": ["mail.sub1.example.com"],
        "ns_records": ["ns1.example.com"],
        "txt_records": ["v=spf1 include:_spf.example.com ~all"],
        "zone_transfer": "",
        "source": "dnsrecon",
        "timestamp": ISODate("2024-04-30T13:45:00Z")
      },
      "certificates": {
        "issuer": "Let's Encrypt",
        "valid_from": ISODate("2024-01-01T00:00:00Z"),
        "valid_to": ISODate("2024-04-01T00:00:00Z"),
        "source": "crt.sh",
        "timestamp": ISODate("2024-04-30T13:45:00Z")
      },
      "web_technologies": {
        "techname": "techversion",
        "timestamp": ISODate("2024-04-30T13:45:00Z")
      },
      "shodan": {
        "services": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "module": "https",
                    "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
                    "timestamp": "2024-01-14T22:15:31.432Z",
                    "product": "nginx",
                    "version": "1.18.0",
                    "cpe": [
                        "cpe:/a:nginx:nginx:1.18.0"
                    ],
                    "vulns": {
                        "CVE-2021-23017": {
                            "summary": "Descripción detallada de la vulnerabilidad...",
                            "cvss_v3": 7.5
                        }
                    },
                }
        ],
        "banners": ["Apache/2.4.41"],
        "timestamp": ISODate("2024-04-30T13:45:00Z")
      },
      "virustotal": {
        "reputation": 95,
        "categories": ["business", "web"],
        "relationships": [
          "referrer_files": [],
          "communicating_files": [],
          "urls": [],
          "resolutions": []
        ],
        "last_analysis": ISODate("2024-04-30T13:45:00Z")
      },
      "whois": {
        "registrar": "Example Registrar",
        "creation_date": ISODate("2020-01-01T00:00:00Z"),
        "expiration_date": ISODate("2025-01-01T00:00:00Z"),
        "nameservers": ["ns1.example.com", "ns2.example.com"]
      }
    },
    "relationships": [
      {
        "type": "subdomain_of",
        "target": "example.com",
        "evidence": "DNS hierarchy"
      },
    ],
    "metadata": {
      "last_scan": ISODate("2024-04-30T13:45:00Z"),
    }
  }
}
```

## Scanning Logic Overview

```python
class AutomatedRecon:
    def __init__(self, target, target_type, scan_type="passive"):
        self.target = target
        self.target_type = target_type
        self.scan_type = scan_type
        self.discovered_assets = set()  # Track all discovered assets
        
    def run_scan(self):
        # Start with initial target
        self._process_asset(self.target)
        
        # Continue until no new assets are discovered
        while True:
            new_assets = self._get_new_assets()
            if not new_assets:
                break
                
            for asset in new_assets:
                self._process_asset(asset)
```

## Next Steps

1. Implement the new asset-centric data structure
2. Modify the scanning logic to process all discovered assets
3. Update the MongoDB schema to support the new structure
4. Add relationship tracking between assets
5. Implement comprehensive OSINT data collection for each asset
6. Add proper timestamp tracking for all findings
7. Create indexes for efficient querying:
   ```javascript
   db.assets.createIndex({ "identifier": 1, "type": 1 })
   db.assets.createIndex({ "osint_data.dns.a_records": 1 })
   db.assets.createIndex({ "relationships.target": 1 })
   db.assets.createIndex({ "osint_data.web_technologies.cms": 1 })
   ```

## Benefits of New Design

1. **Comprehensive Asset Coverage**
   - Every discovered asset gets full OSINT treatment
   - Maximum information gathering
   - Complete relationship mapping

2. **Efficient Data Organization**
   - All findings directly associated with assets
   - Clear source attribution
   - Easy to track changes over time

3. **Improved Querying**
   - Single query to get all information about an asset
   - Easy to find related assets
   - Efficient for dashboard views

4. **Better ASM Capabilities**
   - Complete attack surface mapping
   - Clear asset relationships
   - Comprehensive technology stack analysis 

## Tool Output Structures

### WHOIS
```json
{
  "registrar": "Example Registrar",
  "creation_date": "2020-01-01T00:00:00Z",
  "expiration_date": "2025-01-01T00:00:00Z",
  "nameservers": ["ns1.example.com", "ns2.example.com"]
}
```

### DNSRecon
```json
{
  "a_records": ["192.168.1.1"],
  "cname_records": [],
  "mx_records": ["mail.sub1.example.com"],
  "ns_records": ["ns1.example.com"],
  "txt_records": ["v=spf1 include:_spf.example.com ~all"],
  "zone_transfer": ""
}
```

### Subfinder
```json
[
  "sub1.example.com",
  "sub2.example.com"
]
```

### Wappalyzer
```json
{
  "techname": "techversion"
}
```

### CRT.sh
```json
{
  "issuer": "Let's Encrypt",
  "valid_from": "2024-01-01T00:00:00Z",
  "valid_to": "2024-04-01T00:00:00Z"
}
```

### Shodan
```json
{
  "services": [
    {
      "port": 443,
      "transport": "tcp",
      "module": "https",
      "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
      "timestamp": "2024-01-14T22:15:31.432Z",
      "product": "nginx",
      "version": "1.18.0",
      "cpe": ["cpe:/a:nginx:nginx:1.18.0"],
      "vulns": {
        "CVE-2021-23017": {
          "summary": "Descripción detallada de la vulnerabilidad...",
          "cvss_v3": 7.5
        }
      }
    }
  ],
  "banners": ["Apache/2.4.41"]
}
```

### Nikto
```json
{
  "issues": [
    {
      "id": "CVE-2021-1234",
      "description": "Vulnerability description",
      "severity": "high"
    }
  ]
}
```

### CloudEnum
```json
{
  "s3_buckets": ["bucket1", "bucket2"],
  "cloudfront": ["cf1", "cf2"],
  "ec2_instances": ["i-1234567890abcdef0"]
}
```
