# Automated Reconnaissance Tool

A comprehensive automated reconnaissance tool that combines multiple security scanning tools to perform thorough reconnaissance of targets.

## Features

- Multi-tool integration (Shodan, Nmap, DNSRecon, VirusTotal, Nuclei, Nikto, Wappalyzer, WHOIS, crt.sh, Subfinder, CloudEnum)
- Support for different target types (IP, domain, organization)
- Both passive and active scanning modes
- Structured JSON output with detailed findings
- Modular design for easy tool integration

## Installation

1. Clone the repository
2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Set up API keys in `.env` file:
```
SHODAN_API_KEY=your_shodan_key
VT_API_KEY=your_virustotal_key
INTELX_API_KEY=your_intelx_key
GOOGLE_API_KEY=your_google_key
GOOGLE_CX_ID=your_google_cx_id
WHOIS_API_KEY=your_whois_key
```

## Usage

```python
from automated_recon.main_no_mongo import AutomatedRecon

# Initialize scanner
recon = AutomatedRecon(
    target="example.com",
    target_type="domain",
    scan_type="passive",
    tools=['shodan', 'dnsrecon', 'wappalyzer']  # Optional: specify tools to use
)

# Run scan
results = recon.run_scan()
```

## Data Structure

The tool produces a structured JSON output with the following sections:

### Scan Information
```json
{
  "scan_info": {
    "target": "example.com",
    "target_type": "domain",
    "scan_type": "passive",
    "timestamp": "2024-04-30T13:45:00",
    "status": "completed",
    "tools_used": ["shodan", "dnsrecon", "wappalyzer"]
  }
}
```

### Assets
```json
{
  "assets": {
    "ips": [
      {
        "ip": "192.168.1.1",
        "domain": "example.com",
        "timestamp": "2024-04-30T13:45:00"
      }
    ],
    "domains": [
      {
        "domain": "example.com",
        "source": "wappalyzer",
        "technologies": [
          {
            "name": "Apache",
            "version": "2.4.41",
            "categories": ["Web Servers"]
          }
        ],
        "timestamp": "2024-04-30T13:45:00"
      }
    ],
    "cloud_assets": [],
    "web_apps": []
  }
}
```

### DNS Records
```json
{
  "dns_records": {
    "a_records": [],
    "cname_records": [],
    "mx_records": [],
    "ns_records": [],
    "txt_records": [],
    "zone_transfers": []
  }
}
```

### Findings
```json
{
  "findings": {
    "vulnerabilities": [],
    "misconfigurations": [],
    "exposed_data": []
  }
}
```

### Relationships
```json
{
  "relationships": []
}
```

### Raw Results
```json
{
  "raw_results": {
    "shodan": {},
    "dnsrecon": {},
    "wappalyzer": {}
  }
}
```

## Tool Integration

The tool integrates with the following security tools:

1. **Shodan**: Internet scanning and intelligence gathering
2. **Nmap**: Network scanning and service enumeration
3. **DNSRecon**: DNS enumeration and analysis
4. **VirusTotal**: Domain and IP reputation analysis
5. **Nuclei**: Vulnerability scanning
6. **Nikto**: Web server scanning
7. **Wappalyzer**: Web technology detection
8. **WHOIS**: Domain registration information
9. **crt.sh**: Certificate transparency logs
10. **Subfinder**: Subdomain enumeration
11. **CloudEnum**: Cloud asset discovery

### Current Status
- Basic scanning functionality working
- WHOIS integration pending API key
- Results properly structured in JSON format
- Technologies integrated into domain entries

### Next Steps
1. Implement remaining tool integrations
2. Add more sophisticated vulnerability detection
3. Improve error handling and logging
4. Add result visualization capabilities
5. Implement MongoDB integration 
