# OSINT Tools — ThreatHunt

## Overview

ThreatHunt integrates a suite of OSINT tools executed autonomously by the backend orchestrator. Tools are grouped into passive (no direct interaction with the target) and active (direct interaction, may generate alerts on the target side).

Each tool is implemented as an independent Python class. Results are normalised into a common asset-centric structure before being stored in MongoDB.

---

## Passive tools (implemented)

### Crt.sh
Queries the certificate transparency log to discover subdomains and associated SSL certificates issued for the target domain.

- **API key required:** No
- **Output:** Subdomain list, certificate issuer, validity dates

### DNSRecon
Performs DNS enumeration including record types (A, MX, NS, TXT, SOA) and zone transfer attempts.

- **API key required:** No
- **Output:** DNS records, potential misconfigurations, zone transfer results

### Shodan
Passive lookup of indexed data for the target. Reveals open ports, running services, software versions and geolocation — without sending a single packet to the target.

- **API key required:** Yes
- **Output:** Open ports, service banners, CVEs associated with detected versions
- **Get API key:** [account.shodan.io/register](https://account.shodan.io/register)

### VirusTotal
Queries VirusTotal's passive DNS and subdomain dataset to discover related subdomains and assess domain reputation.

- **API key required:** Yes
- **Output:** Subdomain list, reputation score, detection flags
- **Get API key:** [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)

### Wappalyzer
Fingerprints the technologies running on the target web application: CMS, frameworks, CDN, analytics, server software.

- **API key required:** No
- **Output:** Technology stack breakdown with version information where available

### WHOIS (apilayer)
Retrieves domain registration data including registrar, creation/expiry dates, nameservers and registrant information.

- **API key required:** Yes
- **Output:** Full WHOIS record
- **Get API key:** [apilayer.com/marketplace/whois-api](https://apilayer.com/marketplace/whois-api)

### Hunter.how
Complementary device and service discovery, similar to Shodan. Useful for cross-referencing exposed services.

- **API key required:** Yes
- **Output:** Exposed services, IP ranges
- **Get API key:** [hunter.how/profile](https://hunter.how/profile)

---

## Planned tools

These tools are implemented in the codebase but not yet connected to the scan pipeline.

| Tool | Type | Description |
|------|------|-------------|
| Subfinder | Passive | High-speed subdomain enumeration using multiple passive sources |
| Gobuster | Active | Directory and file brute-forcing on web servers |
| Nikto | Active | Web server vulnerability scanner — detects misconfigurations and known CVEs |
| Google Dorks | Passive | Advanced Google queries to surface sensitive indexed data |
| Intelligence X | Passive | Search across dark web, data leaks and historical records |
| Nuclei | Active | Template-based vulnerability scanner with a large community ruleset |
| CloudEnum | Passive | Enumerates public cloud resources (S3 buckets, Azure blobs, GCP) for a target org |

---

## Adding a new tool

Each tool follows the same interface pattern:

```python
class NewTool:
    def __init__(self, target: str, api_key: str = None):
        self.target = target
        self.api_key = api_key

    def run(self) -> dict:
        # Execute tool logic
        # Return normalised results
        return {
            "tool": "new_tool",
            "target": self.target,
            "results": [...]
        }
```

1. Create the class in `automated_recon/tools/new_tool.py`
2. Register it in the tool selection logic in `mainMongo.py`
3. Add it to the frontend tool list in the scan wizard

---

## API key configuration

API keys are configured per user from the **Profile → API Keys** section of the dashboard. Keys are stored encrypted in MongoDB and injected at scan runtime — they are never logged or exposed in reports.

Tools that do not require an API key (Crt.sh, DNSRecon, Wappalyzer) work out of the box with no configuration.

Tools with a free tier that still delivers useful results: Shodan, VirusTotal. Upgrading to a paid tier significantly increases rate limits and data depth.
