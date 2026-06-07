# VirusTotal Intelligence Gathering Tool

A Python script for gathering focused intelligence about domains using the VirusTotal API. This tool provides detailed information about domain reputation, subdomains, and various relationships.

## Features

- Domain malicious status analysis
- Subdomain discovery with malicious status
- Relationship analysis (communicating files, referrer files, subdomains, etc.)
- Cleaned and focused results showing only malicious/suspicious detections
- JSON output for easy integration with other tools

## Prerequisites

- Python 3.x
- VirusTotal API key
- Required Python packages:
  - requests
  - python-dotenv

## Usage

The script can be used in two ways:

### 1. Direct Execution

Run the script directly to analyze a specific domain:

```bash
python virustotal.py
```

By default, it will analyze "example.com" and save the results to a JSON file.

### 2. Import as a Module

Import the `Virustotal` class in your Python code:

```python
from virustotal import Virustotal

# Initialize the client
vt = Virustotal()

# Get domain intelligence
intel = vt.get_domain_intel(
    domain="example.com",
    relationship_types=["subdomains", "communicating_files", "referrer_files"]
)


# Save results to JSON
vt.save_to_json(intel, "output.json")
```

## Available Relationship Types

The script supports various relationship types for analysis. By default, it uses the following free-tier accessible relationships:

Full list of relationships available: https://docs.virustotal.com/reference/domains-object#relationships

## Output Format

The script generates a JSON file with the following structure:

```json
{
    "timestamp": "2024-03-21T12:00:00",
    "domain": "example.com",
    "malicious_status": {
        "stats": {
            "malicious": 0,
            "suspicious": 0,
            "engines_flagged": 0
        },
        "flagging_engines": {
            // Only includes engines that flagged as malicious/suspicious
        }
    },
    "subdomains": [
        {
            "domain": "sub.example.com",
            "stats": {
                // Analysis statistics
            }
        }
    ],
    "relationships": {
        // Requested relationship data
    },
    "query_parameters": {
        "requested_relationships": ["communicating_files", "referrer_files"],
        "actual_relationships": ["communicating_files", "referrer_files"]
    }
}
```

## Rate Limiting

The script implements a 15-second delay between API requests to comply with VirusTotal's rate limits.

## Error Handling

The script includes error handling for:
- Missing API key
- Invalid API responses
- Network issues
- Invalid relationship types
- Enterprise-only relationship types

