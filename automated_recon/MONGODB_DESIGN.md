# MongoDB Database Design for Web Interface

## Overview
The database is organized around the concept of scans, where each scan contains multiple assets, and each asset runs the user-selected tools. The structure follows this hierarchy:

1. User starts a scan (creates a scan document)
2. Scan discovers assets (creates asset documents)
3. Each asset runs selected tools (stores tool results in asset document)
4. Relationships between assets are tracked (creates relationship documents)

## Collections Structure

### 1. Scans Collection
```json
{
    "_id": ObjectId("..."),  // Unique scan ID (e.g., scan_1, scan_2)
    "user_id": "user123",    // Reference to user who started the scan
    "target": "example.com",
    "target_type": "domain",
    "scan_type": "passive",
    "status": "running",     // running, completed, failed
    "started_at": ISODate("2024-04-30T13:45:00Z"),
    "completed_at": ISODate("2024-04-30T13:50:00Z"),
    "selected_tools": ["shodan", "virustotal", "dnsrecon"],  // Tools user selected for this scan
    "error": null,           // Error message if scan failed
    "progress": {
        "current_tool": "shodan",
        "completed_tools": ["dnsrecon"],
        "total_tools": 3,
        "percentage": 33
    }
}
```

### 2. Assets Collection
Each scan can discover multiple assets (domains, subdomains, IPs). Each asset runs the tools selected for the scan:

```json
{
    "_id": ObjectId("..."),
    "scan_id": ObjectId("..."),  // Reference to parent scan
    "identifier": "sub1.example.com",
    "type": "domain",
    "discovery_context": {
        "source": "dnsrecon",
        "parent_asset": "example.com",
        "discovery_timestamp": ISODate("2024-04-30T13:45:00Z")
    },
    "osint_data": {
        // Each tool selected in the scan will have its own section
        "shodan": {
            "last_scan": ISODate("2024-04-30T13:45:00Z"),
            "data": {
                "ports": [80, 443],
                "hostnames": ["sub1.example.com"],
                "vulns": ["CVE-2021-1234"],
                "banner": "Apache/2.4.41"
            }
        },
        "virustotal": {
            "last_scan": ISODate("2024-04-30T13:45:00Z"),
            "data": {
                "reputation": 95,
                "categories": ["business", "web"],
                "last_analysis_stats": {
                    "harmless": 50,
                    "malicious": 0
                }
            }
        }
        // Other tools selected for the scan will appear here
    },
    "metadata": {
        "created_at": ISODate("2024-04-30T13:45:00Z"),
        "updated_at": ISODate("2024-04-30T13:45:00Z")
    }
}
```

### 3. Relationships Collection
Tracks relationships between assets discovered during the scan:

```json
{
    "_id": ObjectId("..."),
    "scan_id": ObjectId("..."),  // Reference to parent scan
    "source": "example.com",
    "target": "sub1.example.com",
    "type": "has_subdomain",
    "evidence": "DNS discovery",
    "discovered_by": "dnsrecon",
    "metadata": {
        "created_at": ISODate("2024-04-30T13:45:00Z")
    }
}
```

### 4. Users Collection
Stores user information and their scan history:

```json
{
    "_id": ObjectId("..."),
    "username": "user123",
    "email": "user@example.com",
    "api_keys": {
        "shodan": "shodan_api_key_here",
        "virustotal": "vt_api_key_here"
    },
    "scan_history": [
        {
            "scan_id": ObjectId("..."),
            "target": "example.com",
            "started_at": ISODate("2024-04-30T13:45:00Z")
        }
    ],
    "settings": {
        "default_tools": ["shodan", "virustotal"],
        "scan_type": "passive"
    }
}
```

## Indexes

```javascript
// Scans Collection
db.scans.createIndex({ "user_id": 1, "started_at": -1 })
db.scans.createIndex({ "status": 1 })
db.scans.createIndex({ "target": 1, "target_type": 1 })

// Assets Collection
db.assets.createIndex({ "scan_id": 1 })
db.assets.createIndex({ "identifier": 1, "type": 1 })
db.assets.createIndex({ "osint_data.shodan.last_scan": 1 })
db.assets.createIndex({ "osint_data.virustotal.last_scan": 1 })

// Relationships Collection
db.relationships.createIndex({ "scan_id": 1 })
db.relationships.createIndex({ "source": 1, "target": 1 })
db.relationships.createIndex({ "type": 1 })

// Users Collection
db.users.createIndex({ "username": 1 }, { unique: true })
db.users.createIndex({ "email": 1 }, { unique: true })
```

## Common Queries

### 1. Get All Assets and Their Tool Results for a Scan
```javascript
db.assets.find(
    { "scan_id": ObjectId("scan_id_here") }
)
```

### 2. Get All Assets with Specific Tool Results
```javascript
db.assets.find(
    {
        "scan_id": ObjectId("scan_id_here"),
        "osint_data.shodan": { "$exists": true }
    }
)
```

### 3. Get Scan History for a User
```javascript
db.scans.find(
    { "user_id": "user123" },
    { "sort": { "started_at": -1 } }
)
```

## Web Interface Integration

### 1. Starting a New Scan
```python
def start_scan(user_id: str, target: str, tools: List[str]) -> str:
    # Create new scan document
    scan_id = db.scans.insert_one({
        "user_id": user_id,
        "target": target,
        "status": "running",
        "started_at": datetime.now(),
        "selected_tools": tools,
        "progress": {
            "current_tool": None,
            "completed_tools": [],
            "total_tools": len(tools),
            "percentage": 0
        }
    }).inserted_id
    
    # Start scan in background
    start_background_scan(scan_id, target, tools)
    
    return str(scan_id)
```

### 2. Updating Scan Progress
```python
def update_scan_progress(scan_id: str, tool: str, progress: int):
    db.scans.update_one(
        { "_id": ObjectId(scan_id) },
        {
            "$set": {
                "progress.current_tool": tool,
                "progress.percentage": progress
            },
            "$push": { "progress.completed_tools": tool }
        }
    )
```

### 3. Storing Tool Results
```python
def store_tool_results(scan_id: str, asset_id: str, tool: str, results: dict):
    db.assets.update_one(
        {
            "scan_id": ObjectId(scan_id),
            "identifier": asset_id
        },
        {
            "$set": {
                f"osint_data.{tool}": {
                    "last_scan": datetime.now(),
                    "data": results
                }
            }
        }
    )
```

## Next Steps

1. **Implementation**
   - Create scan initialization function
   - Implement asset discovery and processing
   - Add tool execution and result storage
   - Set up relationship tracking

2. **Web Interface**
   - Create scan configuration page
   - Show real-time scan progress
   - Display asset results by tool
   - Visualize asset relationships

3. **Data Management**
   - Implement scan cleanup
   - Add data export features
   - Create backup procedures

4. **Performance**
   - Optimize tool execution
   - Implement result caching
   - Add pagination for large result sets 