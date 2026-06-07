# MongoDB Implementation Guide

## Overview
This document explains the changes needed to implement MongoDB storage in the Automated Reconnaissance tool, replacing the current JSON file storage system.

## Required Changes

### 1. Dependencies
Add the following to your `requirements.txt`:
```
pymongo>=4.0.0
```

### 2. Environment Variables
Add MongoDB connection string to your `.env` file:
```
MONGODB_URI=mongodb://localhost:27017
```

### 3. Code Changes

#### A. Imports
Add these imports at the top of the file:
```python
from pymongo import MongoClient
from bson import ObjectId
```

#### B. MongoDB Connection Setup
In the `__init__` method, add:
```python
# Initialize MongoDB connection
mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017')
self.mongo_client = MongoClient(mongo_uri)
self.db = self.mongo_client['asm_database']

# Define collections
self.scans = self.db['scans']
self.assets = self.db['assets']
self.relationships = self.db['relationships']

# Create indexes
self._create_indexes()
```

#### C. Index Creation Method
Add this new method to create indexes for efficient querying:
```python
def _create_indexes(self) -> None:
    """Create indexes for efficient querying."""
    # Assets collection indexes
    self.assets.create_index([("identifier", 1), ("type", 1)])
    self.assets.create_index([("scan_id", 1)])
    self.assets.create_index([("osint_data.dns.a_records", 1)])
    self.assets.create_index([("osint_data.web_technologies", 1)])
    self.assets.create_index([("last_updated", 1)])
    
    # Relationships collection indexes
    self.relationships.create_index([("source", 1), ("target", 1), ("type", 1)])
    self.relationships.create_index([("scan_id", 1)])
    self.relationships.create_index([("last_updated", 1)])
    
    # Scans collection indexes
    self.scans.create_index([("target", 1), ("target_type", 1)])
    self.scans.create_index([("timestamp", 1)])
    self.scans.create_index([("status", 1)])
```

#### D. Replace _store_results Method
Replace the existing JSON file storage with MongoDB storage:
```python
def _store_results(self) -> None:
    """Store all scan results in MongoDB."""
    try:
        # Store scan metadata
        scan_info = self.results['scan_info']
        scan_info['_id'] = ObjectId()
        scan_id = self.scans.insert_one(scan_info).inserted_id
        
        # Store assets
        for asset_id, asset_data in self.results['assets'].items():
            # Add scan reference and timestamps
            asset_data['scan_id'] = str(scan_id)
            asset_data['last_updated'] = datetime.now().isoformat()
            
            # Update or insert asset
            self.assets.update_one(
                {'identifier': asset_id},
                {'$set': asset_data},
                upsert=True
            )
        
        # Store relationships
        for relationship in self.results['relationships']:
            # Add scan reference and timestamps
            relationship['scan_id'] = str(scan_id)
            relationship['last_updated'] = datetime.now().isoformat()
            
            # Update or insert relationship
            self.relationships.update_one(
                {
                    'source': relationship['source'],
                    'target': relationship['target'],
                    'type': relationship['type']
                },
                {'$set': relationship},
                upsert=True
            )
        
        print(f"Results stored in MongoDB with scan ID: {scan_id}")
        
    except Exception as e:
        print(f"Error storing results in MongoDB: {str(e)}")
        raise
```

## Data Structure

### 1. Scans Collection
```json
{
    "_id": ObjectId("..."),
    "target": "example.com",
    "target_type": "domain",
    "scan_type": "passive",
    "timestamp": "2024-04-30T13:45:00Z",
    "status": "completed",
    "tools_used": ["shodan", "dnsrecon", "wappalyzer"]
}
```

### 2. Assets Collection
```json
{
    "identifier": "sub1.example.com",
    "type": "domain",
    "scan_id": "scan_id_here",
    "last_updated": "2024-04-30T13:45:00Z",
    "discovery_context": {
        "source": "dnsrecon",
        "parent_asset": "example.com",
        "discovery_timestamp": "2024-04-30T13:45:00Z"
    },
    "osint_data": {
        "dns": {},
        "certificates": {},
        "web_technologies": {},
        "shodan": {},
        "virustotal": {},
        "whois": {}
    }
}
```

### 3. Relationships Collection
```json
{
    "source": "example.com",
    "target": "sub1.example.com",
    "type": "has_subdomain",
    "evidence": "DNS discovery",
    "scan_id": "scan_id_here",
    "last_updated": "2024-04-30T13:45:00Z"
}
```

## Querying Examples

### 1. Get All Assets from a Scan
```python
db.assets.find({'scan_id': 'scan_id_here'})
```

### 2. Get All Relationships for an Asset
```python
db.relationships.find({'source': 'asset_identifier'})
```

### 3. Get Scan History for a Target
```python
db.scans.find({'target': 'target_here'})
```

### 4. Get Assets by Type
```python
db.assets.find({'type': 'domain'})
```

### 5. Get Recent Scans
```python
db.scans.find({'timestamp': {'$gte': '2024-04-01T00:00:00Z'}})
```

## Next Steps

1. **Data Migration**
   - Create a script to migrate existing JSON results to MongoDB
   - Validate data integrity after migration

2. **Query Optimization**
   - Monitor query performance
   - Add additional indexes if needed
   - Implement query caching for frequently accessed data

3. **Data Retention**
   - Implement data retention policies
   - Create cleanup scripts for old scans
   - Archive important historical data

4. **API Development**
   - Create REST API endpoints for data access
   - Implement authentication and authorization
   - Add rate limiting and usage tracking

5. **Monitoring and Maintenance**
   - Set up MongoDB monitoring
   - Implement backup procedures
   - Create maintenance scripts

6. **Documentation**
   - Document all MongoDB queries
   - Create usage examples
   - Add troubleshooting guide

7. **Testing**
   - Create unit tests for MongoDB operations
   - Implement integration tests
   - Test performance under load

## Benefits of MongoDB Implementation

1. **Scalability**
   - Better handling of large datasets
   - Efficient querying of complex relationships
   - Support for future growth

2. **Performance**
   - Faster data retrieval
   - Efficient indexing
   - Better memory management

3. **Flexibility**
   - Schema-less design
   - Easy to modify data structure
   - Support for complex queries

4. **Maintainability**
   - Centralized data storage
   - Better data organization
   - Easier backup and restore

5. **Integration**
   - Better support for web applications
   - Easier integration with other tools
   - Support for real-time updates 