import os
from datetime import datetime
from typing import Dict, List, Any
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv

class MongoDBHandler:
    def __init__(self):
        """Initialize MongoDB connection and collections."""
        # Load environment variables
        load_dotenv()
        
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
    
    def store_scan_results(self, results: Dict[str, Any]) -> str:
        """
        Store all scan results in MongoDB.
        
        Args:
            results (Dict[str, Any]): The complete scan results
            
        Returns:
            str: The scan ID
        """
        try:
            # Store scan metadata
            scan_info = results['scan_info']
            scan_info['_id'] = ObjectId()
            scan_id = self.scans.insert_one(scan_info).inserted_id
            
            # Store assets
            for asset_id, asset_data in results['assets'].items():
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
            for relationship in results['relationships']:
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
            return str(scan_id)
            
        except Exception as e:
            print(f"Error storing results in MongoDB: {str(e)}")
            raise
    
    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        """Get scan information by ID."""
        return self.scans.find_one({'_id': ObjectId(scan_id)})
    
    def get_scan_assets(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all assets for a specific scan."""
        return list(self.assets.find({'scan_id': scan_id}))
    
    def get_scan_relationships(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all relationships for a specific scan."""
        return list(self.relationships.find({'scan_id': scan_id}))
    
    def get_asset(self, identifier: str) -> Dict[str, Any]:
        """Get asset information by identifier."""
        return self.assets.find_one({'identifier': identifier})
    
    def get_asset_relationships(self, identifier: str) -> List[Dict[str, Any]]:
        """Get all relationships for a specific asset."""
        return list(self.relationships.find({
            '$or': [
                {'source': identifier},
                {'target': identifier}
            ]
        }))
    
    def get_user_scans(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans for a user."""
        return list(self.scans.find(
            {'user_id': user_id},
            sort=[('started_at', -1)],
            limit=limit
        ))
    
    def update_scan_status(self, scan_id: str, status: str, error: str = None) -> None:
        """Update scan status and optional error message."""
        update_data = {
            'status': status,
            'completed_at': datetime.now().isoformat() if status in ['completed', 'failed'] else None
        }
        if error:
            update_data['error'] = error
            
        self.scans.update_one(
            {'_id': ObjectId(scan_id)},
            {'$set': update_data}
        )
    
    def update_scan_progress(self, scan_id: str, current_tool: str, completed_tools: List[str], percentage: int) -> None:
        """Update scan progress information."""
        self.scans.update_one(
            {'_id': ObjectId(scan_id)},
            {'$set': {
                'progress': {
                    'current_tool': current_tool,
                    'completed_tools': completed_tools,
                    'percentage': percentage
                }
            }}
        ) 