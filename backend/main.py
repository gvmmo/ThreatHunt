from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import os
from dotenv import load_dotenv
import json
from automated_recon.mainMongo import AutomatedRecon
from automated_recon.mongodb_handler import MongoDBHandler

# Initialize FastAPI app
app = FastAPI(title="Automated Reconnaissance API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize MongoDB handler
mongo = MongoDBHandler()

# Pydantic models for request/response
class APIKeys(BaseModel):
    shodan_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None
    intelx_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    google_cx_id: Optional[str] = None
    whois_api_key: Optional[str] = None

class ScanConfig(BaseModel):
    target: str
    target_type: str = Field(..., description="Type of target ('ip' or 'domain')")
    scan_type: str = Field(..., description="Type of scan ('passive' or 'active')")
    tools: List[str] = Field(..., description="List of tools to use")
    active_targets: Optional[List[str]] = Field(None, description="Additional targets for active scanning")
    user_id: str = Field(..., description="User ID for tracking scans")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    results: Optional[Dict[str, Any]] = None

# Store active scans
active_scans: Dict[str, Any] = {}

def run_scan_task(scan_id: str, config: ScanConfig, api_keys: APIKeys):
    """Background task to run the scan"""
    try:
        # Update scan status to running
        mongo.update_scan_status(scan_id, "running")
        
        # Initialize scanner with configuration
        recon = AutomatedRecon(
            target=config.target,
            target_type=config.target_type,
            scan_type=config.scan_type,
            tools=config.tools
        )
        
        # Run the scan
        results = recon.run_scan()
        
        # Store results
        mongo.store_scan_results(results)
        
        # Update scan status to completed
        mongo.update_scan_status(scan_id, "completed")
        
    except Exception as e:
        # Update scan status to failed
        mongo.update_scan_status(scan_id, "failed", str(e))
        raise

@app.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    """Start a new scan"""
    try:
        # Create scan record
        scan_info = {
            "target": config.target,
            "target_type": config.target_type,
            "scan_type": config.scan_type,
            "tools": config.tools,
            "user_id": config.user_id,
            "status": "queued",
            "started_at": datetime.now().isoformat()
        }
        
        # Store scan info and get scan ID
        scan_id = str(mongo.scans.insert_one(scan_info).inserted_id)
        
        # Start scan in background
        background_tasks.add_task(run_scan_task, scan_id, config, APIKeys())
        
        return ScanResponse(
            scan_id=scan_id,
            status="queued",
            message="Scan started successfully"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get status of a scan"""
    try:
        # Get scan info
        scan = mongo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan results if completed
        results = None
        if scan["status"] == "completed":
            assets = mongo.get_scan_assets(scan_id)
            relationships = mongo.get_scan_relationships(scan_id)
            results = {
                "assets": assets,
                "relationships": relationships
            }
        
        return ScanStatus(
            scan_id=scan_id,
            status=scan["status"],
            progress=scan.get("progress"),
            error=scan.get("error"),
            results=results
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans/user/{user_id}")
async def get_user_scans(user_id: str, limit: int = 10):
    """Get recent scans for a user"""
    try:
        scans = mongo.get_user_scans(user_id, limit)
        return scans
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tools")
async def get_available_tools():
    """Get list of available tools"""
    return {
        "passive": [
            "shodan",
            "virustotal",
            "wappalyzer",
            "whois",
            "crt_sh",
            "dnsrecon",
            "subfinder",
            "cloudenum",
            "google_dorks",
            "intelx"
        ],
        "active": [
            "nmap",
            "nikto",
            "nuclei",
            "gobuster"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 