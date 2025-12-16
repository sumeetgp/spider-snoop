"""DLP Scan Pydantic schemas"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.models.scan import ScanStatus, RiskLevel

class ScanCreate(BaseModel):
    content: str = Field(..., min_length=1)
    source: str = "API"

class ScanResponse(BaseModel):
    id: int
    source: str
    status: ScanStatus
    risk_level: Optional[RiskLevel]
    verdict: Optional[str]
    ai_analysis: Optional[str] = None
    findings: Optional[List[Dict[str, Any]]]
    scan_duration_ms: Optional[int]
    created_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class ScanStats(BaseModel):
    total_scans: int
    scans_by_risk: Dict[str, int]
    scans_by_status: Dict[str, int]
    avg_scan_duration_ms: float
    recent_scans: List[ScanResponse]
