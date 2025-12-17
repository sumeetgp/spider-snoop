"""DLP Scan Pydantic schemas"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.models.scan import ScanStatus, RiskLevel

class ScanCreate(BaseModel):
    content: str = Field(..., min_length=1, description="Text content to scan for sensitive data")
    source: str = Field("API", description="Source of the scan (e.g., API, Manual, App)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "content": "Subject: Project X key\nMy AWS key is AKIA1234567890ABCDEF and secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "source": "Manual Test"
            }
        }
    }

class ScanResponse(BaseModel):
    id: int
    source: str
    status: ScanStatus
    risk_level: Optional[RiskLevel]
    verdict: Optional[str]
    ai_analysis: Optional[Any] = None
    findings: Optional[List[Dict[str, Any]]]
    scan_duration_ms: Optional[int]
    created_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

    @staticmethod
    def _parse_json(v):
        import json
        if isinstance(v, str):
            try:
                return json.loads(v)
            except:
                return v
        return v

    from pydantic import field_validator
    @field_validator('ai_analysis')
    @classmethod
    def parse_ai_analysis(cls, v):
        return cls._parse_json(v)

class ScanStats(BaseModel):
    total_scans: int
    scans_by_risk: Dict[str, int]
    scans_by_status: Dict[str, int]
    avg_scan_duration_ms: float
    recent_scans: List[ScanResponse]
