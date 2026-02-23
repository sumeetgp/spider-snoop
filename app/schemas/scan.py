"""DLP Scan Pydantic schemas"""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.models.scan import ScanStatus, RiskLevel

class UserBasicInfo(BaseModel):
    id: int
    username: str
    email: str
    
    class Config:
        from_attributes = True

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
    scan_type: str = "DLP"
    ai_analysis: Optional[Any] = None
    cdr_info: Optional[Dict[str, Any]] = None # Derived from ai_analysis usually, but useful to expose
    threat_score: int = 0
    summary: Optional[str] = "Analysis Complete"
    credits_remaining: int = 50
    findings: Optional[List[Dict[str, Any]]]
    scan_duration_ms: Optional[int]
    created_at: datetime
    completed_at: Optional[datetime]
    user: Optional[UserBasicInfo] = None
    
    @property
    def scan_id(self) -> str:
        return f"cob-uuid-{self.id}"

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

    score: int = 0
    duration: int = 0
    aiInsight: Optional[str] = None
    compliance_alerts: List[str] = []

    @model_validator(mode='after')
    def populate_frontend_fields(self):
        # Map internal fields to Frontend expectations
        self.score = self.threat_score
        self.duration = self.scan_duration_ms or 0
        
        # Populate aiInsight and compliance_alerts from ai_analysis
        if self.ai_analysis:
             try:
                 analysis = self.ai_analysis
                 if isinstance(analysis, str):
                     import json
                     analysis = json.loads(analysis)
                 if isinstance(analysis, dict):
                     self.aiInsight = analysis.get('reason')
                     self.compliance_alerts = analysis.get('compliance_alerts', [])
                     # Also try to refresh score if logic differs
                     # if 'score' in analysis: self.score = analysis['score']
             except:
                 pass
                 
        # Populate cdr_info (Existing logic)
        if not self.cdr_info and self.ai_analysis:
             try:
                 analysis = self.ai_analysis
                 if isinstance(analysis, str):
                     import json
                     analysis = json.loads(analysis)
                 
                 if isinstance(analysis, dict) and 'cdr' in analysis:
                     self.cdr_info = analysis['cdr']
             except:
                 pass
                 
        return self

class ScanStats(BaseModel):
    total_scans: int
    scans_by_risk: Dict[str, int]
    scans_by_status: Dict[str, int]
    avg_scan_duration_ms: float
    recent_scans: List[ScanResponse]
