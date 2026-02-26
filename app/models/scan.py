"""DLP Scan database model"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Enum, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class ScanStatus(str, enum.Enum):
    """Scan status"""
    PENDING = "PENDING"
    UPLOADED = "UPLOADED"
    MALWARE_SCANNING = "MALWARE_SCANNING"
    EXTRACTING = "EXTRACTING"
    CONTENT_SCANNING = "CONTENT_SCANNING"
    AI_ANALYSIS = "AI_ANALYSIS"
    POLICY_EVAL = "POLICY_EVAL"
    SCANNING = "SCANNING"  # Legacy synchronous status
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class RiskLevel(str, enum.Enum):
    """Risk level classification"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DLPScan(Base):
    """DLP Scan result model"""
    __tablename__ = "dlp_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    source = Column(String, nullable=False)  # ICAP, API, Manual
    content = Column(Text, nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    risk_level = Column(Enum(RiskLevel), nullable=True, index=True)
    findings = Column(JSON, nullable=True)  # Detailed findings
    verdict = Column(String, nullable=True)
    ai_analysis = Column(Text, nullable=True)
    threat_score = Column(Integer, default=0)
    scan_duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    @property
    def scan_type(self) -> str:
        if self.source and (self.source.startswith("VIDEO:") or self.source.startswith("OMNISENSE:") or self.source.startswith("ECHOVISION:")):
            return "ECHOVISION"
        if self.source and (self.source.startswith("CODE_SECURITY:") or self.source.startswith("SUPPLY_CHAIN:")):
            return "CODE_SECURITY"
        if self.content and self.content.startswith("[SENTINEL SCAN]"):
            return "MALWARE"
        return "DLP"
    
    # Relationship
    user = relationship("User", back_populates="scans")
