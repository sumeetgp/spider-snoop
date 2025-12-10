"""DLP Scan database model"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Enum, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from app.database import Base

class ScanStatus(str, enum.Enum):
    """Scan status"""
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

class RiskLevel(str, enum.Enum):
    """Risk level classification"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DLPScan(Base):
    """DLP Scan result model"""
    __tablename__ = "dlp_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    source = Column(String, nullable=False)  # ICAP, API, Manual
    content = Column(Text, nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    risk_level = Column(Enum(RiskLevel), nullable=True)
    findings = Column(JSON, nullable=True)  # Detailed findings
    verdict = Column(String, nullable=True)
    scan_duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationship
    # user = relationship("User", back_populates="scans")
