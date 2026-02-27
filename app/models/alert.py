"""Alert Configuration and History models"""
import enum
from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class AlertTrigger(str, enum.Enum):
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INCIDENT = "INCIDENT"   # score >= incident threshold
    BLOCK = "BLOCK"          # score >= block threshold


class AlertChannel(str, enum.Enum):
    WEBHOOK = "webhook"
    EMAIL = "email"


class AlertStatus(str, enum.Enum):
    SENT = "sent"
    FAILED = "failed"


class AlertConfig(Base):
    """User-level alert destination configuration."""
    __tablename__ = "alert_configs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(120), nullable=False, default="Default Alert")
    enabled = Column(Boolean, default=True, nullable=False)

    # Trigger level — alert fires when scan risk_level >= this level
    trigger_on = Column(SAEnum(AlertTrigger), default=AlertTrigger.CRITICAL, nullable=False)

    # Destinations (at least one must be set)
    webhook_url = Column(String(512), nullable=True)
    email = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="alert_configs")
    history = relationship("AlertHistory", back_populates="config", cascade="all, delete-orphan")


class AlertHistory(Base):
    """Log of every alert attempt."""
    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    config_id = Column(Integer, ForeignKey("alert_configs.id", ondelete="CASCADE"), nullable=True)
    scan_id = Column(Integer, ForeignKey("dlp_scans.id", ondelete="SET NULL"), nullable=True, index=True)

    channel = Column(SAEnum(AlertChannel), nullable=False)
    status = Column(SAEnum(AlertStatus), nullable=False)
    response_code = Column(Integer, nullable=True)   # HTTP status for webhooks
    error_message = Column(Text, nullable=True)
    fired_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    config = relationship("AlertConfig", back_populates="history")
