"""Policy Engine ORM models"""
import enum
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from app.database import Base


class PolicyAction(str, enum.Enum):
    ALLOW = "allow"
    FLAG = "flag"           # alert but pass through
    QUARANTINE = "quarantine"
    BLOCK = "block"         # hard reject (verdict overridden)


class Policy(Base):
    __tablename__ = "policies"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(120), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    conditions  = Column(JSON, nullable=False)   # ConditionSchema serialised
    action      = Column(String(20), nullable=False)  # PolicyAction value
    priority    = Column(Integer, nullable=False, default=100, index=True)
    enabled     = Column(Boolean, nullable=False, default=True, index=True)
    simulate    = Column(Boolean, nullable=False, default=False)
    created_by  = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())


class PolicyDecisionLog(Base):
    __tablename__ = "policy_decisions"

    id                 = Column(Integer, primary_key=True, index=True)
    scan_id            = Column(Integer, ForeignKey("dlp_scans.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id            = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    policy_id          = Column(Integer, ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    policy_name        = Column(String(120), nullable=True)   # snapshot at eval time
    decision           = Column(String(20), nullable=False)
    matched_conditions = Column(JSON, nullable=True)
    context_snapshot   = Column(JSON, nullable=True)
    simulated          = Column(Boolean, default=False)
    would_have_action  = Column(String(20), nullable=True)
    evaluation_trace   = Column(JSON, nullable=True)          # ordered list of {policy, matched}
    created_at         = Column(DateTime(timezone=True), server_default=func.now(), index=True)
