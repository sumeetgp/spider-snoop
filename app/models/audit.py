from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Text, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.database import Base

class ProxyAction(str, enum.Enum):
    ALLOWED = "ALLOWED"
    BLOCKED_OPA = "BLOCKED_OPA"
    BLOCKED_DLP = "BLOCKED_DLP"
    REDACTED = "REDACTED"

class ProxyLog(Base):
    __tablename__ = "proxy_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="proxy_logs")
    
    model = Column(String)
    action = Column(Enum(ProxyAction))
    
    risk_score = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    findings_count = Column(Integer, default=0)
    
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    
    request_summary = Column(Text, nullable=True) # Truncated prompt/endpoint
