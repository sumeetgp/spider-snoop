"""Bulk Scan Batch model"""
import enum
from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class BatchStatus(str, enum.Enum):
    PENDING    = "PENDING"
    RUNNING    = "RUNNING"
    COMPLETED  = "COMPLETED"
    PARTIAL    = "PARTIAL"    # Some items failed
    FAILED     = "FAILED"


class BulkScanBatch(Base):
    """Tracks a bulk scan job — multiple text payloads scanned as one unit."""
    __tablename__ = "bulk_scan_batches"

    id           = Column(Integer, primary_key=True, index=True)
    batch_id     = Column(String(36), unique=True, index=True, nullable=False)  # UUID
    user_id      = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status       = Column(SAEnum(BatchStatus), default=BatchStatus.PENDING, nullable=False)
    total_items  = Column(Integer, nullable=False, default=0)
    completed    = Column(Integer, nullable=False, default=0)
    failed       = Column(Integer, nullable=False, default=0)
    results      = Column(JSON, nullable=True)   # List of per-item result dicts
    created_at   = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
