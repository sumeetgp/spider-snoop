"""
API Routes — Bulk Scan (Batch Text DLP)

Endpoints
---------
  POST  /api/scans/bulk            Submit up to 20 text items for batch scanning
  GET   /api/scans/bulk/{batch_id} Poll batch status and retrieve results
  GET   /api/scans/bulk            List recent batches for the current user
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.batch import BulkScanBatch, BatchStatus
from app.models.user import User
from app.routes.scans import get_dlp_engine
from app.utils.auth import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans/bulk", tags=["Bulk Scan"])

_MAX_BATCH_ITEMS   = 20
_MAX_CONTENT_CHARS = 50_000


# ── Schemas ───────────────────────────────────────────────────────────────────

class BulkItem(BaseModel):
    content: str
    label: Optional[str] = None   # caller-supplied identifier for this item

    @field_validator("content")
    @classmethod
    def content_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("content must not be empty")
        return v[:_MAX_CONTENT_CHARS]


class BulkScanRequest(BaseModel):
    items: List[BulkItem]

    @field_validator("items")
    @classmethod
    def validate_items(cls, v):
        if not v:
            raise ValueError("items list must not be empty")
        if len(v) > _MAX_BATCH_ITEMS:
            raise ValueError(f"Maximum {_MAX_BATCH_ITEMS} items per batch")
        return v


# ── Background batch processor ────────────────────────────────────────────────

async def _run_batch(batch_id: str, items: List[BulkItem], user_id: int) -> None:
    """
    Background coroutine: scans all items and writes results back to the DB.
    Runs via asyncio.create_task — never raises to the caller.
    """
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        batch = db.query(BulkScanBatch).filter(BulkScanBatch.batch_id == batch_id).first()
        if not batch:
            logger.error(f"bulk_scan: batch {batch_id} not found")
            return

        batch.status = BatchStatus.RUNNING
        db.commit()

        engine = get_dlp_engine()
        results = []
        completed = 0
        failed    = 0

        for idx, item in enumerate(items):
            item_result = {
                "index": idx,
                "label": item.label or f"item_{idx}",
                "status": "pending",
                "risk_level": None,
                "verdict": None,
                "threat_score": None,
                "findings_count": 0,
                "findings": [],
                "error": None,
            }
            try:
                scan = await engine.scan(item.content)
                item_result.update({
                    "status":        "completed",
                    "risk_level":    scan.get("risk_level"),
                    "verdict":       scan.get("verdict"),
                    "threat_score":  scan.get("threat_score"),
                    "findings_count": len(scan.get("findings") or []),
                    "findings":      scan.get("findings") or [],
                })
                completed += 1
            except Exception as e:
                item_result.update({"status": "failed", "error": str(e)[:200]})
                failed += 1
                logger.warning(f"bulk_scan: item {idx} in batch {batch_id} failed: {e}")

            results.append(item_result)

        final_status = (
            BatchStatus.COMPLETED if failed == 0 else
            BatchStatus.PARTIAL   if completed > 0 else
            BatchStatus.FAILED
        )

        batch.status       = final_status
        batch.completed    = completed
        batch.failed       = failed
        batch.results      = results
        batch.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        logger.error(f"bulk_scan: batch {batch_id} processor crashed: {e}")
        try:
            batch = db.query(BulkScanBatch).filter(BulkScanBatch.batch_id == batch_id).first()
            if batch:
                batch.status = BatchStatus.FAILED
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("", status_code=202)
async def submit_bulk_scan(
    body: BulkScanRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Submit up to 20 text payloads for parallel DLP scanning.

    Returns a `batch_id` immediately (HTTP 202 Accepted).
    Poll `GET /api/scans/bulk/{batch_id}` to retrieve results.
    Typical completion: 2–15 seconds depending on item count.
    """
    bid = str(uuid.uuid4())

    batch = BulkScanBatch(
        batch_id    = bid,
        user_id     = current_user.id,
        status      = BatchStatus.PENDING,
        total_items = len(body.items),
    )
    db.add(batch)
    db.commit()

    # Start background processing
    asyncio.create_task(_run_batch(bid, body.items, current_user.id))

    return {
        "batch_id":    bid,
        "status":      "PENDING",
        "total_items": len(body.items),
        "message":     f"Batch accepted. Poll GET /api/scans/bulk/{bid} for results.",
    }


@router.get("/{batch_id}")
async def get_batch_status(
    batch_id: str,
    include_findings: bool = True,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Poll a batch job for status and results.

    Set `include_findings=false` to get a lightweight status-only response.
    """
    batch = db.query(BulkScanBatch).filter(
        BulkScanBatch.batch_id == batch_id,
        BulkScanBatch.user_id  == current_user.id,
    ).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")

    response = {
        "batch_id":    batch.batch_id,
        "status":      batch.status.value,
        "total_items": batch.total_items,
        "completed":   batch.completed,
        "failed":      batch.failed,
        "created_at":  batch.created_at.isoformat() if batch.created_at else None,
        "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
    }

    if batch.results and batch.status in (BatchStatus.COMPLETED, BatchStatus.PARTIAL, BatchStatus.FAILED):
        if include_findings:
            response["results"] = batch.results
        else:
            # Lightweight summary — no finding details
            response["results"] = [
                {k: v for k, v in r.items() if k != "findings"}
                for r in batch.results
            ]

    # Quick summary stats when complete
    if batch.results:
        risk_counts: dict = {}
        for r in batch.results:
            rl = r.get("risk_level") or "UNKNOWN"
            risk_counts[rl] = risk_counts.get(rl, 0) + 1
        response["risk_summary"] = risk_counts

    return response


@router.get("")
async def list_batches(
    limit: int = 20,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List recent bulk scan batches for the current user (no result details)."""
    limit = max(1, min(limit, 100))
    batches = (
        db.query(BulkScanBatch)
        .filter(BulkScanBatch.user_id == current_user.id)
        .order_by(BulkScanBatch.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "count": len(batches),
        "batches": [
            {
                "batch_id":    b.batch_id,
                "status":      b.status.value,
                "total_items": b.total_items,
                "completed":   b.completed,
                "failed":      b.failed,
                "created_at":  b.created_at.isoformat() if b.created_at else None,
                "completed_at": b.completed_at.isoformat() if b.completed_at else None,
            }
            for b in batches
        ],
    }
