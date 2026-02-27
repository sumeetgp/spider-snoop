"""API Routes — Detection Metrics (admin-only)

Endpoints
---------
  GET  /api/metrics                  Full snapshot of all detection counters + timing
  GET  /api/metrics/false-positives  Recent filtered-out findings (tuning samples)
  POST /api/metrics/reset            Zero all counters and clear FP buffer
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.core.detection_metrics import metrics
from app.models.user import User, UserRole
from app.utils.auth import get_current_active_user

router = APIRouter(prefix="/api/metrics", tags=["Metrics"])


def _require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@router.get("")
async def get_metrics_snapshot(_: User = Depends(_require_admin)):
    """
    Current detection telemetry snapshot.

    Returns:
      - entities.detected_total       — raw regex + Presidio hits before any filter
      - entities.after_validation      — hits that passed all gates
      - entities.rejection_breakdown   — counts by rejection reason
      - by_type                        — per entity-type detected / validated counts
      - by_source                      — regex vs presidio breakdown
      - avg_inference_ms               — rolling average latency per model
      - false_positive_buffer_size     — how many FP samples are buffered
    """
    return metrics.snapshot()


@router.get("/false-positives")
async def get_false_positive_samples(
    limit: int = 50,
    reason: Optional[str] = None,
    entity_type: Optional[str] = None,
    _: User = Depends(_require_admin),
):
    """
    Recent filtered-out detection samples — useful for pattern tuning.

    Each sample shows *why* a match was suppressed:
      - validator_rejection   — failed Luhn / SSN / JWT validator
      - entropy_rejection     — entropy too low or common base64 content
      - context_gate_rejection — requires_context_keywords not met
      - medical_relabel       — bank_account re-labelled as patient ID in medical doc

    Query params:
      limit        – max samples to return (1–100, default 50)
      reason       – filter by rejection reason
      entity_type  – filter by entity type (e.g. "credit_card", "bank_account")
    """
    limit = max(1, min(limit, 100))
    samples = metrics.fp_samples(limit=limit)

    if reason:
        samples = [s for s in samples if s["reason"] == reason]
    if entity_type:
        samples = [s for s in samples if s["entity_type"] == entity_type]

    return {
        "count": len(samples),
        "available_reasons": [
            "validator_rejection",
            "entropy_rejection",
            "context_gate_rejection",
            "medical_relabel",
        ],
        "samples": samples,
    }


@router.post("/reset")
async def reset_metrics(_: User = Depends(_require_admin)):
    """
    Zero all counters and clear the FP sample buffer.
    Useful at the start of a tuning session so measurements are fresh.
    """
    metrics.reset()
    return {"status": "reset", "message": "All detection metrics counters and FP buffer cleared"}
