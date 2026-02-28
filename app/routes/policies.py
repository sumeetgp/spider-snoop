"""Policy Engine REST API — CRUD, evaluate, audit log"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.policy import Policy, PolicyDecisionLog, PolicyAction
from app.models.user import User, UserRole
from app.schemas.policy import (
    PolicyCreate, PolicyUpdate, PolicyOut,
    ContextInput, PolicyEvaluateRequest, PolicyDecisionOut,
    PolicyDecisionLogOut,
)
from app.core.policy_engine import PolicyEngine, ContextPayload
from app.utils.auth import get_current_active_user

router = APIRouter(prefix="/api/policies", tags=["Policies"])
logger = logging.getLogger(__name__)

# ── Default seed data ──────────────────────────────────────────────────────────
_DEFAULT_POLICIES = [
    {
        "name":        "block_critical_external",
        "description": "Block any CRITICAL-risk content going externally",
        "priority":    1,
        "action":      "block",
        "simulate":    False,
        "conditions":  {"risk_bands": ["CRITICAL"], "destinations": ["external"]},
    },
    {
        "name":        "block_contractor_secrets_external",
        "description": "Block contractors/vendors uploading secrets to external destinations",
        "priority":    2,
        "action":      "block",
        "simulate":    False,
        "conditions":  {
            "risk_bands":    ["HIGH", "CRITICAL"],
            "finding_types": [
                "aws_secret_access_key", "private_key",
                "github_access_token", "stripe_secret_key",
            ],
            "destinations": ["external"],
            "user_roles":   ["contractor", "vendor"],
        },
    },
    {
        "name":        "quarantine_unmanaged_high",
        "description": "Simulate quarantine for unmanaged/unknown devices with HIGH+ risk",
        "priority":    5,
        "action":      "quarantine",
        "simulate":    True,
        "conditions":  {
            "risk_bands":   ["HIGH", "CRITICAL"],
            "device_trust": ["unmanaged", "unknown"],
        },
    },
    {
        "name":        "flag_high_risk_internal",
        "description": "Flag HIGH/CRITICAL findings on internal destinations for review",
        "priority":    10,
        "action":      "flag",
        "simulate":    False,
        "conditions":  {"risk_bands": ["HIGH", "CRITICAL"], "destinations": ["internal"]},
    },
]


def seed_default_policies(db: Session) -> None:
    """Insert default policies only when the table is empty."""
    try:
        if db.query(Policy).count() > 0:
            return
        for p in _DEFAULT_POLICIES:
            db.add(Policy(**p))
        db.commit()
        logger.info("Policy Engine: seeded %d default policies", len(_DEFAULT_POLICIES))
    except Exception as exc:
        logger.warning("Policy Engine: seed failed (non-fatal): %s", exc)
        db.rollback()


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user


def _require_analyst(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role not in (UserRole.ADMIN, UserRole.ANALYST):
        raise HTTPException(status_code=403, detail="Analyst or Admin role required")
    return current_user


# ── CRUD endpoints ─────────────────────────────────────────────────────────────

@router.get("/", response_model=List[PolicyOut])
def list_policies(
    db: Session = Depends(get_db),
    _: User = Depends(_require_analyst),
):
    """List all policies ordered by priority."""
    return db.query(Policy).order_by(Policy.priority).all()


@router.post("/", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
def create_policy(
    body: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
):
    """Create a new policy."""
    if body.action not in PolicyAction._value2member_map_:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action '{body.action}'. Must be one of: {list(PolicyAction._value2member_map_)}",
        )
    if db.query(Policy).filter(Policy.name == body.name).first():
        raise HTTPException(status_code=409, detail=f"Policy '{body.name}' already exists")

    policy = Policy(
        name=body.name,
        description=body.description,
        conditions=body.conditions.model_dump(),
        action=body.action,
        priority=body.priority,
        enabled=body.enabled,
        simulate=body.simulate,
        created_by=current_user.id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(_require_analyst),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(_require_admin),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if body.action is not None and body.action not in PolicyAction._value2member_map_:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action '{body.action}'",
        )

    update_data = body.model_dump(exclude_unset=True)
    if "conditions" in update_data and update_data["conditions"] is not None:
        update_data["conditions"] = body.conditions.model_dump()

    for field, value in update_data.items():
        setattr(policy, field, value)

    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: int,
    hard: bool = Query(False, description="Hard delete instead of disabling"),
    db: Session = Depends(get_db),
    _: User = Depends(_require_admin),
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if hard:
        db.delete(policy)
    else:
        policy.enabled = False
    db.commit()


# ── Evaluate (dry-run) ─────────────────────────────────────────────────────────

@router.post("/evaluate", response_model=PolicyDecisionOut)
def evaluate_policy(
    body: PolicyEvaluateRequest,
    db: Session = Depends(get_db),
    _: User = Depends(_require_analyst),
):
    """Dry-run policy evaluation against a mock scan result + context."""
    all_policies = db.query(Policy).all()
    ctx = ContextPayload(**body.context.model_dump())
    decision = PolicyEngine().evaluate(body.scan_result, ctx, all_policies)
    return PolicyDecisionOut(
        action=decision.action.value,
        policy_id=decision.policy_id,
        policy_name=decision.policy_name,
        matched_conditions=decision.matched_conditions,
        simulated=decision.simulated,
        would_have_action=decision.would_have_action.value if decision.would_have_action else None,
        evaluation_trace=decision.evaluation_trace,
    )


# ── Audit log ──────────────────────────────────────────────────────────────────

@router.get("/decisions/", response_model=List[PolicyDecisionLogOut])
def list_decisions(
    scan_id:   Optional[int] = Query(None),
    policy_id: Optional[int] = Query(None),
    days:      Optional[int] = Query(None, description="Limit to last N days"),
    db: Session = Depends(get_db),
    _: User = Depends(_require_analyst),
):
    """List policy decision log entries with optional filters."""
    q = db.query(PolicyDecisionLog)
    if scan_id is not None:
        q = q.filter(PolicyDecisionLog.scan_id == scan_id)
    if policy_id is not None:
        q = q.filter(PolicyDecisionLog.policy_id == policy_id)
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        q = q.filter(PolicyDecisionLog.created_at >= cutoff)
    return q.order_by(PolicyDecisionLog.created_at.desc()).limit(500).all()
