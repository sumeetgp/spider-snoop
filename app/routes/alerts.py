"""
API Routes — Alert Configuration & History

Endpoints
---------
  GET    /api/alerts/configs                     List user's alert configs
  POST   /api/alerts/configs                     Create a new alert config
  PUT    /api/alerts/configs/{id}                Update an alert config
  DELETE /api/alerts/configs/{id}                Delete an alert config
  POST   /api/alerts/configs/{id}/test           Fire a test notification
  GET    /api/alerts/history                     List recent alert history (last 100)
"""
from __future__ import annotations

import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator, HttpUrl
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import AlertConfig, AlertHistory, AlertTrigger
from app.models.user import User
from app.utils.auth import get_current_active_user

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class AlertConfigCreate(BaseModel):
    name: str = "Default Alert"
    enabled: bool = True
    trigger_on: AlertTrigger = AlertTrigger.CRITICAL
    webhook_url: Optional[str] = None
    email: Optional[str] = None

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook(cls, v):
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("webhook_url must start with http:// or https://")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if v and "@" not in v:
            raise ValueError("email must be a valid email address")
        return v

    def at_least_one_destination(self):
        if not self.webhook_url and not self.email:
            raise ValueError("At least one of webhook_url or email must be provided")


class AlertConfigUpdate(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None
    trigger_on: Optional[AlertTrigger] = None
    webhook_url: Optional[str] = None
    email: Optional[str] = None


class AlertConfigOut(BaseModel):
    id: int
    name: str
    enabled: bool
    trigger_on: str
    webhook_url: Optional[str]
    email: Optional[str]

    class Config:
        from_attributes = True


class AlertHistoryOut(BaseModel):
    id: int
    config_id: Optional[int]
    scan_id: Optional[int]
    channel: str
    status: str
    response_code: Optional[int]
    error_message: Optional[str]
    fired_at: str

    class Config:
        from_attributes = True


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/configs", response_model=List[AlertConfigOut])
async def list_alert_configs(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List all alert configurations for the current user."""
    return db.query(AlertConfig).filter(AlertConfig.user_id == current_user.id).all()


@router.post("/configs", response_model=AlertConfigOut, status_code=201)
async def create_alert_config(
    body: AlertConfigCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Create a new alert configuration."""
    if not body.webhook_url and not body.email:
        raise HTTPException(status_code=422, detail="At least one of webhook_url or email must be provided")

    cfg = AlertConfig(
        user_id=current_user.id,
        name=body.name,
        enabled=body.enabled,
        trigger_on=body.trigger_on,
        webhook_url=body.webhook_url,
        email=body.email,
    )
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg


@router.put("/configs/{config_id}", response_model=AlertConfigOut)
async def update_alert_config(
    config_id: int,
    body: AlertConfigUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Update an existing alert configuration."""
    cfg = db.query(AlertConfig).filter(
        AlertConfig.id == config_id, AlertConfig.user_id == current_user.id
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Alert config not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(cfg, field, value)

    db.commit()
    db.refresh(cfg)
    return cfg


@router.delete("/configs/{config_id}", status_code=204)
async def delete_alert_config(
    config_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Delete an alert configuration."""
    cfg = db.query(AlertConfig).filter(
        AlertConfig.id == config_id, AlertConfig.user_id == current_user.id
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Alert config not found")
    db.delete(cfg)
    db.commit()


@router.post("/configs/{config_id}/test", status_code=200)
async def test_alert_config(
    config_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Send a test notification via the specified alert config."""
    cfg = db.query(AlertConfig).filter(
        AlertConfig.id == config_id, AlertConfig.user_id == current_user.id
    ).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Alert config not found")

    from app.core.alerting import _send_webhook, _send_email_sync, _build_webhook_payload, _build_email_html

    test_scan = {
        "risk_level": "CRITICAL",
        "verdict": "TEST ALERT — This is a test notification from SpiderCob DLP",
        "threat_score": 100,
        "findings": [{"type": "test_finding", "severity": "CRITICAL", "value": "te**"}],
        "source": "TEST",
    }
    results = {}

    if cfg.webhook_url:
        payload = _build_webhook_payload(test_scan, scan_id=0)
        payload["event"] = "dlp_alert_test"
        success, code, err = await _send_webhook(cfg.webhook_url, payload)
        results["webhook"] = {"success": success, "status_code": code, "error": err or None}

    if cfg.email:
        subject, html = _build_email_html(test_scan, scan_id=0)
        subject = "[TEST] " + subject
        success, err = await asyncio.to_thread(_send_email_sync, cfg.email, subject, html)
        results["email"] = {"success": success, "error": err or None}

    if not results:
        raise HTTPException(status_code=422, detail="No destinations configured on this alert config")

    return {"status": "test_fired", "results": results}


@router.get("/history")
async def get_alert_history(
    limit: int = 100,
    scan_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List recent alert history for the current user."""
    limit = max(1, min(limit, 200))
    q = db.query(AlertHistory).filter(AlertHistory.user_id == current_user.id)
    if scan_id:
        q = q.filter(AlertHistory.scan_id == scan_id)
    rows = q.order_by(AlertHistory.fired_at.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "history": [
            {
                "id": r.id,
                "config_id": r.config_id,
                "scan_id": r.scan_id,
                "channel": r.channel.value if r.channel else None,
                "status": r.status.value if r.status else None,
                "response_code": r.response_code,
                "error_message": r.error_message,
                "fired_at": r.fired_at.isoformat() if r.fired_at else None,
            }
            for r in rows
        ],
    }
