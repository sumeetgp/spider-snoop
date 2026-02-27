"""
Alert Dispatcher
================
Fires webhook and/or email notifications when a scan crosses a severity threshold.

Entry point
-----------
    await fire_alerts(scan_result, user_id, scan_id, db)

Called from scans.py after a scan completes.  Non-blocking — failures are
logged but never surface to the caller.
"""
from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── Severity ordering ─────────────────────────────────────────────────────────
_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_TRIGGER_SEVERITY_MAP = {
    "HIGH":     "HIGH",
    "CRITICAL": "CRITICAL",
    "INCIDENT": "HIGH",     # INCIDENT maps to HIGH as minimum risk level
    "BLOCK":    "CRITICAL", # BLOCK maps to CRITICAL
}


def _should_fire(scan_risk_level: str, trigger_on: str) -> bool:
    """Return True if the scan's risk level meets or exceeds the alert trigger threshold."""
    threshold_sev = _TRIGGER_SEVERITY_MAP.get(trigger_on, "CRITICAL")
    scan_ord      = _SEVERITY_ORDER.get((scan_risk_level or "").upper(), 0)
    trigger_ord   = _SEVERITY_ORDER.get(threshold_sev, 3)
    return scan_ord >= trigger_ord


def _build_webhook_payload(scan_result: dict, scan_id: Optional[int]) -> dict:
    return {
        "event": "dlp_alert",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "risk_level": scan_result.get("risk_level"),
        "verdict": scan_result.get("verdict"),
        "threat_score": scan_result.get("threat_score"),
        "findings_count": len(scan_result.get("findings", [])),
        "top_findings": [
            {"type": f.get("type"), "severity": f.get("severity")}
            for f in (scan_result.get("findings") or [])[:5]
        ],
        "source": scan_result.get("source", "API"),
    }


def _build_email_html(scan_result: dict, scan_id: Optional[int]) -> tuple[str, str]:
    """Return (subject, html_body)."""
    risk = scan_result.get("risk_level", "UNKNOWN")
    score = scan_result.get("threat_score", 0)
    verdict = scan_result.get("verdict", "—")
    findings = scan_result.get("findings") or []

    color_map = {"CRITICAL": "#F85149", "HIGH": "#D29922", "MEDIUM": "#88FFFF", "LOW": "#238636"}
    color = color_map.get(risk, "#888")

    findings_rows = "".join(
        f'<tr><td style="padding:4px 8px;font-family:monospace">{f.get("type","—")}</td>'
        f'<td style="padding:4px 8px;color:{color_map.get(f.get("severity","LOW"),"#888")}">'
        f'{f.get("severity","—")}</td>'
        f'<td style="padding:4px 8px;color:#888">{f.get("value","—")}</td></tr>'
        for f in findings[:10]
    )

    subject = f"[SpiderCob DLP] {risk} Alert — Scan #{scan_id}"
    html = f"""
<html><body style="background:#0d1117;color:#c9d1d9;font-family:Inter,sans-serif;padding:24px">
  <h2 style="color:#88FFFF">🕸️ SpiderCob DLP — Detection Alert</h2>
  <p style="color:#8b949e">A scan has triggered an alert matching your notification rules.</p>
  <table style="width:100%;border-collapse:collapse;margin:16px 0;background:#161b22;border:1px solid #30363d;border-radius:8px">
    <tr><td style="padding:8px 16px;color:#8b949e">Scan ID</td><td style="padding:8px 16px">#{scan_id}</td></tr>
    <tr><td style="padding:8px 16px;color:#8b949e">Risk Level</td><td style="padding:8px 16px;color:{color};font-weight:bold">{risk}</td></tr>
    <tr><td style="padding:8px 16px;color:#8b949e">Threat Score</td><td style="padding:8px 16px">{score}/100</td></tr>
    <tr><td style="padding:8px 16px;color:#8b949e">Verdict</td><td style="padding:8px 16px">{verdict}</td></tr>
    <tr><td style="padding:8px 16px;color:#8b949e">Findings</td><td style="padding:8px 16px">{len(findings)} entities detected</td></tr>
  </table>
  {"<h3 style='color:#c9d1d9'>Top Findings</h3><table style='width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d'><tr style='color:#8b949e;font-size:12px'><th style='padding:4px 8px;text-align:left'>Type</th><th style='text-align:left;padding:4px 8px'>Severity</th><th style='text-align:left;padding:4px 8px'>Value</th></tr>" + findings_rows + "</table>" if findings else ""}
  <p style="margin-top:24px;color:#8b949e;font-size:12px">
    Sent by SpiderCob DLP &bull; <a href="https://spidercob.com/dashboard" style="color:#88FFFF">View Dashboard</a>
  </p>
</body></html>"""
    return subject, html


async def _send_webhook(url: str, payload: dict, timeout: int = 10) -> tuple[bool, int, str]:
    """POST JSON payload to webhook URL. Returns (success, status_code, error)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json", "User-Agent": "SpiderCob-DLP/1.0"},
            )
            return resp.status_code < 400, resp.status_code, ""
    except Exception as e:
        return False, 0, str(e)[:200]


def _send_email_sync(to: str, subject: str, html: str) -> tuple[bool, str]:
    """Synchronous SMTP send — run in thread."""
    smtp_host = getattr(settings, "SMTP_HOST", None)
    smtp_port = getattr(settings, "SMTP_PORT", 587)
    smtp_user = getattr(settings, "SMTP_USER", None)
    smtp_pass = getattr(settings, "SMTP_PASSWORD", None)
    smtp_from = getattr(settings, "SMTP_FROM", smtp_user or "noreply@spidercob.com")

    if not smtp_host:
        return False, "SMTP_HOST not configured"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = smtp_from
        msg["To"]      = to
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            if smtp_port != 25:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [to], msg.as_string())
        return True, ""
    except Exception as e:
        return False, str(e)[:200]


async def fire_alerts(
    scan_result: dict,
    user_id: int,
    scan_id: Optional[int],
    db,
) -> None:
    """
    Non-blocking alert dispatcher.  Called after each scan completes.
    Loads active AlertConfig rows for the user and dispatches notifications.
    """
    from app.models.alert import AlertConfig, AlertHistory, AlertChannel, AlertStatus

    try:
        configs = (
            db.query(AlertConfig)
            .filter(AlertConfig.user_id == user_id, AlertConfig.enabled == True)
            .all()
        )
    except Exception as e:
        logger.error(f"alerting: failed to load configs for user {user_id}: {e}")
        return

    if not configs:
        return

    risk_level = scan_result.get("risk_level", "LOW")

    for cfg in configs:
        if not _should_fire(risk_level, cfg.trigger_on.value):
            continue

        payload  = _build_webhook_payload(scan_result, scan_id)
        subject, html = _build_email_html(scan_result, scan_id)

        # ── Webhook ───────────────────────────────────────────────────────────
        if cfg.webhook_url:
            success, code, err = await _send_webhook(cfg.webhook_url, payload)
            status = AlertStatus.SENT if success else AlertStatus.FAILED
            if not success:
                logger.warning(f"alerting: webhook failed for config {cfg.id}: {err}")
            try:
                db.add(AlertHistory(
                    user_id=user_id, config_id=cfg.id, scan_id=scan_id,
                    channel=AlertChannel.WEBHOOK, status=status,
                    response_code=code, error_message=err or None,
                ))
                db.commit()
            except Exception as ex:
                logger.error(f"alerting: failed to persist webhook history: {ex}")
                db.rollback()

        # ── Email ─────────────────────────────────────────────────────────────
        if cfg.email:
            try:
                success, err = await asyncio.to_thread(_send_email_sync, cfg.email, subject, html)
            except Exception as ex:
                success, err = False, str(ex)[:200]
            status = AlertStatus.SENT if success else AlertStatus.FAILED
            if not success:
                logger.warning(f"alerting: email failed for config {cfg.id}: {err}")
            try:
                db.add(AlertHistory(
                    user_id=user_id, config_id=cfg.id, scan_id=scan_id,
                    channel=AlertChannel.EMAIL, status=status,
                    error_message=err or None,
                ))
                db.commit()
            except Exception as ex:
                logger.error(f"alerting: failed to persist email history: {ex}")
                db.rollback()
