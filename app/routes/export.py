"""
API Routes — Scan Export & Reporting

Endpoints
---------
  GET  /api/scans/{id}/export          Export a single scan  (?format=pdf|csv)
  GET  /api/scans/export               Bulk export by date range (?format=pdf|csv&from=ISO&to=ISO)
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import DLPScan, RiskLevel
from app.models.user import User
from app.utils.auth import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Export"])

# ── Colour palette (same brand as dashboard) ──────────────────────────────────
_BRAND   = (0x88/255, 1.0, 1.0)          # #88FFFF cyan
_BG      = (0x0D/255, 0x11/255, 0x17/255) # #0D1117
_CARD    = (0x16/255, 0x1B/255, 0x22/255) # #161B22
_WHITE   = (0xC9/255, 0xD1/255, 0xD9/255) # #C9D1D9
_GRAY    = (0x48/255, 0x50/255, 0x58/255) # #485058

_RISK_COLORS = {
    "CRITICAL": (0xF8/255, 0x51/255, 0x49/255),
    "HIGH":     (0xD2/255, 0x99/255, 0x22/255),
    "MEDIUM":   (0x13/255, 0x88/255, 0x96/255),
    "LOW":      (0x23/255, 0x86/255, 0x36/255),
}

# ── PDF generator ─────────────────────────────────────────────────────────────

def _build_pdf(scans: list[DLPScan], title: str) -> bytes:
    """Render scans to a PDF byte string using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )

    BG_HEX = HexColor("#0D1117")
    CARD_HEX = HexColor("#161B22")
    BRAND_HEX = HexColor("#88FFFF")
    TEXT_HEX = HexColor("#C9D1D9")
    GRAY_HEX = HexColor("#8B949E")
    risk_hex = {
        "CRITICAL": HexColor("#F85149"),
        "HIGH":     HexColor("#D29922"),
        "MEDIUM":   HexColor("#1388c0"),
        "LOW":      HexColor("#238636"),
    }

    styles = getSampleStyleSheet()
    h1_style = ParagraphStyle("h1", parent=styles["Heading1"],
        textColor=BRAND_HEX, fontSize=22, spaceAfter=4)
    sub_style = ParagraphStyle("sub", parent=styles["Normal"],
        textColor=GRAY_HEX, fontSize=9, spaceAfter=16)
    label_style = ParagraphStyle("label", parent=styles["Normal"],
        textColor=GRAY_HEX, fontSize=8, fontName="Helvetica")
    body_style = ParagraphStyle("body", parent=styles["Normal"],
        textColor=TEXT_HEX, fontSize=9)
    verdict_style = ParagraphStyle("verdict", parent=styles["Normal"],
        textColor=TEXT_HEX, fontSize=8, fontName="Helvetica-Oblique")

    story = [
        Paragraph("🕸️ SpiderCob DLP", h1_style),
        Paragraph(title, sub_style),
        Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
            f"Total scans: {len(scans)}",
            label_style,
        ),
        Spacer(1, 8*mm),
    ]

    for scan in scans:
        findings = scan.findings or []
        risk_color = risk_hex.get(scan.risk_level or "LOW", GRAY_HEX)
        risk_label = scan.risk_level or "UNKNOWN"

        # Scan header row
        header_data = [[
            Paragraph(f"<b>Scan #{scan.id}</b>", body_style),
            Paragraph(scan.source or "API", body_style),
            Paragraph(
                f"<font color='#{_hex_str(risk_color)}'>■ {risk_label}</font>",
                body_style,
            ),
            Paragraph(f"Score: {scan.threat_score or 0}/100", body_style),
            Paragraph(
                scan.created_at.strftime("%Y-%m-%d %H:%M") if scan.created_at else "—",
                label_style,
            ),
        ]]
        header_table = Table(header_data, colWidths=[35*mm, 30*mm, 30*mm, 30*mm, 40*mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CARD_HEX),
            ("TEXTCOLOR",  (0, 0), (-1, -1), TEXT_HEX),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [CARD_HEX]),
            ("BOX",        (0, 0), (-1, -1), 0.5, GRAY_HEX),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(header_table)

        # Verdict
        if scan.verdict:
            story.append(
                Paragraph(f"Verdict: {scan.verdict[:200]}", verdict_style)
            )

        # Findings table
        if findings:
            rows = [[
                Paragraph("<b>Type</b>", label_style),
                Paragraph("<b>Severity</b>", label_style),
                Paragraph("<b>Value</b>", label_style),
                Paragraph("<b>Context Score</b>", label_style),
            ]]
            for f in findings[:30]:
                sev = f.get("severity", "LOW")
                sev_col = risk_hex.get(sev, GRAY_HEX)
                rows.append([
                    Paragraph(str(f.get("type", "—")), label_style),
                    Paragraph(
                        f"<font color='#{_hex_str(sev_col)}'>{sev}</font>",
                        label_style,
                    ),
                    Paragraph(str(f.get("value", "—"))[:40], label_style),
                    Paragraph(str(round(f.get("context_score", 0), 2)), label_style),
                ])
            findings_table = Table(rows, colWidths=[50*mm, 28*mm, 60*mm, 27*mm])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), BG_HEX),
                ("BACKGROUND",    (0, 1), (-1, -1), CARD_HEX),
                ("TEXTCOLOR",     (0, 0), (-1, -1), TEXT_HEX),
                ("BOX",           (0, 0), (-1, -1), 0.3, GRAY_HEX),
                ("INNERGRID",     (0, 0), (-1, -1), 0.2, GRAY_HEX),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ]))
            story.append(findings_table)

        story.append(Spacer(1, 6*mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY_HEX))
        story.append(Spacer(1, 4*mm))

    doc.build(story)
    return buf.getvalue()


def _hex_str(color) -> str:
    """Convert reportlab Color to 6-char hex string."""
    try:
        return f"{int(color.red*255):02X}{int(color.green*255):02X}{int(color.blue*255):02X}"
    except Exception:
        return "888888"


# ── CSV generator ─────────────────────────────────────────────────────────────

def _build_csv(scans: list[DLPScan]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "scan_id", "source", "risk_level", "threat_score",
        "findings_count", "verdict", "scan_type",
        "duration_ms", "created_at",
    ])
    for scan in scans:
        findings = scan.findings or []
        writer.writerow([
            scan.id,
            scan.source or "",
            scan.risk_level or "",
            scan.threat_score or 0,
            len(findings),
            (scan.verdict or "")[:300],
            scan.scan_type,
            scan.scan_duration_ms or 0,
            scan.created_at.isoformat() if scan.created_at else "",
        ])
    return buf.getvalue()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/api/scans/{scan_id}/export")
async def export_single_scan(
    scan_id: int,
    format: str = Query("pdf", pattern="^(pdf|csv)$"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Export a single scan report.

    - `format=pdf` — returns a styled PDF (default)
    - `format=csv` — returns a CSV row with scan metadata
    """
    scan = db.query(DLPScan).filter(
        DLPScan.id == scan_id,
        DLPScan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    filename = f"spidercob_scan_{scan_id}"

    if format == "csv":
        content = _build_csv([scan])
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )

    # PDF
    try:
        pdf_bytes = await __import__("asyncio").to_thread(
            _build_pdf, [scan], f"Scan Report — #{scan_id}"
        )
    except Exception as e:
        logger.error(f"PDF generation failed for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
    )


@router.get("/api/scans/export")
async def export_bulk_scans(
    format: str = Query("pdf", pattern="^(pdf|csv)$"),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    risk_level: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=500),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """
    Bulk export scan reports filtered by date range and/or risk level.

    - `from` / `to` — ISO 8601 date strings (e.g. `2026-01-01`)
    - `risk_level`  — filter: LOW | MEDIUM | HIGH | CRITICAL
    - `limit`       — max rows (1–500, default 200)
    - `format`      — pdf | csv
    """
    q = db.query(DLPScan).filter(DLPScan.user_id == current_user.id)

    if from_date:
        try:
            q = q.filter(DLPScan.created_at >= datetime.fromisoformat(from_date))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid 'from' date: {from_date}")

    if to_date:
        try:
            q = q.filter(DLPScan.created_at <= datetime.fromisoformat(to_date))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid 'to' date: {to_date}")

    if risk_level:
        rl = risk_level.upper()
        if rl not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=422, detail=f"Invalid risk_level: {risk_level}")
        q = q.filter(DLPScan.risk_level == rl)

    scans = q.order_by(DLPScan.created_at.desc()).limit(limit).all()

    if not scans:
        raise HTTPException(status_code=404, detail="No scans found matching the given filters")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    filename = f"spidercob_report_{ts}"
    title = f"DLP Scan Report — {len(scans)} scans"
    if from_date or to_date:
        title += f" ({from_date or '…'} → {to_date or 'now'})"

    if format == "csv":
        content = _build_csv(scans)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )

    import asyncio
    try:
        pdf_bytes = await asyncio.to_thread(_build_pdf, scans, title)
    except Exception as e:
        logger.error(f"Bulk PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
    )
