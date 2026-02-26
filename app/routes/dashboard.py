"""API Routes - Dashboard"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import cast, func, Date as SQLDate
from datetime import datetime, timedelta

from app.database import get_db
from app.models.user import User, UserRole
from app.models.scan import DLPScan, RiskLevel
from app.models.audit import ProxyLog, ProxyAction
from app.utils.auth import get_current_active_user

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/overview")
async def get_dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get dashboard overview statistics"""
    
    # Base query filter
    filter_user = None
    # Rigorous check: strictly ensure admin role to bypass filter
    is_admin = current_user.role == UserRole.ADMIN
    
    if not is_admin:
        filter_user = DLPScan.user_id == current_user.id
        
    def apply_filter(query):
        return query.filter(filter_user) if filter_user is not None else query

    # Total scans
    q = db.query(func.count(DLPScan.id))
    total_scans = apply_filter(q).scalar()
    
    # Scans today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    q = db.query(func.count(DLPScan.id)).filter(DLPScan.created_at >= today_start)
    scans_today = apply_filter(q).scalar()
    
    # High risk scans (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    q = db.query(func.count(DLPScan.id)).filter(
        DLPScan.created_at >= week_ago,
        DLPScan.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL])
    )
    high_risk_scans = apply_filter(q).scalar()
    
    # Total users (Only show real count if admin, else 1)
    if current_user.role.value == "admin":
        total_users = db.query(func.count(User.id)).scalar()
        active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar()
    else:
        total_users = 1
        active_users = 1
    
    # Scan trends (last 7 days) — single aggregated query
    week_ago_trend = today_start - timedelta(days=6)
    trend_q = db.query(
        cast(DLPScan.created_at, SQLDate).label("day"),
        func.count(DLPScan.id).label("count")
    ).filter(DLPScan.created_at >= week_ago_trend)
    trend_q = apply_filter(trend_q)
    trend_rows = trend_q.group_by(cast(DLPScan.created_at, SQLDate)).all()

    trend_map = {str(row.day): row.count for row in trend_rows}
    scan_trends = []
    for i in range(6, -1, -1):
        day = today_start - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        scan_trends.append({'date': day_str, 'count': trend_map.get(day_str, 0)})

    # Risk distribution — single aggregated query
    risk_q = db.query(
        DLPScan.risk_level,
        func.count(DLPScan.id).label("count")
    )
    risk_q = apply_filter(risk_q)
    risk_rows = risk_q.group_by(DLPScan.risk_level).all()

    risk_distribution = {level.value: 0 for level in RiskLevel}
    for row in risk_rows:
        if row.risk_level is not None:
            risk_distribution[row.risk_level.value] = row.count
    
    return {
        'total_scans': total_scans,
        'scans_today': scans_today,
        'high_risk_scans': high_risk_scans,
        'total_users': total_users,
        'active_users': active_users,
        'scan_trends': scan_trends,
        'risk_distribution': risk_distribution,
        'user_info': {
            'username': current_user.username,
            'role': current_user.role.value
        }
    }

@router.get("/firewall-stats")
async def get_firewall_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get statistics for the AI Firewall Dashboard"""
    
    # Require Admin
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # 1. Action Counts
    stats = db.query(
        ProxyLog.action, func.count(ProxyLog.id)
    ).group_by(ProxyLog.action).all()
    
    action_counts = {action.value: count for action, count in stats}
    
    # Calculate derived stats
    total_blocked = action_counts.get("BLOCKED_OPA", 0) + action_counts.get("BLOCKED_DLP", 0)
    total_redacted = action_counts.get("REDACTED", 0)
    total_allowed = action_counts.get("ALLOWED", 0)
    total_requests = total_blocked + total_redacted + total_allowed
    
    # 2. Recent Logs (Last 50)
    recent_logs = db.query(ProxyLog).order_by(ProxyLog.timestamp.desc()).limit(50).all()
    
    logs_data = []
    for log in recent_logs:
        logs_data.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "user": log.user.username if log.user else "Unknown",
            "model": log.model,
            "action": log.action.value,
            "risk_score": log.risk_score,
            "findings": log.findings_count,
            "summary": log.request_summary
        })
        
    return {
        "stats": {
            "total_requests": total_requests,
            "blocked": total_blocked,
            "redacted": total_redacted,
            "allowed": total_allowed
        },
        "logs": logs_data
    }
