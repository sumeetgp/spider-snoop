"""API Routes - Dashboard"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
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
    
    # Scan trends (last 7 days)
    scan_trends = []
    for i in range(7):
        day_start = today_start - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        
        q = db.query(func.count(DLPScan.id)).filter(
            DLPScan.created_at >= day_start,
            DLPScan.created_at < day_end
        )
        count = apply_filter(q).scalar()
        
        scan_trends.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'count': count
        })
    
    scan_trends.reverse()
    
    # Risk distribution
    risk_distribution = {}
    for risk_level in RiskLevel:
        q = db.query(func.count(DLPScan.id)).filter(DLPScan.risk_level == risk_level)
        count = apply_filter(q).scalar()
        risk_distribution[risk_level.value] = count
    
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
