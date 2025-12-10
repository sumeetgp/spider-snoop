"""API Routes - Dashboard"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from app.database import get_db
from app.models.user import User
from app.models.scan import DLPScan, RiskLevel
from app.utils.auth import get_current_active_user

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/overview")
async def get_dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get dashboard overview statistics"""
    
    # Total scans
    total_scans = db.query(func.count(DLPScan.id)).scalar()
    
    # Scans today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = db.query(func.count(DLPScan.id)).filter(
        DLPScan.created_at >= today_start
    ).scalar()
    
    # High risk scans (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    high_risk_scans = db.query(func.count(DLPScan.id)).filter(
        DLPScan.created_at >= week_ago,
        DLPScan.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL])
    ).scalar()
    
    # Total users
    total_users = db.query(func.count(User.id)).scalar()
    
    # Active users (logged in last 30 days - would need login tracking)
    active_users = db.query(func.count(User.id)).filter(
        User.is_active == True
    ).scalar()
    
    # Scan trends (last 7 days)
    scan_trends = []
    for i in range(7):
        day_start = today_start - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        
        count = db.query(func.count(DLPScan.id)).filter(
            DLPScan.created_at >= day_start,
            DLPScan.created_at < day_end
        ).scalar()
        
        scan_trends.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'count': count
        })
    
    scan_trends.reverse()
    
    # Risk distribution
    risk_distribution = {}
    for risk_level in RiskLevel:
        count = db.query(func.count(DLPScan.id)).filter(
            DLPScan.risk_level == risk_level
        ).scalar()
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
