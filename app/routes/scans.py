"""API Routes - DLP Scanning"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, File, UploadFile
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.models.user import User
from app.models.scan import DLPScan, ScanStatus
from app.schemas.scan import ScanCreate, ScanResponse, ScanStats
from app.utils.auth import get_current_active_user
from app.dlp_engine import DLPEngine

router = APIRouter(prefix="/api/scans", tags=["DLP Scanning"])
dlp_engine = DLPEngine()

@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create and execute a DLP scan"""
    # Create scan record
    db_scan = DLPScan(
        user_id=current_user.id,
        source=scan_data.source,
        content=scan_data.content,
        status=ScanStatus.SCANNING
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    try:
        # Perform scan
        result = await dlp_engine.scan(scan_data.content)
        
        # Update scan record
        db_scan.status = ScanStatus.COMPLETED
        db_scan.risk_level = result['risk_level']
        db_scan.findings = result['findings']
        db_scan.verdict = result['verdict']
        db_scan.scan_duration_ms = result['scan_duration_ms']
        db_scan.completed_at = datetime.utcnow()
        
        db.commit()
        db.refresh(db_scan)
        
    except Exception as e:
        db_scan.status = ScanStatus.FAILED
        db_scan.verdict = f"Scan failed: {str(e)}"
        db.commit()
        db.refresh(db_scan)
    
    return db_scan

@router.post("/upload_file", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Upload and scan a file"""
    # Read file content
    try:
        content_bytes = await file.read()
        
        if file.filename.lower().endswith('.docx'):
            try:
                import io
                import docx
                doc = docx.Document(io.BytesIO(content_bytes))
                content = "\n".join([paragraph.text for paragraph in doc.paragraphs])
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to process DOCX file: {str(e)}"
                )
        else:
            try:
                content = content_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    # Fallback to latin-1
                    content = content_bytes.decode('latin-1')
                except:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Binary files are not supported. Please upload text or DOCX files."
                    )
    except HTTPException:
        raise
    except Exception as e:
         raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File upload error: {str(e)}"
        )
    
    # Create scan record
    db_scan = DLPScan(
        user_id=current_user.id,
        source=f"FILE:{file.filename}",
        content=content, # Note: In prod, maybe don't store full file content in DB if huge
        status=ScanStatus.SCANNING
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    try:
        # Perform scan
        result = await dlp_engine.scan(content)
        
        # Update scan record
        db_scan.status = ScanStatus.COMPLETED
        db_scan.risk_level = result['risk_level']
        db_scan.findings = result['findings']
        db_scan.verdict = result['verdict']
        db_scan.ai_analysis = result.get('ai_analysis')
        db_scan.scan_duration_ms = result['scan_duration_ms']
        db_scan.completed_at = datetime.utcnow()
        
        db.commit()
        db.refresh(db_scan)
        
    except Exception as e:
        db_scan.status = ScanStatus.FAILED
        db_scan.verdict = f"Scan failed: {str(e)}"
        db.commit()
        db.refresh(db_scan)
    
    return db_scan

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List DLP scans"""
    # Regular users can only see their own scans
    query = db.query(DLPScan)
    
    if current_user.role.value == "viewer":
        query = query.filter(DLPScan.user_id == current_user.id)
    
    scans = query.order_by(DLPScan.created_at.desc()).offset(skip).limit(limit).all()
    return scans

@router.get("/stats", response_model=ScanStats)
async def get_scan_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan statistics"""
    query = db.query(DLPScan)
    
    if current_user.role.value == "viewer":
        query = query.filter(DLPScan.user_id == current_user.id)
    
    all_scans = query.all()
    
    # Calculate stats
    scans_by_risk = {}
    scans_by_status = {}
    total_duration = 0
    count_with_duration = 0
    
    for scan in all_scans:
        # Risk level stats
        risk = scan.risk_level.value if scan.risk_level else "UNKNOWN"
        scans_by_risk[risk] = scans_by_risk.get(risk, 0) + 1
        
        # Status stats
        status = scan.status.value
        scans_by_status[status] = scans_by_status.get(status, 0) + 1
        
        # Duration stats
        if scan.scan_duration_ms:
            total_duration += scan.scan_duration_ms
            count_with_duration += 1
    
    avg_duration = total_duration / count_with_duration if count_with_duration > 0 else 0
    
    # Get recent scans
    recent_scans = query.order_by(DLPScan.created_at.desc()).limit(10).all()
    
    return ScanStats(
        total_scans=len(all_scans),
        scans_by_risk=scans_by_risk,
        scans_by_status=scans_by_status,
        avg_scan_duration_ms=avg_duration,
        recent_scans=recent_scans
    )

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan by ID"""
    scan = db.query(DLPScan).filter(DLPScan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check permissions
    if current_user.role.value == "viewer" and scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    return scan
