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

from app.dlp_engine import DLPEngine
from app.utils.limiter import limiter, get_rate_limit_key
from fastapi import Request

router = APIRouter(prefix="/api/scans", tags=["DLP Scanning"])
dlp_engine = DLPEngine()

@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("50/60minute")
async def create_scan(
    request: Request,
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
        if result.get('ai_analysis'):
            import json
            db_scan.ai_analysis = json.dumps(result['ai_analysis'])
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
@limiter.limit("50/60minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Upload and scan a file for sensitive data.
    
    Supported formats:
    - **Documents**: PDF, DOCX, TXT, MD, CSV, JSON
    - **Images**: PNG, JPG, JPEG (OCR enabled)
    
    **Limit**: 10 MB per file.
    """
    # Read file content
    try:
        content_bytes = await file.read()
        
        # 0. File Guard (AV/YARA)
        # Check if file_guard is available (it might fail if ClamAV container is down, but we proceed or fail open/closed?)
        if hasattr(request.app.state, 'file_guard') and request.app.state.file_guard:
            is_safe, findings = await request.app.state.file_guard.scan_bytes(content_bytes)
            if not is_safe:
                # Log the threat
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"File Guard blocked upload: {file.filename}, Findings: {findings}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Security Threat Detected: {', '.join(findings)}"
                )

        import io
        filename = file.filename.lower()
        
        if filename.endswith('.docx'):
            try:
                import docx
                doc = docx.Document(io.BytesIO(content_bytes))
                content = "\n".join([paragraph.text for paragraph in doc.paragraphs])
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to process DOCX file: {str(e)}"
                )
                  
        elif filename.endswith('.pdf'):
            try:
                import pypdf
                pdf_reader = pypdf.PdfReader(io.BytesIO(content_bytes))
                content = ""
                for page in pdf_reader.pages:
                    content += page.extract_text() + "\n"
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to process PDF file: {str(e)}"
                )
                   
        elif filename.endswith(('.png', '.jpg', '.jpeg')):
            try:
                import pytesseract
                from PIL import Image
                image = Image.open(io.BytesIO(content_bytes))
                content = pytesseract.image_to_string(image)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to process Image file (OCR): {str(e)}"
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
                        detail="Binary files are not supported. Please upload text, DOCX, PDF, or Image files."
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
        if result.get('ai_analysis'):
            import json
            db_scan.ai_analysis = json.dumps(result['ai_analysis'])
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

@router.post("/upload_video", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/60minute") # Stricter limit for heavy video processing
async def upload_video(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Upload and scan a video file for sensitive spoken data (Audio DLP).
    
    Process:
    1. Extract audio from video.
    2. Transcribe audio to text (OpenAI Whisper).
    3. Scan transcript for sensitive info.
    
    **Limit**: 25 MB per file.
    """
    if not file.filename.lower().endswith(('.mp4', '.mov', '.avi', '.mkv')):
        raise HTTPException(status_code=400, detail="Invalid video format. Use MP4, MOV, AVI, or MKV.")

    # 1. Save temp file
    import shutil
    import os
    from app.utils.video import VideoProcessor
    
    temp_filename = f"temp_{current_user.id}_{int(datetime.utcnow().timestamp())}_{file.filename}"
    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Check size (approx)
        if os.path.getsize(temp_filename) > 25 * 1024 * 1024:
            os.remove(temp_filename)
            raise HTTPException(status_code=413, detail="Video too large. Limit is 25MB.")
            
        # 1.5 File Guard (AV/YARA)
        if hasattr(request.app.state, 'file_guard') and request.app.state.file_guard:
            is_safe, findings = await request.app.state.file_guard.scan_file(temp_filename)
            if not is_safe:
                if os.path.exists(temp_filename):
                    os.remove(temp_filename)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Security Threat Detected: {', '.join(findings)}"
                )

        # 2. Process Video (Extract & Transcribe)
        transcription = await VideoProcessor.process_video(temp_filename)
        
        # Cleanup video immediately
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
            
        if "[Error" in transcription:
             raise HTTPException(status_code=500, detail=f"Video processing failed: {transcription}")

    except HTTPException:
        if os.path.exists(temp_filename): os.remove(temp_filename)
        raise
    except Exception as e:
        if os.path.exists(temp_filename): os.remove(temp_filename)
        raise HTTPException(status_code=500, detail=f"Upload error: {str(e)}")

    # 3. Create Scan Record using Transcript
    db_scan = DLPScan(
        user_id=current_user.id,
        source=f"VIDEO:{file.filename}",
        content=f"[TRANSCRIPT]\n{transcription}", 
        status=ScanStatus.SCANNING
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    try:
        # 4. Perform Scan on Transcript
        result = await dlp_engine.scan(transcription)
        
        db_scan.status = ScanStatus.COMPLETED
        db_scan.risk_level = result['risk_level']
        db_scan.findings = result['findings']
        db_scan.verdict = result['verdict']
        if result.get('ai_analysis'):
            import json
            db_scan.ai_analysis = json.dumps(result['ai_analysis'])
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
    
    if current_user.role.value != "admin":
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
    
    if current_user.role.value != "admin":
        query = query.filter(DLPScan.user_id == current_user.id)
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
    if current_user.role.value != "admin" and scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    return scan
