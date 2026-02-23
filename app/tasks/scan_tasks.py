import json
import logging
from datetime import datetime
from celery.exceptions import SoftTimeLimitExceeded
import traceback

from app.worker import celery_app
from app.database import SessionLocal
from app.models.scan import DLPScan, ScanStatus, RiskLevel
from app.utils.storage import StorageManager

logger = logging.getLogger(__name__)

# Initialize DO Spaces manager
storage_manager = StorageManager()

# Soft timeout at 5 minutes exactly, Hard kill at 5 mins + 10s
@celery_app.task(bind=True, soft_time_limit=300, time_limit=310, max_retries=1)
def process_async_scan(self, scan_id: int, file_url: str):
    """
    Background worker that runs the full scan lifecycle decoupled from the API request.
    Handles Large Files via DigitalOcean Spaces URL retrieval.
    """
    db = SessionLocal()
    scan = db.query(DLPScan).filter(DLPScan.id == scan_id).first()
    
    if not scan:
        logger.error(f"Async Scan Failed: Scan ID {scan_id} not found in DB.")
        db.close()
        return

    try:
        # Phase 1: UPLOADED -> MALWARE_SCANNING (Downloading from DO Spaces)
        scan.status = ScanStatus.MALWARE_SCANNING
        db.commit()
        
        # FUTURE: Implement secure download stream from `file_url` into temp buffer
        # FUTURE: Stream directly to ClamAV without writing huge files to disk
        
        # Phase 2: MALWARE -> EXTRACTING
        scan.status = ScanStatus.EXTRACTING
        db.commit()
        
        # FUTURE: Trigger Tesseract OCR or Whisper AI if media file
        
        # Phase 3: EXTRACTING -> CONTENT_SCANNING (DLP)
        scan.status = ScanStatus.CONTENT_SCANNING
        db.commit()
        
        # FUTURE: Run Presidio NLP engine
        
        # Phase 4: CONTENT_SCANNING -> AI_ANALYSIS
        scan.status = ScanStatus.AI_ANALYSIS
        db.commit()
        
        # FUTURE: Feed results into LocalML Zero-Shot classifier
        
        # Phase 5: AI_ANALYSIS -> POLICY_EVAL
        scan.status = ScanStatus.POLICY_EVAL
        db.commit()
        
        # FUTURE: Synthesize JSON
        
        # Finalization
        scan.status = ScanStatus.COMPLETED
        scan.verdict = "Offline Scan Mock Finished"
        scan.threat_score = 15
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        logger.info(f"Async Scan ID {scan_id} Completed Successfully.")

    except SoftTimeLimitExceeded:
        # User defined 5-minute timeout reached.
        logger.error(f"Task Time Out! Async Scan ID {scan_id} exceeded 5 mins.")
        scan.status = ScanStatus.FAILED
        scan.verdict = "FAILED: Timeout exceeded 5 minutes"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        logger.error(f"Async Scan Error: {e}")
        scan.status = ScanStatus.FAILED
        scan.verdict = f"FAILED: System Error ({str(e)})"
        scan.completed_at = datetime.utcnow()
        db.commit()

    finally:
        # ALWAYS delete the ephemeral heavy file from remote DigitalOcean space
        storage_manager.delete_file(file_url)
        db.close()
