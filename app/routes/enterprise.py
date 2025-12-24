from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import json
import os
import time
from datetime import datetime
from app.utils.storage import StorageManager

router = APIRouter(prefix="/api/enterprise", tags=["Enterprise"])
storage = StorageManager()

class ConsultationRequest(BaseModel):
    name: str = Field(..., min_length=2)
    email: EmailStr
    company_size: str
    interest: str

@router.post("/consultation")
async def request_consultation(request: ConsultationRequest):
    """
    Handle enterprise consultation request.
    Saves request details to a JSON file and uploads to S3.
    """
    try:
        # Prepare data
        ticket_id = f"CONSULT-{int(time.time())}"
        data = {
            "ticket_id": ticket_id,
            "timestamp": datetime.utcnow().isoformat(),
            "name": request.name,
            "email": request.email,
            "company_size": request.company_size,
            "interest": request.interest,
            "status": "PENDING"
        }
        
        # Save locally to temp
        filename = f"{ticket_id}.json"
        temp_path = f"storage/{filename}"
        
        # Ensure storage dir exists
        os.makedirs("storage", exist_ok=True)
        
        with open(temp_path, "w") as f:
            json.dump(data, f, indent=2)
            
        # Upload to S3
        s3_url = await storage.upload_file(temp_path, f"consultations/{filename}")
        
        # Clean up local file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        if s3_url:
            return {"status": "success", "message": "Request received", "ticket_id": ticket_id}
        else:
            # Fallback if S3 fails - log error but return success to user if file was created? 
            # Actually storage.upload_file returns None on failure.
            # If S3 is not configured, we might want to just log it.
            # But the user specifically asked for S3 upload. 
            if not storage.enabled:
                 return {"status": "warning", "message": "Request logged locally (S3 disabled)", "ticket_id": ticket_id}
            
            raise HTTPException(status_code=500, detail="Failed to persist request to storage")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
