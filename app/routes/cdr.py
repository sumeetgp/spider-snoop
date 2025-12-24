from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from app.cdr_engine import CDREngine
import shutil
import tempfile
import os
from pathlib import Path
from app.utils.auth import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/api/cdr", tags=["cdr"])
cdr_engine = CDREngine()

@router.post("/sanitize", response_class=FileResponse)
async def sanitize_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user)
):
    """
    Sanitize a file by removing active content.
    Returns the sanitized file.
    """
    # Create temp directory
    tmp_dir = tempfile.mkdtemp()
    try:
        # Save uploaded file
        input_path = os.path.join(tmp_dir, file.filename)
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Determine output path
        filename_base, ext = os.path.splitext(file.filename)
        
        # For reconstructed Word docs, we might change extension slightly or keep same
        # But our engine handles it.
        output_filename = f"safe_{filename_base}{ext}"
        output_path = os.path.join(tmp_dir, output_filename)
        
        # Disarm
        success = cdr_engine.disarm(input_path, output_path)
        
        if not success:
            raise HTTPException(status_code=422, detail="Could not sanitize file or format unsupported.")
        
        if not os.path.exists(output_path):
             raise HTTPException(status_code=500, detail="Sanitization failed to produce output.")

        # Return file (background task to cleanup?)
        # For simplicity in this turn, we return FileResponse which handles cleaning up open handles,
        # but the temp dir might persist. We should use BackgroundTasks to clean up.
        from starlette.background import BackgroundTasks
        
        def cleanup():
            shutil.rmtree(tmp_dir, ignore_errors=True)
            
        return FileResponse(output_path, filename=output_filename, background=BackgroundTasks([cleanup]))

    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))
