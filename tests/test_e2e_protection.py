import os
import shutil
import pytest
from app.routes import scans
from app.cdr_engine import CDREngine

# Mocking
import sys
from unittest.mock import MagicMock, AsyncMock

# Mock boto3 before it is imported by app.utils.storage
sys.modules["boto3"] = MagicMock()
sys.modules["yara"] = MagicMock()
sys.modules["clamd"] = MagicMock()

import asyncio

@pytest.fixture
def mock_upload_file():
    from fastapi import UploadFile
    return UploadFile

@pytest.fixture
def mock_storage():
    mock = MagicMock()
    mock.upload_file = AsyncMock(return_value="https://bucket.com/safe/file.docx")
    return mock

@pytest.mark.asyncio
async def test_e2e_protection_flow_malware(mock_storage, monkeypatch):
    # Import auth FIRST to ensure it initializes before main/routes try to use it
    from app.utils import auth
    # Import main after
    from app.main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    
    get_current_active_user = auth.get_current_active_user
    # Mock Deps
    mock_db = MagicMock()
    
    def refresh_side_effect(obj):
        obj.id = 123
        from datetime import datetime
        if not getattr(obj, 'created_at', None): obj.created_at = datetime.utcnow()
        if not getattr(obj, 'completed_at', None): obj.completed_at = datetime.utcnow()
        
    mock_db.refresh.side_effect = refresh_side_effect
    
    mock_user = MagicMock()
    mock_user.id = 1
    mock_user.credits_remaining = 50
    mock_user.role.value = "user"
    
    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_active_user] = lambda: mock_user

    # Mock FileGuard in app.state
    mock_file_guard = MagicMock()
    mock_file_guard.scan_file = AsyncMock(return_value=(False, ["ClamAV: Eicar-Test-Signature"]))
    app.state.file_guard = mock_file_guard

    # Mock CDREngine
    mock_cdr_instance = MagicMock()
    mock_cdr_instance.disarm.return_value = True
    monkeypatch.setattr("app.cdr_engine.CDREngine", lambda: mock_cdr_instance)
    
    # Mock Storage
    monkeypatch.setattr("app.utils.storage.StorageManager", lambda: mock_storage)

    # Mock Rate Limiter? (Passes through if we use TestClient generally, 
    # but we might need to mock slowapi if it's strict on memory storage)
    # Usually TestClient works fine with slowapi defaults.

    client = TestClient(app)
    
    # Create dummy file
    with open("test.docx", "wb") as f: f.write(b"dummy malware content")
    try:
        with open("test.docx", "rb") as f:
            response = client.post(
                "/api/scans/upload_file?track=sentinel",
                files={"file": ("test.docx", f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
            )
        
        # Assertions
        assert response.status_code == 201
        result = response.json()
        
        # Verdict should be MALWARE
        assert result['verdict'] == "MALWARE DETECTED"
        assert result['risk_level'] == "critical"
        
        # CDR should have run
        assert result['cdr_info'] is not None
        assert result['cdr_info']['status'] == "success"
        assert result['cdr_info']['url'] == "https://bucket.com/safe/file.docx"

    finally:
        if os.path.exists("test.docx"): os.remove("test.docx")
        app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_e2e_protection_flow_safe(mock_storage, monkeypatch):
    """
    Test that uploading a SAFE file DOES NOT trigger CDR.
    """
    # Import auth FIRST
    from app.utils import auth
    from app.main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    
    get_current_active_user = auth.get_current_active_user
    # Mock Deps
    mock_db = MagicMock()
    
    def refresh_side_effect(obj):
        obj.id = 124
        from datetime import datetime
        if not getattr(obj, 'created_at', None): obj.created_at = datetime.utcnow()
        if not getattr(obj, 'completed_at', None): obj.completed_at = datetime.utcnow()
        
    mock_db.refresh.side_effect = refresh_side_effect
    
    mock_user = MagicMock()
    mock_user.id = 1
    mock_user.credits_remaining = 50
    mock_user.role.value = "user"

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_active_user] = lambda: mock_user

    # Mock FileGuard - SAFE this time
    mock_file_guard = MagicMock()
    mock_file_guard.scan_file = AsyncMock(return_value=(True, []))
    app.state.file_guard = mock_file_guard

    # Mock CDREngine - Should NOT be called
    mock_cdr_instance = MagicMock()
    monkeypatch.setattr("app.cdr_engine.CDREngine", lambda: mock_cdr_instance)
    
    monkeypatch.setattr("app.utils.storage.StorageManager", lambda: mock_storage)

    client = TestClient(app)
    
    with open("safe.docx", "wb") as f: f.write(b"safe content")
    try:
        with open("safe.docx", "rb") as f:
            response = client.post(
                "/api/scans/upload_file?track=sentinel",
                files={"file": ("safe.docx", f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
            )
        
        assert response.status_code == 201
        result = response.json()
        
        # Verdict SAFE
        assert result['verdict'] == "SAFE"
        assert result['risk_level'] == "low"
        
        # CDR should NOT be present
        assert result['cdr_info'] is None
        # Verify disarm was NOT called
        mock_cdr_instance.disarm.assert_not_called()

    finally:
        if os.path.exists("safe.docx"): os.remove("safe.docx")
        app.dependency_overrides.clear()
