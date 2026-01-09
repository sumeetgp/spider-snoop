import pytest
import os
import sys
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models.user import User, UserRole
from app.utils.auth import get_password_hash
from app.routes.scans import get_dlp_engine

# --- TEST DB SETUP ---
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=engine)

def seed_users():
    db = TestingSessionLocal()
    if not db.query(User).filter(User.username == "admin_test").first():
        admin = User(
            username="admin_test",
            email="admin@test.com",
            hashed_password=get_password_hash("test"),
            role=UserRole.ADMIN,
            is_active=True,
            credits_remaining=100
        )
        db.add(admin)
    
    if not db.query(User).filter(User.username == "viewer_test").first():
        viewer = User(
            username="viewer_test",
            email="viewer@test.com",
            hashed_password=get_password_hash("test"),
            role=UserRole.VIEWER,
            is_active=True,
            credits_remaining=10
        )
        db.add(viewer)
    db.commit()
    db.close()

seed_users()

app.dependency_overrides[get_db] = override_get_db

# --- MOCK ENGINE ---
class MockDLPEngine:
    def __init__(self):
        self.mcp_session = None
        
    async def scan(self, content, file_path=None, use_ai=False):
        findings = []
        risk_level = "LOW"
        verdict = "SAFE"
        ai_analysis = {"score": 0, "reason": "Safe"}
        
        content_str = str(content)
        fpath_str = str(file_path) if file_path else ""
        
        # 1. Secrets
        if "API_KEY" in content_str or "AWS" in content_str:
            risk_level = "HIGH"
            verdict = "SECRETS DETECTED"
            findings.append({"type": "secret", "severity": "HIGH", "detail": "AWS Access Key"})
            ai_analysis["score"] = 85
            ai_analysis["reason"] = "Found Secrets [SOC2]"
            
        # 2. PII / HIPAA / Compliance
        elif "Credit Card" in content_str or "SSN" in content_str or "4111" in content_str:
            risk_level = "HIGH"
            verdict = "PII DETECTED"
            findings.append({"type": "pii", "severity": "HIGH", "detail": "Credit Card Number"})
            ai_analysis["score"] = 80
            ai_analysis["reason"] = "Financial PII [PCI-DSS]"
            
        elif "Medical Record" in content_str or "MRN" in content_str:
            risk_level = "CRITICAL"
            verdict = "COMPLIANCE VIOLATION"
            findings.append({"type": "medical_record", "severity": "CRITICAL", "detail": "Medical Record Number"})
            ai_analysis["score"] = 95
            ai_analysis["reason"] = "Detected Protected Health Information (PHI) [HIPAA]"
            ai_analysis["compliance_alerts"] = ["HIPAA"]
            
        # 3. Malware
        elif "EICAR" in content_str or "Virus" in content_str or "eicar" in fpath_str:
            risk_level = "CRITICAL"
            verdict = "MALWARE DETECTED"
            findings.append({"type": "malware", "severity": "CRITICAL", "detail": "EICAR Test File"})
            ai_analysis["score"] = 100
            ai_analysis["reason"] = "Malware Signature"
            
        return {
            "risk_level": risk_level,
            "findings": findings,
            "verdict": verdict,
            "scan_duration_ms": 15,
            "ai_analysis": ai_analysis
        }

    async def scan_macros(self, file_path):
        if "active_macro" in str(file_path):
            return "Found suspicious VBA macro (Mock)"
        return None

@pytest.fixture(autouse=True)
def override_dlp_engine_fixture():
    mock_engine = MockDLPEngine()
    app.dependency_overrides[get_dlp_engine] = lambda: mock_engine
    yield

@pytest.fixture
def client():
    return TestClient(app)

from app.utils.auth import create_access_token

@pytest.fixture
def h_admin():
    token = create_access_token(data={"sub": "admin_test", "role": UserRole.ADMIN})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def h_viewer():
    token = create_access_token(data={"sub": "viewer_test", "role": UserRole.VIEWER})
    return {"Authorization": f"Bearer {token}"}

# Test Data Paths
DATA_DIR = "test_data"
DLP_TXT = f"{DATA_DIR}/dlp_pii.txt"
DLP_PNG = f"{DATA_DIR}/dlp_pii.png"
EICAR_TXT = f"{DATA_DIR}/eicar_test.txt"
HIPAA_TXT = f"{DATA_DIR}/compliance_hipaa.txt"

# --- TESTS ---
def test_dlp_text_scan(client, h_admin):
    if not os.path.exists(DLP_TXT): pytest.skip("No data")
    with open(DLP_TXT, "rb") as f:
        files = {"file": ("dlp_pii.txt", f, "text/plain")}
        response = client.post("/api/scans/upload_file", headers=h_admin, files=files, params={"track": "guardian"})
    assert response.status_code == 201
    assert response.json()["risk_level"].upper() in ["HIGH", "CRITICAL"]

def test_dlp_image_ocr(client, h_admin):
    if not os.path.exists(DLP_PNG): pytest.skip("No data")
    
    # Mock libraries in sys.modules
    mock_tess = MagicMock()
    mock_tess.image_to_string.return_value = "User Screenshot. Credit Card: 4111 2222 3333 4444"
    mock_pil = MagicMock()
    mock_pil.Image.open.return_value = MagicMock()
    
    with patch.dict("sys.modules", {"pytesseract": mock_tess, "PIL": mock_pil}):
        with open(DLP_PNG, "rb") as f:
            files = {"file": ("dlp_pii.png", f, "image/png")}
            response = client.post("/api/scans/upload_file", headers=h_admin, files=files, params={"track": "guardian"})
            
    assert response.status_code == 201
    assert response.json()["risk_level"].upper() == "HIGH"
    assert "Credit Card" in str(response.json()["findings"])

def test_compliance_hipaa(client, h_admin):
    """Test HIPAA Compliance Detection (PHI)"""
    if not os.path.exists(HIPAA_TXT): pytest.skip("No data")
    
    with open(HIPAA_TXT, "rb") as f:
        files = {"file": ("compliance_hipaa.txt", f, "text/plain")}
        response = client.post("/api/scans/upload_file", headers=h_admin, files=files, params={"track": "guardian"})
    
    assert response.status_code == 201
    data = response.json()
    
    # 1. Check Risk Level
    assert data["risk_level"].upper() == "CRITICAL"
    
    # 2. Check Finding Type (simulating Regex)
    findings_str = str(data["findings"])
    assert "medical_record" in findings_str
    
    # 3. Check Compliance Tag in Reason/Analysis (simulating AI)
    # The API might flatten this or put it in ai_analysis depending on schema
    ai_analysis = data.get("ai_analysis", {})
    if isinstance(ai_analysis, str):
        # Handle stringified JSON case if app does that
        import json
        try:
            ai_analysis = json.loads(ai_analysis)
        except:
             ai_analysis = {"reason": ai_analysis}
             
    # Check for [HIPAA] in reason OR explicit alerts
    reason = ai_analysis.get("reason", "")
    alerts = ai_analysis.get("compliance_alerts", [])
    
    assert "[HIPAA]" in reason or "HIPAA" in alerts or "HIPAA" in str(data["verdict"])

def test_malware_detection(client, h_admin):
    if not os.path.exists(EICAR_TXT): pytest.skip("No data")
    with open(EICAR_TXT, "rb") as f:
        files = {"file": ("eicar.txt", f, "text/plain")}
        response = client.post("/api/scans/upload_file", headers=h_admin, files=files, params={"track": "sentinel"})
    
    if response.status_code == 400:
        assert "Threat" in response.json().get("detail", "")
    elif response.status_code == 201:
        assert response.json()["risk_level"].upper() == "CRITICAL"

def test_rbac_user_list(client, h_viewer, h_admin):
    res1 = client.get("/api/users/", headers=h_admin)
    assert res1.status_code == 200
    res2 = client.get("/api/users/", headers=h_viewer)
    assert res2.status_code == 403
