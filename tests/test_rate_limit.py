import pytest
import time
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import UserRole
from app.utils.auth import create_access_token
from app.utils import limiter
# Import the module where get_rate_limit_value is defined so we can patch it
from app.utils import limiter as limiter_module
from app.database import get_db
from app.utils.auth import get_current_active_user
from unittest.mock import MagicMock

# Mock User class
class MockUser:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.id = 1
        self.is_active = True

# Mock DB Session
from datetime import datetime
from unittest.mock import patch

from datetime import datetime
from unittest.mock import patch
from app.models.scan import ScanStatus, RiskLevel

# Mock DB Session with refresh logic
def override_get_db():
    try:
        db = MagicMock()
        db.add = MagicMock()
        db.commit = MagicMock()
        
        def fake_refresh(obj):
            obj.id = 123
            obj.created_at = datetime.utcnow()
            obj.owner_id = 1
            if not hasattr(obj, 'source'): obj.source = "API"
            if not hasattr(obj, 'findings'): obj.findings = []
            if not hasattr(obj, 'risk_level'): obj.risk_level = RiskLevel.LOW
            if not hasattr(obj, 'status'): obj.status = ScanStatus.COMPLETED
            if not hasattr(obj, 'verdict'): obj.verdict = "Safe"
            if not hasattr(obj, 'scan_duration_ms'): obj.scan_duration_ms = 10
            if not hasattr(obj, 'completed_at'): obj.completed_at = datetime.utcnow()
        
        db.refresh.side_effect = fake_refresh
        yield db
    finally:
        pass

# Mock DLP Engine functionality to avoid OpenAI calls and validation errors
@pytest.fixture(autouse=True)
def mock_dlp_engine():
    with patch("app.routes.scans.dlp_engine.scan") as mock_scan:
        mock_scan.return_value = {
            "risk_level": "LOW",
            "findings": [],
            "verdict": "Safe",
            "ai_analysis": None,
            "scan_duration_ms": 10
        }
        yield mock_scan

client = TestClient(app)

def get_test_token(username: str, role: UserRole):
    return create_access_token(data={"sub": username, "role": role.value})


@pytest.fixture(autouse=True)
def setup_dependencies():
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_active_user] = None
    yield
    app.dependency_overrides = {}

@pytest.fixture(autouse=True)
def clear_limiters():
    # Attempt to clear limiter storage between tests for in-memory backend
    # slowapi Limiter stores data in limiter._storage usually
    # For in-memory, it's a list/dict.
    # We can try to reset it if accessible.
    try:
        if hasattr(app.state, 'limiter'):
             # This is hacky but needed for in-memory reset
             app.state.limiter.reset()
    except:
        pass


def test_rate_limit_analyst():
    # Setup mock user
    user = MockUser("rate_limit_analyst", UserRole.ANALYST)
    app.dependency_overrides[get_current_active_user] = lambda: user
    
    token = get_test_token("rate_limit_analyst", UserRole.ANALYST)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Send 50 requests (Allowed)
    for i in range(50):
        res = client.post("/api/scans/", json={"source": "test", "content": "test"}, headers=headers)
        if res.status_code != 201:
             pytest.fail(f"Request {i+1} failed with {res.status_code}: {res.text}")
    
    # Request 51: Should look blocked?
    # Actually, default implementation might allow burst? 
    # But "50/60minute" usually means fixed window or moving window. 
    # 51st should fail.
    
    res = client.post("/api/scans/", json={"source": "test", "content": "test"}, headers=headers)
    assert res.status_code == 429
    assert "Rate limit exceeded" in res.text

def test_rate_limit_admin():
    # Setup mock user
    user = MockUser("rate_limit_admin", UserRole.ADMIN)
    app.dependency_overrides[get_current_active_user] = lambda: user
    
    token = get_test_token("rate_limit_admin", UserRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Admin should bypass the limit (10000/minute)
    # Testing 55 is enough to prove it exceeds the 50 limit of normal users
    for i in range(55):
        res = client.post("/api/scans/", json={"source": "test", "content": "test"}, headers=headers)
        assert res.status_code == 201

