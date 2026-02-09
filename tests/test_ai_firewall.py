
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from app.main import app
from app.models.user import User, UserRole
from app.utils.auth import get_current_active_user
from app.database import get_db

# Mock User
def mock_get_current_active_user():
    return User(id=1, username="testadmin", role=UserRole.ADMIN, email="admin@example.com")

def mock_get_analyst_user():
    return User(id=2, username="testanalyst", role=UserRole.ANALYST, email="analyst@example.com")

# Mock DB
def mock_get_db():
    try:
        yield MagicMock()
    finally:
        pass

# Override Dependency
app.dependency_overrides[get_db] = mock_get_db
app.dependency_overrides[get_current_active_user] = mock_get_current_active_user

client = TestClient(app)

@pytest.fixture
def mock_httpx_client():
    with patch("app.routes.proxy.httpx.AsyncClient") as mock_client:
        yield mock_client

@pytest.fixture
def mock_dlp_engine():
    with patch("app.routes.proxy.get_dlp_engine") as mock_engine_getter:
        mock_engine = AsyncMock()
        mock_engine_getter.return_value = mock_engine
        # Setup pattern matcher mock for redaction
        mock_engine.pattern_matcher = MagicMock()
        mock_engine.pattern_matcher.redact.return_value = "[REDACTED]"
        yield mock_engine

@pytest.mark.asyncio
async def test_proxy_passthrough_allowed(mock_httpx_client, mock_dlp_engine):
    """
    Scenario: Admin User sends safe content.
    Expectation: 
    1. OPA allows (Admin).
    2. DLP returns LOW risk.
    3. Proxy forwards to OpenAI.
    4. Returns 200 OK.
    """
    
    # Mock OPA: Allow
    mock_opa_response = MagicMock()
    mock_opa_response.status_code = 200
    mock_opa_response.json.return_value = {"result": True}
    
    # Mock OpenAI: Success
    mock_openai_response = MagicMock()
    mock_openai_response.status_code = 200
    mock_openai_response.content = b'{"id": "chatcmpl-123", "choices": []}'
    mock_openai_response.headers = {"Content-Type": "application/json"}
    
    # Setup AsyncClient Context Manager Mock
    mock_instance = mock_httpx_client.return_value.__aenter__.return_value
    # Side effects for sequential calls: 1. OPA, 2. OpenAI
    mock_instance.post.return_value = mock_opa_response
    mock_instance.request.return_value = mock_openai_response
    
    # Mock DLP: Safe
    mock_dlp_engine.scan.return_value = {"risk_level": "LOW", "findings": []}
    
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello, how are you?"}]
    }
    
    response = client.post("/v1/proxy/chat/completions", json=payload)
    
    assert response.status_code == 200
    assert response.json() == {"id": "chatcmpl-123", "choices": []}
    
    # Verify DLP Scan called
    mock_dlp_engine.scan.assert_awaited_with("Hello, how are you?")


@pytest.mark.asyncio
async def test_proxy_opa_blocked(mock_httpx_client):
    """
    Scenario: User role denied by OPA.
    Expectation: 403 Forbidden.
    """
    # Mock OPA: Deny
    mock_opa_response = MagicMock()
    mock_opa_response.status_code = 200
    mock_opa_response.json.return_value = {"result": False}
    
    mock_instance = mock_httpx_client.return_value.__aenter__.return_value
    mock_instance.post.return_value = mock_opa_response
    
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    }
    
    response = client.post("/v1/proxy/chat/completions", json=payload)
    
    assert response.status_code == 403
    assert "OPA BLOCK" in response.json()["detail"]


@pytest.mark.asyncio
async def test_proxy_dlp_blocked(mock_httpx_client, mock_dlp_engine):
    """
    Scenario: Request contains CRITICAL secrets.
    Expectation: 400 Bad Request (Blocked).
    """
    # Mock OPA: Allow
    mock_opa_response = MagicMock()
    mock_opa_response.status_code = 200
    mock_opa_response.json.return_value = {"result": True}
    
    mock_instance = mock_httpx_client.return_value.__aenter__.return_value
    mock_instance.post.return_value = mock_opa_response
    
    # Mock DLP: Critical
    mock_dlp_engine.scan.return_value = {
        "risk_level": "CRITICAL", 
        "findings": [{"type": "AWS_KEY"}]
    }
    
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Here is my AKIA..."}]
    }
    
    response = client.post("/v1/proxy/chat/completions", json=payload)
    
    assert response.status_code == 400
    assert "DLP BLOCK" in response.json()["detail"]


@pytest.mark.asyncio
async def test_proxy_dlp_redacted(mock_httpx_client, mock_dlp_engine):
    """
    Scenario: Request contains PII (Medium Risk).
    Expectation: 
    1. Content is Redacted.
    2. Proxy forwards redacted content to OpenAI.
    3. Returns 200 OK.
    """
    # Mock OPA: Allow
    mock_opa_response = MagicMock()
    mock_opa_response.status_code = 200
    mock_opa_response.json.return_value = {"result": True}
    
    # Mock OpenAI: Success
    mock_openai_response = MagicMock()
    mock_openai_response.status_code = 200
    mock_openai_response.content = b'{}'
    mock_openai_response.headers = {}
    
    mock_instance = mock_httpx_client.return_value.__aenter__.return_value
    mock_instance.post.return_value = mock_opa_response
    mock_instance.request.return_value = mock_openai_response
    
    # Mock DLP: High/Medium -> Redact
    mock_dlp_engine.scan.return_value = {
        "risk_level": "HIGH", 
        "findings": [{"type": "EMAIL"}]
    }
    
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Contact me at bob@email.com"}]
    }
    
    response = client.post("/v1/proxy/chat/completions", json=payload)
    
    assert response.status_code == 200
    
    # Verify Redaction Logic
    # We check that the 'request' call to upstream used the redacted content
    call_args = mock_instance.request.call_args
    # call_args[1] is kwargs
    sent_content = call_args[1]['content']
    import json
    sent_json = json.loads(sent_content)
    
    assert sent_json['messages'][0]['content'] == "[REDACTED]"
    mock_dlp_engine.pattern_matcher.redact.assert_called()
