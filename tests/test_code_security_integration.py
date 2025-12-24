import sys
from unittest.mock import MagicMock

# Mock MCP for App Startup
mock_mcp = MagicMock()
mock_mcp.tool.return_value = lambda f: f
sys.modules["mcp"] = mock_mcp
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.server.fastmcp"] = MagicMock()
# Mock oletools just in case
sys.modules["oletools"] = MagicMock()
sys.modules["oletools.olevba"] = MagicMock()
sys.modules["pytesseract"] = MagicMock()
sys.modules["PIL"] = MagicMock()

from fastapi.testclient import TestClient
from app.main import app

def test_code_security_route():
    client = TestClient(app)
    # Check if router is mounted (GET /security)
    response = client.get("/security")
    assert response.status_code == 200
    assert "Code Security" in response.text
