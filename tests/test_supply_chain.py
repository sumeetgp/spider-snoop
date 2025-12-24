import pytest
import os
import zipfile
import json
import sys
from unittest.mock import MagicMock, patch

# --- MOCK SETUP START ---
# 1. Create the Mock for MCP Module
mock_mcp = MagicMock()
sys.modules["mcp"] = mock_mcp

# 2. Mock FastMCP specifically to handle the decorator
mock_fastmcp_module = MagicMock()
mock_fastmcp_class = MagicMock()
mock_fastmcp_instance = MagicMock()

# The key: @mcp.tool() returns a decorator. That decorator should just return the function.
mock_fastmcp_instance.tool.return_value = lambda f: f
mock_fastmcp_class.return_value = mock_fastmcp_instance

mock_fastmcp_module.FastMCP = mock_fastmcp_class
sys.modules["mcp.server.fastmcp"] = mock_fastmcp_module
sys.modules["mcp.server"] = MagicMock()

# 3. Mock heavy dependencies
sys.modules["oletools"] = MagicMock()
sys.modules["oletools.olevba"] = MagicMock()
sys.modules["pytesseract"] = MagicMock()
sys.modules["PIL"] = MagicMock()
# --- MOCK SETUP END ---

from mcp_server import scan_dependencies, scan_secrets_codebase

def test_scan_dependencies_pypi():
    """Test OSV scanning for Python requirements"""
    manifest = "requests==2.20.0" # Known vulnerable version
    
    # Mock requests.post to avoid hitting real OSV API in CI/CD (though here we might want to hit it)
    # But for comprehensive testing, let's allow it if network is available, or mock if we want stability.
    # Let's mock it to ensure deterministic output for this example.
    
    mock_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "PYSEC-2018-0001",
                        "summary": "Vulnerability in requests",
                        "details": "Details about vuln...",
                        "affected": [{"ranges": [{"events": [{"fixed": "2.21.0"}]}]}]
                    }
                ]
            }
        ]
    }
    
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = mock_response
        
        result = scan_dependencies(manifest, ecosystem="PyPI")
        
        assert "SUPPLY CHAIN VULNERABILITIES" in result
        assert "requests @ 2.20.0" in result
        assert "PYSEC-2018-0001" in result
        assert "Fixed in: 2.21.0" in result

def test_scan_secrets_codebase_zip():
    """Test TruffleHog-style scanning on a Zip file"""
    # Create a dummy zip with a secret
    zip_name = "test_secrets.zip"
    with zipfile.ZipFile(zip_name, 'w') as zf:
        zf.writestr("config.py", "AWS_KEY = 'AKIA1234567890123456'")
        zf.writestr("safe.txt", "Nothing to see here")
        
    try:
        # Mock matcher since it's global in mcp_server
        # But mcp_server imports DLPPatternMatcher. 
        # mcp_server.matcher is initialized at module level.
        # We can rely on the real matcher if it works, or mock it.
        # The real matcher is robust, let's try it.
        
        result = scan_secrets_codebase(zip_name)
        
        # Check output
        assert "CODEBASE SECRETS DETECTED" in result
        # DLPPatternMatcher likely names it 'aws_access_key' or 'aws_key' depending on regex
        # The failure showed: [CRITICAL] aws_access_key found in config.py
        assert "aws_access_key found in config.py" in result
        assert "AKIA1234567890123456" in result
        
    finally:
        if os.path.exists(zip_name):
            os.remove(zip_name)
