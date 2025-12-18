import pytest
from unittest.mock import MagicMock, patch
import sys

# Mock modules BEFORE importing app components
mock_yara_module = MagicMock()
mock_clamd_module = MagicMock()
sys.modules['yara'] = mock_yara_module
sys.modules['clamd'] = mock_clamd_module

from app.core.file_guard import FileGuard

@pytest.fixture
def mock_clamd():
    return mock_clamd_module

@pytest.fixture
def mock_yara():
    return mock_yara_module

@pytest.mark.asyncio
async def test_file_guard_init(mock_clamd, mock_yara):
    # Setup
    mock_clamd.ClamdNetworkSocket.return_value = MagicMock()
    mock_yara.compile.return_value = MagicMock()
    
    guard = FileGuard()
    assert guard._clamd_client is not None
    assert guard._yara_rules is not None

@pytest.mark.asyncio
async def test_scan_bytes_clean(mock_clamd, mock_yara):
    # Setup mocks for clean file
    client_mock = MagicMock()
    # clamd returns { 'stream': ('OK', None) }
    client_mock.instream.return_value = {'stream': ('OK', None)}
    mock_clamd.ClamdNetworkSocket.return_value = client_mock
    
    rules_mock = MagicMock()
    rules_mock.match.return_value = [] # No matches
    mock_yara.compile.return_value = rules_mock
    
    guard = FileGuard()
    is_safe, findings = await guard.scan_bytes(b"clean content")
    
    assert is_safe is True
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_scan_bytes_clamav_detected(mock_clamd, mock_yara):
    # Setup mocks for malware
    client_mock = MagicMock()
    # clamd returns { 'stream': ('FOUND', 'Eicar-Test-Signature') }
    client_mock.instream.return_value = {'stream': ('FOUND', 'Eicar-Test-Signature')}
    mock_clamd.ClamdNetworkSocket.return_value = client_mock
    
    rules_mock = MagicMock()
    rules_mock.match.return_value = []
    mock_yara.compile.return_value = rules_mock
    
    guard = FileGuard()
    is_safe, findings = await guard.scan_bytes(b"malicious content")
    
    assert is_safe is False
    assert "ClamAV: Eicar-Test-Signature" in findings

@pytest.mark.asyncio
async def test_scan_bytes_yara_detected(mock_clamd, mock_yara):
    # Setup mocks for yara match
    client_mock = MagicMock()
    client_mock.instream.return_value = {'stream': ('OK', None)}
    mock_clamd.ClamdNetworkSocket.return_value = client_mock
    
    rules_mock = MagicMock()
    match_mock = MagicMock()
    match_mock.rule = "Suspicious_PDF_Script"
    match_mock.tags = []
    rules_mock.match.return_value = [match_mock]
    mock_yara.compile.return_value = rules_mock
    
    guard = FileGuard()
    is_safe, findings = await guard.scan_bytes(b"suspicious content")
    
    assert is_safe is False
    assert "YARA: Suspicious_PDF_Script" in findings

@pytest.mark.asyncio
async def test_connection_failure_handling(mock_clamd, mock_yara):
    # Setup connection failure
    mock_clamd.ClamdNetworkSocket.side_effect = Exception("Connection refused")
    
    # Ensure YARA is clean for this test
    rules_mock = MagicMock()
    rules_mock.match.return_value = []
    mock_yara.compile.return_value = rules_mock
    
    guard = FileGuard()
    assert guard._clamd_client is None
    
    # scan should proceed (fail open for AV connection, or just skip AV)
    # The implementation logs error but proceeds.
    is_safe, findings = await guard.scan_bytes(b"content")
    assert is_safe is True # Assumes safe if AV scan skipped
