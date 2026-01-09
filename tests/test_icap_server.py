import pytest
import pytest_asyncio
import asyncio
import logging
from unittest.mock import MagicMock, patch
from app.icap_server import ICAPServer
from app.config import settings

# Configure Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- MOCKS ---
class MockDLPEngine:
    async def scan(self, content: str):
        # Simulate DLP Logic
        if "PII" in content or "BLOCK_ME" in content:
            return {
                "risk_level": "CRITICAL",
                "verdict": "BLOCK",
                "findings": [{"type": "mock_pii", "count": 1}]
            }
        return {
            "risk_level": "LOW",
            "verdict": "SAFE",
            "findings": []
        }

# --- FIXTURES ---
@pytest.fixture
def mock_dlp():
    with patch("app.icap_server.DLPEngine", return_value=MockDLPEngine()):
        yield

@pytest_asyncio.fixture
async def icap_server(mock_dlp):
    # Start on random port (0 lets OS pick, but we need to know it)
    # Using 13445 to avoid conflict
    host = "127.0.0.1"
    port = 13445
    
    server = ICAPServer(host=host, port=port)
    
    # Run in background task
    task = asyncio.create_task(server.start())
    
    # Wait for startup (simple sleep for now, or check connection)
    await asyncio.sleep(0.5) 
    
    yield (host, port)
    
    # Teardown
    await server.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

# --- HELPER CLIENT ---
async def send_icap_request(host, port, data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(data)
    await writer.drain()
    
    response = b""
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            if not chunk:
                break
            response += chunk
        except asyncio.TimeoutError:
            break
            
    writer.close()
    await writer.wait_closed()
    return response

# --- TESTS ---

@pytest.mark.asyncio
async def test_icap_options(icap_server):
    host, port = icap_server
    
    # OPTIONS request
    req = (
        f"OPTIONS icap://{host}:{port}/reqmod ICAP/1.0\r\n"
        "Host: localhost\r\n"
        "\r\n"
    ).encode()
    
    resp = await send_icap_request(host, port, req)
    assert b"ICAP/1.0 200 OK" in resp
    assert b"Methods: RESPMOD, REQMOD" in resp

@pytest.mark.asyncio
async def test_icap_auth_missing(icap_server):
    host, port = icap_server
    
    req = (
        f"REQMOD icap://{host}:{port}/reqmod ICAP/1.0\r\n"
        "Host: localhost\r\n"
        "Encapsulated: null-body=0\r\n"
        "\r\n"
    ).encode()
    
    resp = await send_icap_request(host, port, req)
    assert b"ICAP/1.0 401 Unauthorized" in resp

@pytest.mark.asyncio
async def test_icap_scan_safe(icap_server):
    host, port = icap_server
    
    # Generate a valid token (Mocking verifier is easier, but let's assume verifier is mocked)
    # Actually, verify_auth uses standard JWT decoding. 
    # Let's Patch verify_auth for simplicity in this integration test
    with patch.object(ICAPServer, 'verify_auth', return_value=True):
        
        # Simple body "Hello World"
        body = b"Hello World"
        # Calculate chunks: B\r\nHello World\r\n0\r\n\r\n
        enc_body = f"{hex(len(body))[2:]}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        
        req = (
            f"REQMOD icap://{host}:{port}/reqmod ICAP/1.0\r\n"
            "Host: localhost\r\n"
            "X-ICAP-Auth: test-token\r\n"
            "Encapsulated: req-body=0\r\n"
            "\r\n"
        ).encode() + enc_body
        
        resp = await send_icap_request(host, port, req)
        
        # Expect 204 No Modifications (Safe)
        assert b"ICAP/1.0 204" in resp

@pytest.mark.asyncio
async def test_icap_scan_block(icap_server):
    host, port = icap_server
    
    with patch.object(ICAPServer, 'verify_auth', return_value=True):
        
        # Body triggering mock "BLOCK_ME"
        body = b"This content contains BLOCK_ME pattern."
        enc_body = f"{hex(len(body))[2:]}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        
        req = (
            f"REQMOD icap://{host}:{port}/reqmod ICAP/1.0\r\n"
            "Host: localhost\r\n"
            "X-ICAP-Auth: valid-token\r\n"
            "Encapsulated: req-body=0\r\n"
            "\r\n"
        ).encode() + enc_body
        
        resp = await send_icap_request(host, port, req)
        
        # Expect 200 OK (Modified/Blocked Response)
        assert b"ICAP/1.0 200 OK" in resp
        assert b"Content Blocked by DLP" in resp
