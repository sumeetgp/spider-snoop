"""ICAP Protocol Server Implementation"""
import asyncio
import logging
from typing import Optional
from datetime import datetime
from app.config import settings
from app.dlp_engine import DLPEngine

logger = logging.getLogger(__name__)

class ICAPServer:
    """ICAP Protocol Server for DLP scanning"""
    
    def __init__(self, host: str = None, port: int = None):
        self.host = host or settings.ICAP_HOST
        self.port = port or settings.ICAP_PORT
        self.dlp_engine = DLPEngine()
        self.server = None
        
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle ICAP client request"""
        try:
            # Read ICAP request
            request_line = await reader.readline()
            request_str = request_line.decode('utf-8').strip()
            
            logger.info(f"ICAP Request: {request_str}")
            
            # Parse ICAP request
            method, uri, version = request_str.split()
            
            # Read headers
            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                if line:
                    key, value = line.decode('utf-8').strip().split(':', 1)
                    headers[key.strip()] = value.strip()
            
            if method == "RESPMOD":
                # Response modification - scan content
                response = await self.handle_respmod(reader, headers)
                writer.write(response)
            elif method == "REQMOD":
                # Request modification - scan content
                response = await self.handle_reqmod(reader, headers)
                writer.write(response)
            elif method == "OPTIONS":
                # OPTIONS request
                response = self.handle_options()
                writer.write(response)
            else:
                # Unsupported method
                response = self.error_response(405, "Method Not Allowed")
                writer.write(response)
            
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Error handling ICAP request: {e}")
            writer.write(self.error_response(500, "Internal Server Error"))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_respmod(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        """Handle RESPMOD request (response modification)"""
        # Read the encapsulated HTTP response
        content = await self.read_encapsulated_content(reader, headers)
        
        # Scan with DLP engine
        start_time = datetime.utcnow()
        scan_result = await self.dlp_engine.scan(content.decode('utf-8', errors='ignore'))
        scan_duration = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        logger.info(f"Scan completed in {scan_duration}ms - Verdict: {scan_result['verdict']}")
        
        # If content is blocked, return modified response
        if scan_result['risk_level'] in ['HIGH', 'CRITICAL']:
            return self.blocked_response(scan_result)
        
        # Otherwise, return 204 No Modifications Needed
        return self.no_modification_response()
    
    async def handle_reqmod(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        """Handle REQMOD request (request modification)"""
        # Similar to RESPMOD but for requests
        content = await self.read_encapsulated_content(reader, headers)
        
        # Scan with DLP engine
        scan_result = await self.dlp_engine.scan(content.decode('utf-8', errors='ignore'))
        
        # If content is blocked, return modified response
        if scan_result['risk_level'] in ['HIGH', 'CRITICAL']:
            return self.blocked_response(scan_result)
        
        return self.no_modification_response()
    
    def handle_options(self) -> bytes:
        """Handle OPTIONS request"""
        response = [
            "ICAP/1.0 200 OK",
            f"Service: {settings.ICAP_SERVICE_NAME}",
            "ISTag: \"spider-snoop-1.0\"",
            "Methods: RESPMOD, REQMOD",
            "Allow: 204",
            "Preview: 0",
            "Transfer-Preview: *",
            "Max-Connections: 100",
            "Options-TTL: 3600",
            "Date: " + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Encapsulated: null-body=0",
            "\r\n"
        ]
        return "\r\n".join(response).encode('utf-8')
    
    def no_modification_response(self) -> bytes:
        """Return 204 No Modifications Needed"""
        response = [
            "ICAP/1.0 204 No Modifications Needed",
            "Date: " + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "ISTag: \"spider-snoop-1.0\"",
            "\r\n"
        ]
        return "\r\n".join(response).encode('utf-8')
    
    def blocked_response(self, scan_result: dict) -> bytes:
        """Return blocked content response"""
        blocked_html = f"""
        <html>
        <head><title>Content Blocked</title></head>
        <body>
            <h1>Content Blocked by DLP</h1>
            <p>This content has been blocked due to policy violations.</p>
            <p><strong>Risk Level:</strong> {scan_result['risk_level']}</p>
            <p><strong>Reason:</strong> {scan_result['verdict']}</p>
        </body>
        </html>
        """
        
        http_response = [
            "HTTP/1.1 403 Forbidden",
            "Content-Type: text/html",
            f"Content-Length: {len(blocked_html)}",
            "Connection: close",
            "",
            blocked_html
        ]
        http_response_str = "\r\n".join(http_response)
        
        header_len = len(http_response_str.split('\r\n\r\n')[0]) + 4
        icap_response = [
            "ICAP/1.0 200 OK",
            "Date: " + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "ISTag: \"spider-snoop-1.0\"",
            f"Encapsulated: res-hdr=0, res-body={header_len}",
            "",
            http_response_str
        ]
        
        return "\r\n".join(icap_response).encode('utf-8')
    
    def error_response(self, code: int, message: str) -> bytes:
        """Return error response"""
        response = [
            f"ICAP/1.0 {code} {message}",
            "Date: " + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "\r\n"
        ]
        return "\r\n".join(response).encode('utf-8')
    
    async def read_encapsulated_content(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        """Read encapsulated HTTP content from ICAP request"""
        # Parse Encapsulated header
        encapsulated = headers.get('Encapsulated', '')
        
        # Read until end of stream or specified length
        content = b''
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            content += chunk
        
        return content
    
    async def start(self):
        """Start the ICAP server"""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        logger.info(f"ICAP Server started on {self.host}:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Stop the ICAP server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("ICAP Server stopped")
