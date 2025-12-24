"""ICAP Protocol Server Implementation"""
import asyncio
import logging
from datetime import datetime
from jose import JWTError, jwt
from app.database import SessionLocal
from app.models.user import User
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

    def verify_auth(self, headers: dict) -> bool:
        """Verify Authentication Token"""
        token = None
        
        # Check standard Authorization header
        auth_header = headers.get("Authorization") or headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            
        # Check X-ICAP-Auth header (for proxies that can't send Auth)
        if not token:
            token = headers.get("X-ICAP-Auth") or headers.get("x-icap-auth")
            
        if not token:
            return False
            
        try:
            # Decode Token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                return False
                
            # Allow valid tokens directly for performance, 
            # but ideally we check DB for active status occasionally.
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.username == username).first()
                if not user or not user.is_active:
                    return False
                return True
            finally:
                db.close()
                
        except JWTError:
            return False
        except Exception as e:
            logger.error(f"Auth verification error: {e}")
            return False
        
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle ICAP client request"""
        try:
            # Read ICAP request
            request_line = await reader.readline()
            request_str = request_line.decode('utf-8').strip()
            
            logger.info(f"ICAP Request: {request_str}")
            
            # Parse ICAP request
            try:
                method, uri, version = request_str.split()
            except ValueError:
                return

            # Read headers
            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                if line:
                    try:
                        key, value = line.decode('utf-8').strip().split(':', 1)
                        headers[key.strip()] = value.strip()
                    except ValueError:
                        continue
            
            # --- AUTHENTICATION CHECK ---
            if not self.verify_auth(headers):
                logger.warning(f"ICAP Unauthorized Access Attempt: {request_str}")
                response = self.error_response(401, "Unauthorized - Invalid Token")
                writer.write(response)
                await writer.drain()
                return
            # ----------------------------
            
            if method == "RESPMOD":
                response = await self.handle_respmod(reader, headers)
                writer.write(response)
            elif method == "REQMOD":
                response = await self.handle_reqmod(reader, headers)
                writer.write(response)
            elif method == "OPTIONS":
                response = self.handle_options()
                writer.write(response)
            else:
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
        """Handle RESPMOD request"""
        content = await self.read_encapsulated_content(reader, headers)
        
        start_time = datetime.utcnow()
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
             text_content = "[BINARY_DATA]" 
        
        scan_result = await self.dlp_engine.scan(text_content)
        scan_duration = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        logger.info(f"Scan completed in {scan_duration}ms - Verdict: {scan_result['verdict']}")
        
        if scan_result['risk_level'] in ['HIGH', 'CRITICAL']:
            return self.blocked_response(scan_result)
        
        return self.no_modification_response()
    
    async def handle_reqmod(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        """Handle REQMOD request"""
        content = await self.read_encapsulated_content(reader, headers)
        
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            text_content = "[BINARY_DATA]"
            
        scan_result = await self.dlp_engine.scan(text_content)
        
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
            "Max-Connections: 100",
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
        encapsulated = headers.get('Encapsulated', '')
        
        offsets = {}
        for part in encapsulated.split(','):
            part = part.strip()
            if '=' in part:
                key, val = part.split('=')
                try:
                    offsets[key] = int(val)
                except ValueError:
                    continue
        
        body_offset = None
        for key in ['req-body', 'res-body', 'opt-body']:
            if key in offsets:
                body_offset = offsets[key]
                break
                
        if body_offset is None:
            return b''
            
        if body_offset > 0:
            try:
                await reader.readexactly(body_offset)
            except Exception as e:
                logger.error(f"Error skipping encapsulated headers: {e}")
                return b''
            
        return await self._read_chunked_body(reader)

    async def _read_chunked_body(self, reader: asyncio.StreamReader) -> bytes:
        """Read ICAP Chunked Body"""
        content = bytearray()
        
        while True:
            line = await reader.readline()
            line = line.strip()
            
            if not line:
                continue
                
            try:
                chunk_size = int(line, 16)
            except ValueError:
                logger.warning(f"Invalid chunk size: {line}")
                break
                
            if chunk_size == 0:
                await reader.readline() # Trailing CRLF
                break
                
            chunk = await reader.readexactly(chunk_size)
            content.extend(chunk)
            await reader.readexactly(2) # CRLF
            
        return bytes(content)

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        logger.info(f"ICAP Server started on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("ICAP Server stopped")
