
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        # Generate Nonce
        import secrets
        nonce = secrets.token_hex(16)
        request.state.nonce = nonce

        response = await call_next(request)
        
        # 1. HSTS (HTTP Strict Transport Security)
        # 1 year = 31536000 seconds
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # 2. Prevent MIME Sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # 3. Clickjacking Protection
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        
        # 4. XSS Protection (Legacy browser support)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # 5. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # 6. CMP (Content Security Policy) - Strict Nonce-based
        script_src = f"'self' 'nonce-{nonce}' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net"
        
        # Allow unsafe-inline for Swagger UI (API Docs) which may have inline handlers
        if request.url.path.startswith("/api/docs"):
            script_src += " 'unsafe-inline'"

        csp = (
            f"script-src {script_src}; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.openai.com; " 
            "frame-src 'self'; "
            "object-src 'none';"
        )
        response.headers["Content-Security-Policy"] = csp
        
        return response
