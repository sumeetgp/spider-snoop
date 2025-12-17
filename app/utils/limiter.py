from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
from jose import jwt, JWTError
from app.config import settings
import logging

logger = logging.getLogger(__name__)

def get_rate_limit_key(request: Request) -> str:
    """
    Generate the rate limit key.
    
    Logic:
    1. Check Authorization header.
    2. If Admin -> Return None (Bypass/Unlimited).
    3. If User -> Return "user:{id}".
    4. If Guest/Invalid -> Return IP address.
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id = payload.get("sub")
            role = payload.get("role")
            
            # Admins are exempt from rate limiting
            if role == "admin":
                return None
                
            if user_id:
                return f"user:{user_id}"
        except JWTError:
            pass # Invalid token, fall back to IP
            
    return get_remote_address(request)

# Initialize Limiter
limiter = Limiter(key_func=get_rate_limit_key)
