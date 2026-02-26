"""Application Configuration"""
import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "SPIDERCOB DLP"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./spider_snoop.db")
    
    # ICAP Server
    ICAP_HOST: str = "0.0.0.0"
    ICAP_PORT: int = 1344
    ICAP_SERVICE_NAME: str = "dlp_scan"
    
    # OpenAI
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    USE_LANGCHAIN_CISO: bool = False
    USE_LOCAL_ML: bool = True

    # Security scanning behaviour
    ENABLE_ACTIVE_AWS_VERIFICATION: bool = False  # Makes live STS API calls — off by default
    PRESIDIO_SCORE_THRESHOLD: float = 0.4
    # Caps how many chars are fed into the Presidio transformer to keep CPU latency sane.
    # 20 000 chars ≈ 8 pages ≈ ~12 BERT inference chunks ≈ 3-5 s on CPU.
    PRESIDIO_MAX_CONTENT_CHARS: int = 20000

    # File size limits (MB)
    MAX_FILE_SIZE_MB_SENTINEL: int = 50
    MAX_FILE_SIZE_MB_GUARDIAN: int = 10
    MAX_FILE_SIZE_MB_VIDEO: int = 50

    # Storage (DigitalOcean Spaces)
    DO_SPACES_KEY: Optional[str] = os.getenv("DO_SPACES_KEY")
    DO_SPACES_SECRET: Optional[str] = os.getenv("DO_SPACES_SECRET")
    DO_SPACES_ENDPOINT: str = os.getenv("DO_SPACES_ENDPOINT", "https://sgp1.digitaloceanspaces.com")
    DO_SPACES_REGION: str = os.getenv("DO_SPACES_REGION", "sgp1")
    DO_SPACES_BUCKET: str = os.getenv("DO_SPACES_BUCKET", "spider-snoop")
    
    # Logging
    LOG_LEVEL: str = "INFO"

    # Microservices
    SERVICE_ROLE: str = os.getenv("SERVICE_ROLE", "MONOLITH") # Options: MONOLITH, API, SCANNER
    SCANNER_SERVICE_URL: str = os.getenv("SCANNER_SERVICE_URL", "http://scanner:8000")
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"

settings = Settings()
