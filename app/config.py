"""Application Configuration"""
import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "SPIDERCOB DLP"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
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
    USE_LANGCHAIN_CISO: bool = True

    # Storage (DigitalOcean Spaces)
    DO_SPACES_KEY: Optional[str] = os.getenv("DO_SPACES_KEY")
    DO_SPACES_SECRET: Optional[str] = os.getenv("DO_SPACES_SECRET")
    DO_SPACES_ENDPOINT: str = os.getenv("DO_SPACES_ENDPOINT", "https://sgp1.digitaloceanspaces.com")
    DO_SPACES_REGION: str = os.getenv("DO_SPACES_REGION", "sgp1")
    DO_SPACES_BUCKET: str = os.getenv("DO_SPACES_BUCKET", "spider-snoop")
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"

settings = Settings()
