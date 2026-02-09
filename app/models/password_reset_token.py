from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from app.database import Base

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    user = relationship("User", back_populates="reset_tokens")

    def is_valid(self) -> bool:
        """Check if token is valid (not used and not expired)"""
        return not self.used and datetime.utcnow() < self.expires_at

    @staticmethod
    def create_token(user_id: int, hours: int = 1) -> str:
        """Generate a secure random token"""
        import secrets
        token = secrets.token_urlsafe(32)
        return token
