"""Database configuration and session management"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings

_is_sqlite = "sqlite" in settings.DATABASE_URL

_pool_kwargs = {"connect_args": {"check_same_thread": False}} if _is_sqlite else {
    "pool_size": 20,
    "max_overflow": 40,
    "pool_recycle": 3600,
    "pool_pre_ping": True,
}

engine = create_engine(settings.DATABASE_URL, **_pool_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency for database sessions"""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
