"""Database initialization and setup script"""
import asyncio
from sqlalchemy.orm import Session
from app.database import SessionLocal, engine, Base
from app.models.user import User, UserRole
from app.utils.auth import get_password_hash
import logging

logger = logging.getLogger(__name__)

def init_db():
    """Initialize database with tables and default admin user"""
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")
    
    # Create default admin user
    db = SessionLocal()
    
    try:
        # Create admin user
        if not get_user_by_username(db, "admin"):
            admin_user = User(
                email="admin@spidercob.com",
                username="admin",
                hashed_password=get_password_hash("admin123"),
                full_name="Admin User",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin_user)
            print("Default admin user created (username: admin, password: admin123)")
        else:
            logger.info("Admin user already exists")

        # Create analyst user
        if not get_user_by_username(db, "analyst"):
            analyst_user = User(
                email="analyst@spidercob.com",
                username="analyst",
                hashed_password=get_password_hash("analyst123"),
                full_name="Analyst User",
                role=UserRole.ANALYST,
                is_active=True
            )
            db.add(analyst_user)
            print("Demo analyst user created (username: analyst, password: analyst123)")
        else:
            logger.info("Analyst user already exists")

        # Create viewer user
        if not get_user_by_username(db, "viewer"):
            viewer_user = User(
                email="viewer@spidercob.com",
                username="viewer",
                hashed_password=get_password_hash("viewer123"),
                full_name="Viewer User",
                role=UserRole.VIEWER,
                is_active=True
            )
            db.add(viewer_user)
            print("Demo viewer user created (username: viewer, password: viewer123)")
        else:
            logger.info("Viewer user already exists")
            
        db.commit() # Commit all changes at once after adding all users
            
    except Exception as e:
        logger.error(f"Error creating default users: {e}")
        db.rollback()
    finally:
        db.close()
    
    logger.info("Database initialization complete")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
