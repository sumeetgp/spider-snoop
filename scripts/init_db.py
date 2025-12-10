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
        # Check if admin exists
        admin = db.query(User).filter(User.username == "admin").first()
        
        if not admin:
            admin = User(
                email="admin@spider-snoop.local",
                username="admin",
                hashed_password=get_password_hash("admin123"),
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin)
            db.commit()
            logger.info("Default admin user created (username: admin, password: admin123)")
        else:
            logger.info("Admin user already exists")
        
        # Create demo users
        analyst = db.query(User).filter(User.username == "analyst").first()
        if not analyst:
            analyst = User(
                email="analyst@spider-snoop.local",
                username="analyst",
                hashed_password=get_password_hash("analyst123"),
                full_name="Security Analyst",
                role=UserRole.ANALYST,
                is_active=True
            )
            db.add(analyst)
            db.commit()
            logger.info("Demo analyst user created (username: analyst, password: analyst123)")
        
        viewer = db.query(User).filter(User.username == "viewer").first()
        if not viewer:
            viewer = User(
                email="viewer@spider-snoop.local",
                username="viewer",
                hashed_password=get_password_hash("viewer123"),
                full_name="Read-Only Viewer",
                role=UserRole.VIEWER,
                is_active=True
            )
            db.add(viewer)
            db.commit()
            logger.info("Demo viewer user created (username: viewer, password: viewer123)")
            
    except Exception as e:
        logger.error(f"Error creating default users: {e}")
        db.rollback()
    finally:
        db.close()
    
    logger.info("Database initialization complete")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
