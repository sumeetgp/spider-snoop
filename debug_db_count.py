from app.database import SessionLocal
from app.models.scan import DLPScan
from app.models.user import User

db = SessionLocal()
try:
    scans = db.query(DLPScan).order_by(DLPScan.created_at.desc()).all()
    print(f"Total Scans in DB: {len(scans)}")
    for s in scans:
        print(f"ID: {s.id}, Source: {s.source}, Risk: {s.risk_level}, Content Starts: {s.content[:50]}")
except Exception as e:
    print(f"Error: {e}")
finally:
    db.close()
