from app.database import SessionLocal
from app.models.user import User
from app.utils.auth import get_password_hash
import secrets
import string

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for i in range(length))

def fix_users():
    db = SessionLocal()
    try:
        users = {
            "admin": {"email": "admin@spidercob.com", "role": "admin"},
            "analyst": {"email": "analyst@spidercob.com", "role": "analyst"},
            "viewer": {"email": "viewer@spidercob.com", "role": "viewer"}
        }
        
        results = []
        print("\n=== UPDATED CREDENTIALS ===")
        print("| Username | Email | New Password |")
        print("|----------|-------|--------------|")
        
        for username, data in users.items():
            user = db.query(User).filter(User.username == username).first()
            
            # Generate new strong password
            new_password = generate_strong_password()
            password_hash = get_password_hash(new_password)
            
            if user:
                user.email = data['email']
                user.hashed_password = password_hash
                print(f"| {username} | {data['email']} | {new_password} |")
            else:
                print(f"| {username} | NOT FOUND | - |")
        
        db.commit()
        print("===========================\n")
        print("Database updated successfully.")
        
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    fix_users()
