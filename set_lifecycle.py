from app.utils.storage import StorageManager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def main():
    print("Setting Lifecycle Policy for DigitalOcean Spaces Bucket...")
    storage = StorageManager()
    
    if not storage.enabled:
        print("Error: Cloud storage is not configured.")
        return

    if storage.set_lifecycle_policy(days=7):
        print(f"SUCCESS: Lifecycle policy set to expire files after 7 days in bucket '{storage.bucket}'.")
    else:
        print("FAILED: Could not set lifecycle policy.")

if __name__ == "__main__":
    main()
