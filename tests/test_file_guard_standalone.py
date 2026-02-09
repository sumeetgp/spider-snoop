
import asyncio
import os
import logging
from app.core.file_guard import FileGuard

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_file_guard")

async def test_file_guard():
    logger.info("Initializing FileGuard...")
    # Point to rules dir relative to execution root
    guard = FileGuard(rules_path="rules") 
    
    # 1. Test Clean File
    clean_file = "test_clean.txt"
    with open(clean_file, "w") as f:
        f.write("This is a clean file with no malware.")
    
    logger.info(f"Scanning Clean File: {clean_file}")
    is_safe, findings = await guard.scan_file(clean_file)
    if is_safe:
        logger.info("✅ Clean file passed.")
    else:
        logger.error(f"❌ Clean file failed! Findings: {findings}")

    # 2. Test Malware File (EICAR)
    malware_file = "test_malware.txt"
    # Ensure it exists (it should fromrepo)
    if not os.path.exists(malware_file):
        with open(malware_file, "w") as f:
            f.write("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            
    logger.info(f"Scanning Malware File: {malware_file}")
    is_safe, findings = await guard.scan_file(malware_file)
    
    if not is_safe:
        logger.info(f"✅ Malware detected as expected. Findings: {findings}")
    else:
        logger.error("❌ Malware NOT detected!")

    # Cleanup
    if os.path.exists(clean_file):
        os.remove(clean_file)

if __name__ == "__main__":
    asyncio.run(test_file_guard())
