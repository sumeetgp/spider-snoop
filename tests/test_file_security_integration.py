
import asyncio
import logging
import os
from app.core.file_security_engine import get_file_security_engine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_integration")

async def test_integration():
    engine = get_file_security_engine()
    
    # 1. Test Clean File
    clean_file = "final_clean.txt"
    with open(clean_file, "w") as f:
        f.write("This is a safe business document report.")
        
    logger.info(f"Scanning Clean File: {clean_file}")
    res_clean = await engine.scan(clean_file, "Safe content here.")
    logger.info(f"Clean Verdict: {res_clean['verdict']} | Remediation: {res_clean['remediation']}")
    
    if res_clean["verdict"] == "CLEAN":
        logger.info("✅ Clean file passed integration.")
    else:
        logger.error(f"❌ Clean file failed: {res_clean}")

    # 2. Test Malware (EICAR)
    malware_file = "final_malware.txt"
    with open(malware_file, "w") as f:
        f.write("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        
    logger.info(f"Scanning Malware File: {malware_file}")
    res_malware = await engine.scan(malware_file)
    logger.info(f"Malware Verdict: {res_malware['verdict']} | Remediation: {res_malware['remediation']}")
    
    if res_malware["verdict"] == "MALICIOUS":
        logger.info("✅ Malware blocked by integration.")
    else:
        logger.error(f"❌ Malware NOT blocked: {res_malware}")

    # Cleanup
    for f in [clean_file, malware_file]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    try:
        asyncio.run(test_integration())
    except Exception as e:
        logger.error(f"Test Crashed: {e}")
