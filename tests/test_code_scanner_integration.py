
import asyncio
import logging
from app.core.code_scanner import get_code_scanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_code_integration")

async def test_code_integration():
    scanner = get_code_scanner()
    
    # 1. Vulnerable File Content
    vulnerable_code = """
    import pickle
    import os
    
    # HARDCODED SECRET (CRITICAL)
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    
    def load_data(data):
        # VULNERABLE LOGIC (HIGH)
        return pickle.load(data)
        
    def safe_function():
        # SAFE EXAMPLE - Matches regex (AKIA+16) but context says example
        example_key = "AKIAEXAMPLE123456789" 
        print("Hello")
    """
    
    logger.info("Scanning Vulnerable Code...")
    report = await scanner.scan_file("vulnerable.py", vulnerable_code)
    
    findings = report["findings"]
    logger.info(f"Total Findings: {len(findings)}")
    
    # Check Verdicts
    secret_found = False
    vuln_found = False
    safe_ignored = True
    
    for f in findings:
        desc = f"{f['category']} - {f['description']} ({f['ai_risk']}) [Conf: {f['ai_confidence']}]"
        logger.info(f"Finding: {desc} -> Action: {f['action']}")
        
        if f['category'] == "SECRET" and f['ai_risk'] == "REAL_SECRET":
            if f['action'] == "BLOCK": secret_found = True # Only count if blocked
            else: logger.error(f"❌ Real secret found but not blocked. Conf: {f['ai_confidence']}")
            
        if f['category'] == "VULNERABILITY" and "pickle" in f['description'] and f['ai_risk'] == "VULNERABLE_LOGIC":
            vuln_found = True
            
        if "AKIA_EXAMPLE_KEY" in f.get('context', '') and f['action'] != "ALLOW":
             safe_ignored = False
             logger.error("❌ Example key was not allowed")

    if secret_found and vuln_found:
        logger.info("✅ Code Scanner Verified: Detected Secrets & Vulnerabilities.")
    else:
        logger.error("❌ Code Scanner Failed detection.")

if __name__ == "__main__":
    asyncio.run(test_code_integration())
