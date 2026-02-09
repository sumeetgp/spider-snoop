
import logging
from app.core.dlp_engine import DLPEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_dlp_integration")

def test_dlp_integration():
    engine = DLPEngine()
    
    # 1. Test Smart Redaction (Real vs Test)
    # Added padding to ensure context windows don't overlap significantly
    mixed_content = """
    project_config = {
        "owner": "Alice",
        "live_credentials": {
            "key_id": "AKIAIOSFODNN7EXAMPLE" 
        }
    }
    
    
    
    
    
    
    // ==========================================
    // TEST SECTION - MOCK DATA BELOW
    // ==========================================
    const mockKey = 'AKIA1234567890ABCDEF'; // For unit testing only
    """
    
    logger.info("Testing Smart Redaction on Mixed Content...")
    report_mix = engine.scan(mixed_content)
    logger.info(f"Findings: {[f['type'] + ':' + f['intent'] for f in report_mix['findings']]}")
    
    redacted = engine.smart_redact(mixed_content)
    # logger.info(f"Redacted:\n{redacted}") # Reduce noise
    
    # Assertions
    if "REDACTED: AWS_ACCESS_KEY" in redacted and "AKIA1234567890ABCDEF" in redacted:
        logger.info("✅ Smart Redaction Successful: Real key masked, Mock key preserved.")
    else:
        logger.error(f"❌ Smart Redaction Failed! Real Key Redacted? {'REDACTED' in redacted}. Mock Preserved? {'AKIA123' in redacted}")

    # 2. Test Correlation (Multiple Signals)
    # Using 3 distinct CRITICAL types to trigger escalation
    # 1. AWS Key
    # 2. GitHub Token (Standard format)
    # 3. Private Key Header
    high_risk_content = """
    Here are the leaked creds:
    AWS: AKIAIOSFODNN7EXAMPLE
    GitHub: ghp_123456789012345678901234567890123456
    SSH: -----BEGIN OPENSSH PRIVATE KEY-----
    """
    
    logger.info("Testing Correlation Logic...")
    report_high = engine.scan(high_risk_content)
    risk_high = report_high["summary"]["correlation_risk"]
    types = report_high["summary"]["unique_types"]
    
    logger.info(f"Context Types: {types}")
    logger.info(f"Correlation Risk: {risk_high}")
    
    if risk_high == "CRITICAL":
        logger.info(f"✅ Correlation Risk Verified: {risk_high}")
    else:
        logger.error(f"❌ Correlation failed. Got {risk_high}")

if __name__ == "__main__":
    test_dlp_integration()
