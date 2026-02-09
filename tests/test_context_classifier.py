
import logging
from app.core.context_classifier import ContextClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_context")

def test_context():
    classifier = ContextClassifier()
    
    # 1. Test Benign Document
    metadata_benign = {
        "file_name": "quarterly_report.pdf",
        "title": "Q4 Financial Results",
        "author": "CFO Office"
    }
    extracted_text_benign = "Revenue increased by 15% this quarter due to strong sales."
    
    logger.info("Classifying Benign Context...")
    res_benign = classifier.classify(metadata_benign, extracted_text_benign)
    logger.info(f"Result: {res_benign}")
    
    if res_benign["ml_verdict"] == "CLEAN":
        logger.info("✅ Benign Doc classified correctly.")
    else:
        logger.error("❌ Benign Doc mismatch!")

    # 2. Test Suspicious Context (Ransomware note)
    metadata_suspicious = {
        "file_name": "READ_ME_NOW.txt",
        "title": "Decrypt Your Files",
    }
    extracted_text_susp = "Your files are encrypted. Pay 5 BTC to this address to get the key. Time is running out."
    
    logger.info("Classifying Suspicious Context...")
    res_susp = classifier.classify(metadata_suspicious, extracted_text_susp)
    logger.info(f"Result: {res_susp}")
    
    if res_susp["ml_verdict"] == "SUSPICIOUS" and res_susp["threat_family"] == "RANSOMWARE":
        logger.info("✅ Ransomware classified correctly.")
    else:
        logger.error("❌ Ransomware mismatch!")

if __name__ == "__main__":
    test_context()
