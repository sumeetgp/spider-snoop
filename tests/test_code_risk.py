
import logging
from app.core.code_risk_classifier import CodeRiskClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_code_risk")

def test_code_risk():
    classifier = CodeRiskClassifier()
    
    # 1. Test Real Secret
    snippet_secret = "DB_PASSWORD = 'super_secret_password_123' # Production DB"
    logger.info("Classifying Real Secret...")
    res_secret = classifier.classify("Hardcoded Password", snippet_secret)
    logger.info(f"Result: {res_secret}")
    
    if res_secret["risk_type"] == "REAL_SECRET":
        logger.info("✅ Real Secret correctly identified.")
    else:
        logger.error(f"❌ Real Secret mismatch: {res_secret}")

    # 2. Test Test/Mock Data
    snippet_mock = "def test_login(): password = 'mock_password'"
    logger.info("Classifying Mock Data...")
    res_mock = classifier.classify("Hardcoded Password", snippet_mock)
    logger.info(f"Result: {res_mock}")
    
    if res_mock["risk_type"] == "TEST_MOCK" or res_mock["risk_type"] == "SAFE_CODE":
        logger.info("✅ Mock Data correctly identified.")
    else:
        logger.error(f"❌ Mock Data mismatch: {res_mock}")
        
    # 3. Test Vulnerable Logic (Eval)
    snippet_eval = "user_input = request.args.get('code'); eval(user_input)"
    logger.info("Classifying Vulnerable Logic...")
    res_eval = classifier.classify("Dangerous Function", snippet_eval)
    logger.info(f"Result: {res_eval}")
    
    if res_eval["risk_type"] == "VULNERABLE_LOGIC":
        logger.info("✅ Vulnerable Logic correctly identified.")
    else:
         logger.error(f"❌ Vulnerable Logic mismatch: {res_eval}")


if __name__ == "__main__":
    test_code_risk()
