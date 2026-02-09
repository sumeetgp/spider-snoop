
import logging
from app.core.dlp_intent_classifier import DLPIntentClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_dlp_intent")

def test_intent():
    classifier = DLPIntentClassifier()
    
    # 1. Test "Real" Context
    context_real = "var aws_secret = 'AKIA...' // Production AWS key for payment service. Do not commit!"
    logger.info("Classifying Real Context...")
    res_real = classifier.classify("aws_access_key", context_real)
    logger.info(f"Result: {res_real}")
    
    if res_real["intent"] == "REAL_DATA":
        logger.info("✅ Real Secret classified correctly.")
    else:
        logger.error(f"❌ Real mismatch: {res_real}")

    # 2. Test "Test/Mock" Context
    context_test = "it('should login with valid key', () => { const mockKey = 'AKIA_TEST_KEY_123'; ... })"
    logger.info("Classifying Test Context...")
    res_test = classifier.classify("aws_access_key", context_test)
    logger.info(f"Result: {res_test}")
    
    if res_test["intent"] == "TEST_DATA":
        logger.info("✅ Test Data classified correctly.")
    else:
        logger.error(f"❌ Test Data mismatch: {res_test}")

if __name__ == "__main__":
    test_intent()
