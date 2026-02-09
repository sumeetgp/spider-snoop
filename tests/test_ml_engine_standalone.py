
import sys
import logging
from app.core.ml_engine import LocalMLEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_ml_engine")

def test_ml_loading():
    logger.info("Initializing Engine...")
    engine = LocalMLEngine()
    
    logger.info("Testing DLP Model Loading (DistilBERT)...")
    try:
        result = engine.classify_text("dlp", "This is a test message with sensitive info.", ["safe", "unsafe"])
        logger.info(f"Inference Result: {result}")
    except Exception as e:
        logger.error(f"Inference Failed: {e}")
        sys.exit(1)

    logger.info("Test Complete!")

if __name__ == "__main__":
    test_ml_loading()
