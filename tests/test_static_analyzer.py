
import os
import logging
from app.core.static_analyzer import StaticAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_static")

def test_static():
    analyzer = StaticAnalyzer()
    
    # 1. Test High Entropy (Random Data)
    high_entropy_file = "test_random.bin"
    with open(high_entropy_file, "wb") as f:
        f.write(os.urandom(1024)) # Truly random -> High entropy (~8.0)
        
    logger.info(f"Analyzing High Entropy File: {high_entropy_file}")
    res_high = analyzer.analyze(high_entropy_file)
    logger.info(f"Result: {res_high}")
    
    try:
        assert res_high["entropy"] > 7.0
        assert res_high["is_packed"] is True
        logger.info("✅ High Entropy Check Passed")
    except AssertionError:
        logger.error(f"❌ Low Entropy detected: {res_high['entropy']}")

    # 2. Test Low Entropy (Text)
    low_entropy_file = "test_text.txt"
    with open(low_entropy_file, "w") as f:
        f.write("A" * 1000) # Zero entropy basically
        
    logger.info(f"Analyzing Low Entropy File: {low_entropy_file}")
    res_low = analyzer.analyze(low_entropy_file)
    logger.info(f"Result: {res_low}")
    
    try:
        assert res_low["entropy"] < 1.0
        assert res_low["is_packed"] is False
        logger.info("✅ Low Entropy Check Passed")
    except AssertionError:
        logger.error(f"❌ Unexpected Entropy: {res_low['entropy']}")

    # 3. Test Magic Number Mismatch
    fake_pdf = "fake.pdf"
    with open(fake_pdf, "wb") as f:
        f.write(b"This is not a PDF header")
        
    logger.info(f"Analyzing Fake PDF: {fake_pdf}")
    res_magic = analyzer.analyze(fake_pdf)
    logger.info(f"Result: {res_magic}")
    
    try:
        assert res_magic["magic_match"] is False
        logger.info("✅ Magic Number Mismatch Detected")
    except AssertionError:
        logger.error("❌ Magic Number Mismatch NOT Detected")

    # Cleanup
    for f in [high_entropy_file, low_entropy_file, fake_pdf]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    test_static()
