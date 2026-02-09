
import os
import logging
from app.core.metadata_extractor import MetadataExtractor
from pypdf import PdfWriter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_metadata")

def test_metadata():
    extractor = MetadataExtractor()
    
    # 1. Create a Test PDF with Metadata
    pdf_file = "test_metadata.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    
    writer.add_metadata({
        "/Title": "Secret Plan",
        "/Author": "Dr. No",
        "/Creator": "Evil PDF Maker v1.0",
        "/Producer": "ReportLab"
    })
    
    with open(pdf_file, "wb") as f:
        writer.write(f)
        
    # 2. Extract
    logger.info(f"Extracting metadata from {pdf_file}...")
    meta = extractor.extract(pdf_file)
    logger.info(f"Result: {meta}")
    
    # 3. Assertions
    try:
        assert meta["author"] == "Dr. No"
        assert meta["toolchain"] == "Evil PDF Maker v1.0"
        assert meta["extension"] == ".pdf"
        logger.info("✅ PDF Metadata Extraction Passed!")
    except AssertionError as e:
        logger.error(f"❌ Assertion Failed: {e}")
    except KeyError as e:
         logger.error(f"❌ Missing Key: {e}")
         
    # Cleanup
    if os.path.exists(pdf_file):
        os.remove(pdf_file)

if __name__ == "__main__":
    test_metadata()
