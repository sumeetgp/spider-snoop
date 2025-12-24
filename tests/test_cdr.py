import os
import zipfile
import pytest
from app.cdr_engine import CDREngine
from PIL import Image

@pytest.fixture
def cdr_engine():
    return CDREngine()

@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path

def test_image_sanitization(cdr_engine, temp_dir):
    # Create a dummy image with EXIF (simulated by just checking it saves cleanly)
    # Creating a real EXIF image programmatically without external tools is hard, 
    # but we can check if the function runs and produces a valid image.
    input_path = temp_dir / "test.png"
    output_path = temp_dir / "safe_test.png"
    
    img = Image.new('RGB', (100, 100), color='red')
    img.save(input_path)
    
    assert cdr_engine.disarm(str(input_path), str(output_path))
    assert os.path.exists(output_path)
    
    # Check if readable
    with Image.open(output_path) as safe_img:
        assert safe_img.size == (100, 100)

def test_office_macro_removal(cdr_engine, temp_dir):
    # Simulate a docm with a macro file inside
    input_path = temp_dir / "malicious.xlsm"
    output_path = temp_dir / "safe_malicious.xlsm"
    
    with zipfile.ZipFile(input_path, 'w') as zf:
        zf.writestr('xl/workbook.xml', '<xml>Workbook</xml>')
        zf.writestr('xl/vbaProject.bin', 'DANGEROUS MACRO CONTENT')
        zf.writestr('other.xml', '<xml>Safe</xml>')
        
    assert cdr_engine.disarm(str(input_path), str(output_path))
    assert os.path.exists(output_path)
    
    # Verify macro is gone
    with zipfile.ZipFile(output_path, 'r') as zf:
        files = zf.namelist()
        assert 'xl/workbook.xml' in files
        assert 'other.xml' in files
        assert 'xl/vbaProject.bin' not in files

def test_unsupported_file(cdr_engine, temp_dir):
    input_path = temp_dir / "test.txt"
    output_path = temp_dir / "out.txt"
    with open(input_path, "w") as f:
        f.write("text")
        
    # Should fallback to copy
    assert cdr_engine.disarm(str(input_path), str(output_path))
    assert os.path.exists(output_path)
    with open(output_path, "r") as f:
        assert f.read() == "text"
