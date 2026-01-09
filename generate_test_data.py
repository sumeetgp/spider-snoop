import os
import io
from reportlab.pdfgen import canvas
from PIL import Image, ImageDraw, ImageFont
import zipfile

DATA_DIR = "test_data"

def ensure_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def create_dlp_text():
    content = """
    CONFIDENTIAL DOCUMENT
    
    Customer Database Dump:
    1. John Doe - SSN: 123-45-6789 - CC: 4532 1234 5678 9012
    2. Jane Smith - Other: 987-65-4321
    3. Admin Email: admin@example.com
    
    API_KEY = "sk-live-12345abcdef"
    """
    with open(f"{DATA_DIR}/dlp_pii.txt", "w") as f:
        f.write(content.strip())
    print(f"Created {DATA_DIR}/dlp_pii.txt")

def create_dlp_pdf():
    # Requires reportlab
    path = f"{DATA_DIR}/dlp_pii.pdf"
    c = canvas.Canvas(path)
    c.drawString(100, 750, "CONFIDENTIAL REPORT")
    c.drawString(100, 700, "Subject: Financial Data")
    c.drawString(100, 680, "Credit Card: 4111 1111 1111 1111")
    c.save()
    print(f"Created {path}")

def create_dlp_image():
    # Requires Pillow
    img = Image.new('RGB', (800, 600), color = (255, 255, 255))
    d = ImageDraw.Draw(img)
    # Basic text handling
    d.text((10,10), "SCREENSHOT OF SENSITIVE DATA", fill=(0,0,0))
    d.text((10,50), "USER: admin", fill=(0,0,0))
    d.text((10,70), "PASSWORD: SuperSecretPassword123!", fill=(0,0,0))
    
    path = f"{DATA_DIR}/dlp_pii.png"
    img.save(path)
    print(f"Created {path}")

def create_code_security_samples():
    # 1. Leaked Secrets
    py_content = """
def connect_db():
    # Hardcoded credentials (BAD)
    aws_access_key = "AKIA1234567890EXAMPLE"
    aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    return True
    """
    with open(f"{DATA_DIR}/leak_secrets.py", "w") as f:
        f.write(py_content)
    print(f"Created {DATA_DIR}/leak_secrets.py")

    # 2. Vulnerable Manifest
    req_content = """
flask==0.12
django==1.11
requests==2.0.0
    """
    with open(f"{DATA_DIR}/vuln_manifest.txt", "w") as f:
        f.write(req_content.strip())
    print(f"Created {DATA_DIR}/vuln_manifest.txt")

def create_malware_sample():
    # Standard EICAR string
    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(f"{DATA_DIR}/eicar_test.txt", "w") as f:
        f.write(eicar)
    print(f"Created {DATA_DIR}/eicar_test.txt")

def create_cdr_sample():
    # Create a dummy zip file named .docm
    # Real macros require complex OLE structures, but we can test
    # if the file type detection works or if the zip structure is analyzed.
    path = f"{DATA_DIR}/active_macro.docm"
    with zipfile.ZipFile(path, 'w') as zf:
        zf.writestr('word/document.xml', '<xml>dummy content</xml>')
        # Suspicious file usage often checked in zips
        zf.writestr('vbaProject.bin', b'BinaryData') 
    print(f"Created {path}")

def create_compliance_hipaa():
    """Create HIPAA test file with Fake MRN and Diagnosis"""
    content = """
    HOSPITAL ADMISSION RECORD
    -------------------------
    Patient: John Doe
    DOB: 05/12/1980
    MRN: 123456789
    Diagnosis: Acute Myocardial Infarction (ICD-10: I21.9)
    Notes: Patient admits to severe chest pain.
    Treating Physician: Dr. Smith
    CONFIDENTIAL - DO NOT DISTRIBUTE
    """
    with open(f"{DATA_DIR}/compliance_hipaa.txt", "w") as f:
        f.write(content)
    print(f"Created {DATA_DIR}/compliance_hipaa.txt")

if __name__ == "__main__":
    ensure_dir()
    create_dlp_text()
    try:
        create_dlp_pdf()
    except Exception as e:
        print(f"Skipped PDF: {e}")
    try:
        create_dlp_image()
    except Exception as e:
        print(f"Skipped Image: {e}")
        
    create_code_security_samples()
    create_malware_sample()
    create_cdr_sample()
    create_compliance_hipaa()
