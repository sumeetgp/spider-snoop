
import asyncio
import json
import os
import shutil
from app.dlp_engine import DLPEngine
from app.cdr_engine import CDREngine
from app.core.dlp_patterns import DLPPatternMatcher
# We'll mock the DB/User part for Code Security or just call the logic functions directly if possible.
# For Code Security, it's easier to verify the Logic functions from `mcp_server.py` which are the core logic used by the API.
from mcp_server import scan_dependencies_logic, scan_secrets_codebase_logic

async def generate_report():
    report = []
    report.append("# Spider Snoop: Test Data & Service Output Report\n")
    report.append("This report documents the actual inputs provided to the service and the corresponding outputs generated during testing.\n")

    # --- 1. DLP Engine Scenarios ---
    report.append("## 1. Data Loss Prevention (DLP) Engine\n")
    dlp = DLPEngine()
    
    # Scene 1: Financial
    input_text = "My credit card is 4111 1111 1111 1111 and my bank account is 123456789"
    report.append("### 1.1 Financial Data Detection")
    report.append(f"**Input:**\n```text\n{input_text}\n```")
    result = await dlp.scan(input_text)
    # Filter result for brevity
    simplified_result = {
        "risk_level": result["risk_level"],
        "findings": [{"type": f["type"], "value": f["matches"][0], "severity": f["severity"]} for f in result["findings"]]
    }
    report.append(f"**Service Output:**\n```json\n{json.dumps(simplified_result, indent=2)}\n```\n")

    # Scene 2: Secrets
    input_text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    report.append("### 1.2 Secret Key Detection")
    report.append(f"**Input:**\n```text\n{input_text}\n```")
    result = await dlp.scan(input_text)
    simplified_result = {
        "risk_level": result["risk_level"],
        "findings": [{"type": f["type"], "value": f["matches"][0], "severity": f["severity"]} for f in result["findings"]]
    }
    report.append(f"**Service Output:**\n```json\n{json.dumps(simplified_result, indent=2)}\n```\n")

    # Scene 3: Redaction
    input_text = "Contact me at 555-555-5555 regarding account 123456789"
    report.append("### 1.3 Redaction")
    report.append(f"**Input:**\n```text\n{input_text}\n```")
    # Redaction is usually separate or part of specialized call in pattern matcher or engine wrapper
    # Using DLPPatternMatcher directly for pure redaction demonstration if dlp_engine doesn't expose it simply
    matcher = DLPPatternMatcher()
    redacted = matcher.redact(input_text)
    report.append(f"**Service Output:**\n```text\n{redacted}\n```\n")

    # --- 2. CDR Engine Scenarios ---
    report.append("## 2. Content Disarm & Reconstruction (CDR)\n")
    cdr = CDREngine()
    
    # Scene 1: Text Sanitization
    eicar_str = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    input_text = f"Normal text. {eicar_str}"
    
    # Create temp file
    if not os.path.exists("temp_test"): os.mkdir("temp_test")
    infile = "temp_test/malware.txt"
    outfile = "temp_test/safe.txt"
    with open(infile, "w") as f: f.write(input_text)
    
    report.append("### 2.1 Malicious Text Sanitization")
    report.append(f"**Input Content:**\n```text\n{input_text}\n```")
    
    cdr.disarm(infile, outfile)
    
    with open(outfile, "r") as f:
        safe_content = f.read()
        
    report.append(f"**Service Output (File Content):**\n```text\n{safe_content}\n```\n")
    
    # Clean up
    shutil.rmtree("temp_test")

    # --- 3. Code Security Scenarios ---
    report.append("## 3. Code Security\n")
    
    # Scene 1: Dependency Scan
    req_content = "Django==3.2.0\nrequests==2.25.1"
    report.append("### 3.1 Dependency Vulnerability Scan (OSV)")
    report.append(f"**Input (requirements.txt):**\n```text\n{req_content}\n```")
    
    # Using the logic function directly (mocking the HTTP call effectively by running it? 
    # No, let's run it. If it hits real OSV API, great. If blocked, we might see error.)
    # The user environment allows outbound HTTP usually? If not, we'll see error in report.
    scan_result = scan_dependencies_logic(req_content, ecosystem="PyPI")
    report.append(f"**Service Output:**\n```text\n{scan_result}\n```\n")

    # Scene 2: Codebase Secrets (Simulated logic call since we can't easily zip in script without verbosity)
    # We will test the regex fallback logic of `scan_secrets_codebase` by passing a file path that triggers it?
    # Or just use the DLP matcher in secrets mode which is what the loop does.
    # Let's try to make a real zip for the full experience.
    import zipfile
    if not os.path.exists("temp_code"): os.mkdir("temp_code")
    zip_path = "temp_code/source.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("config.py", "API_KEY='AKIAIOSFODNN7EXAMPLE'")
    
    report.append("### 3.2 Codebase Secret Scanning")
    report.append(f"**Input (source.zip):**\n- `config.py`: `API_KEY='AKIAIOSFODNN7EXAMPLE'`")
    
    # This logic function extracts and scans
    secrets_result = scan_secrets_codebase_logic(zip_path)
    report.append(f"**Service Output:**\n```text\n{secrets_result}\n```\n")
    
    shutil.rmtree("temp_code")

    # Output to stdout
    print("\n".join(report))

if __name__ == "__main__":
    asyncio.run(generate_report())
