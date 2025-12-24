import re
from typing import Dict, List, Tuple
try:
    from fastmcp import FastMCP
    mcp = FastMCP("DLP Scanner Service")
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("DLP Scanner Service")
    except ImportError:
        import sys
        import time
        # sys.stderr.write("MCP: FastMCP not found. Running in MOCK mode (Direct import functions will still work).\\n")
        
        class MockMCP:
            def tool(self):
                def decorator(func):
                    return func
                return decorator
            def run(self):
                 # Keep alive to prevent container exit if run as main
                sys.stderr.write("Mock MCP running... (Looping to keep container alive)\\n")
                while True:
                    time.sleep(10)

        mcp = MockMCP()

from app.core.dlp_patterns import DLPPatternMatcher
import subprocess
import zipfile
import pytesseract
from PIL import Image
from oletools.olevba import VBA_Parser

# Initialize the matcher
matcher = DLPPatternMatcher()

# Load Knowledge Base
import json
import os
KB_PATH = os.path.join(os.path.dirname(__file__), "app/core/knowledge_base.json")
KNOWLEDGE_BASE = {}
try:
    with open(KB_PATH, 'r') as f:
        KNOWLEDGE_BASE = json.load(f)
except Exception as e:
    print(f"Warning: Could not load Knowledge Base: {e}")

@mcp.tool()
def consult_policy_db(query: str) -> str:
    """
    RAG TOOL: Consults the Enhanced Security Policy DB.
    Checks for terms, evaluates context (positive/negative keywords) to reduce false positives,
    and returns the required ACTION (Block/Alert).
    """
    query_lower = query.lower()
    matches = []
    
    # 1. Check TERMS with Context Logic
    for term, policy in KNOWLEDGE_BASE.get("terms", {}).items():
        term_lower = term.lower()
        
        # Check if the term exists in the query
        if term_lower in query_lower:
            
            # A. Negative Context Check (The "Bird" Filter)
            # If any negative context word is present, SKIP this match.
            neg_ctx = policy.get("negative_context", [])
            if any(neg_word in query_lower for neg_word in neg_ctx):
                continue  # Skip, this is likely a false positive
                
            # B. Positive Context Check (The "Relevance" Booster)
            # If positive context is defined, we prefer if it exists, but usually we flag anyway 
            # and just increase confidence. Here, we just add a note.
            pos_ctx = policy.get("positive_context", [])
            has_context = any(pos_word in query_lower for pos_word in pos_ctx)
            
            # Formatting the Output
            match_detail = [
                f"🚨 MATCH: {term}",
                f"   RISK: {policy['risk']}",
                f"   ACTION: {policy.get('action', 'REVIEW')}",
                f"   CATEGORY: {policy.get('category', 'Unknown')}",
                f"   OWNER: {policy.get('owner', 'Security Team')}",
                f"   DESC: {policy.get('description', '')}"
            ]
            
            if has_context:
                match_detail.append(f"   CONFIDENCE: HIGH (Context keywords found)")
            
            matches.append("\n".join(match_detail))

    # 2. Check REGEX Patterns
    # (Note: In a real app, you'd use 're.search' here, not string matching)
    for pattern, details in KNOWLEDGE_BASE.get("regex_patterns", {}).items():
        # This is a simplified check. In production, compile the regex.
        import re
        if re.search(pattern, query):
             matches.append(f"🔍 PATTERN MATCH: {details['desc']}\n   RISK: {details['risk']}\n   ACTION: {details.get('action', 'LOG')}")

    if not matches:
        return "✅ CLEAN: No policy violations found."

    return "\n" + "="*40 + "\n" + "\n\n".join(matches) + "\n" + "="*40


@mcp.tool()
def scan_patterns(text: str) -> str:
    """
    Enterprise-grade DLP scanner for comprehensive PII and sensitive data detection.
    
    Scans for:
    - Financial: Credit cards (Luhn validated), SSN, bank accounts, IBAN, routing numbers
    - Personal: Email, phone, passport, driver's license, medical records, DOB
    - Network: IPv4, IPv6, MAC addresses
    - Credentials: AWS keys, GitHub tokens, API keys, Bearer tokens, JWT, passwords
    - Cryptographic: Private keys (RSA, EC, SSH, PGP)
    - Database: Connection strings with credentials
    - Cryptocurrency: Bitcoin, Ethereum addresses
    - Sensitive keywords: Confidential, proprietary, trade secret, etc.
    
    Returns a detailed report organized by severity (CRITICAL, HIGH, MEDIUM, LOW).
    """
    results = matcher.scan(text)
    
    # Build formatted report
    report_lines = []
    total_findings = 0
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        findings = results[severity]
        if findings:
            report_lines.append(f"\n{'='*60}")
            report_lines.append(f"  {severity} FINDINGS: {len(findings)}")
            report_lines.append(f"{'='*60}")
            
            # Group by type
            by_type = {}
            for finding in findings:
                ftype = finding["type"]
                if ftype not in by_type:
                    by_type[ftype] = []
                by_type[ftype].append(finding)
            
            # Display findings
            for ftype, items in by_type.items():
                report_lines.append(f"\n  [{items[0]['description']}]")
                for idx, item in enumerate(items[:5], 1):  # Limit to 5 per type
                    report_lines.append(f"    {idx}. {item['value']} (at {item['position']})")
                if len(items) > 5:
                    report_lines.append(f"    ... and {len(items) - 5} more")
            
            total_findings += len(findings)
    
    if total_findings == 0:
        return "✓ CLEAN: No sensitive patterns detected in the scanned content."
    
    # Summary header
    summary = f"""
╔══════════════════════════════════════════════════════════╗
║          DLP SCAN REPORT - {total_findings} FINDINGS DETECTED          
╚══════════════════════════════════════════════════════════╝
"""
    
    return summary + "\n".join(report_lines) + f"\n\n{'='*60}\nTotal Findings: {total_findings}\n{'='*60}"


@mcp.tool()
def enhanced_scan(text: str, include_context: bool = False) -> str:
    """
    Advanced DLP scan with optional context extraction.
    
    Args:
        text: Content to scan
        include_context: If True, returns 20 chars before/after each finding
    
    Returns:
        Detailed scan report with optional surrounding context
    """
    results = matcher.scan(text)
    
    report = {
        "summary": {
            "total_findings": sum(len(findings) for findings in results.values()),
            "critical": len(results["CRITICAL"]),
            "high": len(results["HIGH"]),
            "medium": len(results["MEDIUM"]),
            "low": len(results["LOW"])
        },
        "findings_by_severity": results
    }
    
    # Format as readable text
    output = f"""
ENHANCED DLP SCAN RESULTS
{'='*60}

SUMMARY:
  Total Findings: {report['summary']['total_findings']}
  Critical: {report['summary']['critical']}
  High: {report['summary']['high']}
  Medium: {report['summary']['medium']}
  Low: {report['summary']['low']}

RISK ASSESSMENT:
"""
    
    if report['summary']['critical'] > 0:
        output += "  ⛔ CRITICAL RISK: Immediate action required!\n"
    elif report['summary']['high'] > 0:
        output += "  ⚠️  HIGH RISK: Review and remediate\n"
    elif report['summary']['medium'] > 0:
        output += "  ⚡ MEDIUM RISK: Monitor and address\n"
    else:
        output += "  ✓ LOW/NO RISK: No critical issues detected\n"
    
    return output


@mcp.tool()
def decode_obfuscation(text: str) -> str:
    """
    SKILL: Decodes obfuscated text (Base64, Hex) to reveal hidden payloads.
    Use this if you see strings like 'eyJhb...' or '48656c6c6f'.
    """
    results = []
    
    # Base64
    import base64
    try:
        # Check if looks like base64 (length/4, alphanumeric)
        if len(text) > 8 and re.match(r'^[A-Za-z0-9+/=]+$', text.strip()):
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if len(decoded) > 3 and decoded.isprintable(): 
                results.append(f"DECODED_BASE64: {decoded}")
    except:
        pass
        
     # Hex
    try:
         if len(text) > 4 and re.match(r'^[0-9a-fA-F]+$', text.strip()):
             decoded = bytes.fromhex(text.strip()).decode('utf-8', errors='ignore')
             if len(decoded) > 3:
                 results.append(f"DECODED_HEX: {decoded}")
    except:
        pass
        
    return "\n".join(results) if results else "No obfuscation detected or decode failed."

@mcp.tool()
def analyze_code_snippet(code: str) -> str:
    """
    SKILL: Forensics for Source Code.
    Determines if code is 'Generic/Boilerplate' (Safe) or 'Proprietary logic' (High Risk).
    Checks for: 
    - Hardcoded IPs/Secrets
    - Internal package imports (e.g., 'import internal_utils')
    - Business logic comments
    """
    report = []
    risk_score = 0
    
    # 1. Internal Imports
    if re.search(r'(import|from)\s+(internal|corp|spidercob)', code):
        report.append("MATCH: Internal package import identified.")
        risk_score += 50
        
    # 2. Hardcoded IPs
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', code):
        report.append("MATCH: IPv4 Address hardcoded.")
        risk_score += 30
        
    # 3. Specific Business Logic indicators
    if re.search(r'(proprietary|confidential|do not share)', code, re.IGNORECASE):
        report.append("MATCH: Explicit confidentiality markers found.")
        risk_score += 40
        
    if risk_score > 60:
        return f"RISK: HIGH ({risk_score})\nVERDICT: PROPRIETARY CODE\nDETAILS: {'; '.join(report)}"
    elif risk_score > 0:
        return f"RISK: MEDIUM ({risk_score})\nVERDICT: POTENTIALLY SENSITIVE\nDETAILS: {'; '.join(report)}"
    else:
        return "RISK: LOW\nVERDICT: GENERIC CODE\nDETAILS: No specific proprietary markers found."


@mcp.tool()
def scan_metadata(file_path: str) -> str:
    """
    SKILL: Extracts hidden metadata from files (PDF, DOCX, IMG).
    Detects: Author names, software versions, GPS coordinates, and edit history.
    """
    try:
        # We use subprocess to call exiftool directly for safety & speed
        # Ensure 'exiftool' is installed: sudo apt-get install libimage-exiftool-perl
        result = subprocess.run(
            ["exiftool", "-json", file_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        if not result.stdout:
            return "METADATA_SCAN: No metadata found or tool error."
        
        data = json.loads(result.stdout)[0]
        
        # Filter for interesting fields only (reduce noise)
        interesting_keys = ['Author', 'Creator', 'Title', 'Subject', 'Software', 'GPSPosition', 'CreateDate']
        findings = [f"{k}: {v}" for k, v in data.items() if k in interesting_keys or "GPS" in k]
        
        return "METADATA FINDINGS:\n" + "\n".join(findings)
    except Exception as e:
        return f"METADATA_ERROR: {str(e)}"

@mcp.tool()
def scan_office_macros(file_path: str) -> str:
    """
    SKILL: Extracts and analyzes VBA Macros from Office Docs (Word, Excel).
    Detects: Auto-execution strings, suspicious URL downloads, and obfuscation.
    """
    try:
        vbaparser = VBA_Parser(file_path)
        if not vbaparser.detect_vba_macros():
            return "CLEAN: No Macros found in this document."

        report = ["⚠️ MACROS DETECTED:"]
        for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
            report.append(f"- Macro in: {vba_filename}")
            
            # Simple keyword check in the macro code
            if "AutoOpen" in vba_code or "AutoExec" in vba_code:
                report.append("  [CRITICAL] Contains Auto-Execution trigger!")
            if "http" in vba_code or "powershell" in vba_code.lower():
                report.append("  [CRITICAL] Suspicious network/shell command found!")

        results = vbaparser.analyze_macros()
        for kw_type, keyword, description in results:
             if kw_type == 'Suspicious':
                 report.append(f"  [SUSPICIOUS] {keyword}: {description}")

        return "\n".join(report)
    except Exception as e:
        return f"MACRO_SCAN_ERROR: {str(e)}"

@mcp.tool()
def inspect_zip_structure(file_path: str) -> str:
    """
    SKILL: Safety check for ZIP/Archive files.
    Detects: Zip Bombs (high compression ratio) and forbidden file types inside.
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            total_size = 0
            file_count = 0
            suspicious_files = []
            
            for info in zf.infolist():
                file_count += 1
                total_size += info.file_size
                
                # 1. Check Compression Ratio (Zip Bomb logic)
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > 100: # 100x compression is suspicious
                        return f"CRITICAL: ZIP BOMB DETECTED! File {info.filename} has {int(ratio)}x compression."

                # 2. Check for nested threats
                if info.filename.endswith(('.exe', '.bat', '.vbs', '.js')):
                    suspicious_files.append(info.filename)
            
            # 3. Size Limits (e.g., limit extraction to 500MB)
            if total_size > 500 * 1024 * 1024:
                return f"BLOCK: Archive expands to {total_size/1024/1024:.2f}MB (Policy Limit: 500MB)"

            report = f"ARCHIVE_OK: Contains {file_count} files. Total uncompressed size: {total_size/1024/1024:.2f}MB."
            if suspicious_files:
                report += f"\nWARNING: Contains executable files: {', '.join(suspicious_files)}"
            return report
            
    except zipfile.BadZipFile:
        return "ERROR: Invalid or Corrupted Zip file."

@mcp.tool()
def scan_image_text(image_path: str) -> str:
    """
    SKILL: OCR (Optical Character Recognition) for images (PNG, JPG, TIFF).
    Extracts text from images so it can be passed to the 'scan_patterns' tool.
    """
    try:
        # Requires 'tesseract-ocr' installed on system
        text = pytesseract.image_to_string(Image.open(image_path))
        if len(text.strip()) == 0:
            return "OCR_INFO: No readable text found in image."
        
        # We return the text so Gemini/Matcher can analyze it
        return f"OCR_EXTRACTED_TEXT:\n{text[:5000]}..." # Limit size
    except Exception as e:
        return f"OCR_ERROR: {str(e)}"

def scan_dependencies_logic(manifest_content: str, ecosystem: str = "PyPI") -> str:
    """
    Core Logic: Scans manifest content using OSV directly.
    """
    import requests
    import re
    
    # 1. Parse Manifest
    packages = []
    try:
        if ecosystem == "PyPI":
            # Simple requirements.txt parser
            for line in manifest_content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle "package==1.0.0"
                    parts = re.split(r'[=<>!]', line)
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        version = line.replace(name, "").strip().lstrip("=<>!")
                        if version:
                            packages.append({"name": name, "version": version, "ecosystem": "PyPI"})
                            
        elif ecosystem == "npm":
            # Simple package.json parser
            data = json.loads(manifest_content)
            deps = data.get("dependencies", {})
            deps.update(data.get("devDependencies", {}))
            for name, version in deps.items():
                # Clean version (remove ^, ~)
                clean_ver = version.replace("^", "").replace("~", "")
                if clean_ver and clean_ver[0].isdigit(): 
                    packages.append({"name": name, "version": clean_ver, "ecosystem": "npm"})
    except Exception as e:
        return f"MANIFEST_ERROR: Failed to parse content: {str(e)}"

    if not packages:
        return "CLEAN: No parseable packages found in manifest."

    # 2. Query OSV Batch API
    queries = []
    for pkg in packages:
        queries.append({
            "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
            "version": pkg["version"]
        })

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch", 
            json={"queries": queries},
            timeout=10
        )
        if resp.status_code != 200:
            return f"OSV_API_ERROR: {resp.status_code} {resp.text}"
            
        results = resp.json().get("results", [])
    except Exception as e:
        return f"OSV_CONNECTION_ERROR: {str(e)}"

    # 3. Format Report
    report = ["SUPPLY CHAIN VULNERABILITIES:"]
    vuln_count = 0
    
    for idx, res in enumerate(results):
        vulns = res.get("vulns", [])
        if vulns:
            pkg = packages[idx]
            vuln_count += len(vulns)
            report.append(f"\n📦 {pkg['name']} @ {pkg['version']}")
            for v in vulns:
                # 1. Get best description
                summary = v.get("summary", "")
                if not summary:
                    # Fallback to details (truncated)
                    summary = v.get("details", "No summary available.")[:150].replace("\n", " ") + "..."
                
                # 2. Extract Fixed Version
                # OSV can have multiple affected ranges (GIT, ECOSYSTEM). We prefer ECOSYSTEM.
                fixed_versions = []
                for affected in v.get("affected", []):
                    # Check if this affected block matches our ecosystem/package
                    # (Usually it does in batch query, but good to be safe)
                    for range_info in affected.get("ranges", []):
                        if range_info.get("type") == "ECOSYSTEM":
                            for event in range_info.get("events", []):
                                if "fixed" in event:
                                    fixed_versions.append(event["fixed"])
                
                # Sort/Dedupe to find the most relevant 'next' fixed version
                # Logic: Find the smallest fixed version that is > current version?
                # For simplicity, we join them or take the latest.
                # Often there's just one relevant fix for the branch.
                fixed_ver = "Unknown"
                if fixed_versions:
                    # Filter out non-semantic versions if possible?
                    # basic heuristic: take the last one found (usually highest) or join
                    fixed_ver = ", ".join(sorted(set(fixed_versions)))
                
                report.append(f"  - [{v.get('id', 'VULN')}] {summary}")
                report.append(f"    Fixed in: {fixed_ver}")
    
    if vuln_count == 0:
        return f"✓ CLEAN: Scanned {len(packages)} packages. No known vulnerabilities found."
        
    return "\n".join(report)

@mcp.tool()
def scan_dependencies(manifest_content: str, ecosystem: str = "PyPI") -> str:
    """
    SKILL: Supply Chain Security (OSV.dev).
    Analyzes 'requirements.txt' (ecosystem='PyPI') or 'package.json' (ecosystem='npm') for detailed CVEs.
    """
    return scan_dependencies_logic(manifest_content, ecosystem)

def scan_secrets_codebase_logic(file_path: str) -> str:
    """
    Core Logic: TruffleHog-style Secret Scanning for Zip/Codebases.
    Recursively scans all files in a zip for secrets using TruffleHog (if available) and Regex.
    """
    if not os.path.exists(file_path):
        return "ERROR: File not found."
        
    import tempfile
    import shutil
    import subprocess
    import json
    
    findings = []
    temp_dir = tempfile.mkdtemp()
    
    try:
        # 1. Extract
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zf:
                zf.extractall(temp_dir)
        else:
            return "ERROR: Only .zip codebases supported for now."
            
        # 2. Try TruffleHog First (Superior Detection)
        trufflehog_found = False
        try:
            # Run TruffleHog on the temp directory
            # --json: Structured output
            # --no-verification: Speed up scans (don't ping APIs), helpful for offline/safe scanning
            # --no-update: Don't check for updates
            cmd = ["trufflehog", "filesystem", temp_dir, "--json", "--no-verification", "--no-update", "--fail-verified"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            trufflehog_found = True
            
            # TruffleHog outputs one JSON object per line per finding
            for line in result.stdout.splitlines():
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    # TruffleHog Json Structure Varies, usually:
                    # {"SourceMetadata":{"Data":{"Filesystem":{"file":"..."}}}, "DetectorName": "...", "Raw": "..."}
                    
                    file_name = "unknown"
                    if "SourceMetadata" in data and "Data" in data["SourceMetadata"] and "Filesystem" in data["SourceMetadata"]["Data"]:
                         file_name = data["SourceMetadata"]["Data"]["Filesystem"].get("file", "unknown")
                         # Relativize path
                         if file_name.startswith(temp_dir):
                             file_name = file_name[len(temp_dir):].lstrip('/')

                    detector = data.get("DetectorName", "Secret")
                    raw_secret = data.get("Raw", "")
                    
                    # Mask secret for display
                    masked = f"{raw_secret[:6]}...***" if len(raw_secret) > 10 else "***"
                    
                    findings.append(f"[CRITICAL] {detector} found in {file_name}: {masked} (Verified: {data.get('Verified', False)})")
                except:
                    continue
                    
        except FileNotFoundError:
             # TruffleHog not installed, fall through to regex
             trufflehog_found = False
        except Exception as e:
             findings.append(f"WARN: TruffleHog error: {str(e)}")

        # 3. Always Run Internal Regex Scan (Complementary)
        # We run this to catch things TruffleHog might miss (custom patterns like specific IP ranges, internal keywords)
        
        regex_findings = []
        for root, dirs, files in os.walk(temp_dir):
            if '.git' in dirs: dirs.remove('.git') # Skip git internals
            
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, temp_dir)
                
                # Skip known binary/media extensions
                if file.endswith(('.png', '.jpg', '.exe', '.dll', '.so', '.dylib', '.pyc')):
                    continue
                    
                try:
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()
                        
                    # Use the shared matcher with Secrets Only mode
                    scan_res = matcher.scan(content, secrets_only=True)
                    
                    # Flatten findings
                    for severity, items in scan_res.items():
                        if severity in ["CRITICAL", "HIGH"]: # Focus on high impact
                            for item in items:
                                regex_findings.append({
                                    "severity": severity,
                                    "type": item['type'],
                                    "file": rel_path,
                                    "value": item['value'],
                                    "source": "Internal Regex"
                                })
                                
                except Exception:
                    pass

        # 4. Merge Findings (Deduplication)
        # findings list already has strings from TruffleHog. Let's convert them or append regex strings.
        # TruffleHog strings format: "[CRITICAL] {detector} found in {file_name}: {masked}..."
        
        # We'll just append non-duplicate regex matches.
        # Simple heurstic: if the regex value/type is already 'covered' by a trufflehog report, roughly skip?
        # Actually safer to show both if unsure. Let's just append but mark source.
        
        for rf in regex_findings:
            # Create a string representation
            rf_str = f"[{rf['severity']}] {rf['type']} found in {rf['file']}: {rf['value']} (Source: {rf['source']})"
            findings.append(rf_str)


    except Exception as e:
        return f"SCAN_ERROR: {str(e)}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    if not findings:
        return "✓ CLEAN: No secrets found in codebase."
        
    source = "TruffleHog + Internal Regex"
    return f"CODEBASE SECRETS DETECTED ({source}):\n" + "\n".join(findings)

@mcp.tool()
def scan_secrets_codebase(file_path: str) -> str:
    """
    SKILL: TruffleHog-style Secret Scanning for Zip/Codebases.
    Recursively scans all files in a zip for secrets using TruffleHog (if available) and Regex.
    """
    return scan_secrets_codebase_logic(file_path)

def scan_os_package_list_logic(package_list_text: str, os_distro: str = "Debian") -> str:
    """
    Core Logic: Scans a text list of OS packages (e.g., 'dpkg -l' output) for vulnerabilities.
    """
    import requests
    
    # 1. Parse the messy text file
    packages = []
    
    # Simple parser for 'dpkg -l' format: "ii  package_name  1.2.3  ..."
    # Also handles basic "name version" format for simplicity
    for line in package_list_text.splitlines():
        line = line.strip()
        if not line or line.startswith("Desire=") or line.startswith("| Status=") or line.startswith("+++-") or line.startswith("Listing..."):
            continue
            
        parts = line.split()
        
        # dpkg format: "ii  libssl1.1:amd64  1.1.1f-1ubuntu2  ..."
        if len(parts) >= 3 and parts[0] == "ii":
            name = parts[1].split(":")[0] # Remove architecture if present
            version = parts[2]
            packages.append({"name": name, "version": version})
            
        # simple "name version" format fallback
        elif len(parts) == 2:
             packages.append({"name": parts[0], "version": parts[1]})

    if not packages:
        return "ERROR: Could not parse package list. Ensure it looks like 'dpkg -l' output or 'name version' list."

    # 2. Query OSV API (Batch Query)
    api_url = "https://api.osv.dev/v1/querybatch"
    
    queries = []
    # Cap at 200 to be safe with free API limits per batch
    for pkg in packages[:200]: 
        queries.append({
            "package": {"name": pkg["name"], "ecosystem": os_distro},
            "version": pkg["version"]
        })

    try:
        response = requests.post(api_url, json={"queries": queries}, timeout=10)
        if response.status_code != 200:
            return f"OSV_API_ERROR: {response.text}"
            
        results = response.json().get("results", [])
        
        # 3. Format Findings
        vuln_report = []
        vuln_count = 0
        seen_vulns = set()
        
        for i, res in enumerate(results):
            if "vulns" in res:
                pkg = packages[i]
                
                for vuln in res["vulns"]:
                    vuln_id = vuln.get('id', 'VULN')
                    
                    # Extract Summary
                    summary = vuln.get("summary") or vuln.get("details", "No summary available.")
                    if len(summary) > 200: summary = summary[:200].replace("\n", " ") + "..."
                    
                    # Extract Fixed Version
                    fixed_ver = "Unknown"
                    for affected in vuln.get("affected", []):
                        # Check if this affected block matches our package (name and ecosystem)
                        # This is important for OSV, as a vuln might affect multiple packages/ecosystems
                        affected_pkg_name = affected.get("package", {}).get("name")
                        affected_ecosystem = affected.get("package", {}).get("ecosystem")
                        
                        if affected_pkg_name == pkg["name"] and affected_ecosystem == os_distro:
                            for range_info in affected.get("ranges", []):
                                if range_info.get("type") == "ECOSYSTEM":
                                    for event in range_info.get("events", []):
                                        if "fixed" in event:
                                            fixed_ver = event["fixed"]
                                            break # Found fix for this package/ecosystem
                                    if fixed_ver != "Unknown": break # Stop looking in ranges
                            if fixed_ver != "Unknown": break # Stop looking in affected blocks
                    
                    # Deduplicate output by ID for the current package
                    # We only add the package header once if it has any unique vulns
                    if (pkg["name"], vuln_id) not in seen_vulns:
                        if vuln_count == 0: # First vulnerability found, add package header
                            vuln_report.append(f"\n📦 {pkg['name']} @ {pkg['version']}")
                        elif (pkg["name"], pkg["version"]) not in [ (p['name'], p['version']) for p in packages[:i] if (p['name'], vuln_id) in seen_vulns]:
                            # Add package header if this is the first vuln for this specific package instance
                            vuln_report.append(f"\n📦 {pkg['name']} @ {pkg['version']}")

                        seen_vulns.add((pkg["name"], vuln_id))
                        vuln_count += 1
                        vuln_report.append(f"  - [{vuln_id}] {summary}")
                        vuln_report.append(f"    Fixed in: {fixed_ver}")
                    
        if not vuln_report:
            return f"✅ CLEAN: Scanned {len(packages)} OS packages. No known vulnerabilities found."
            
        return "\n".join(vuln_report)
        
    except Exception as e:
        return f"OSV_SCAN_ERROR: {str(e)}"
        
@mcp.tool()
def scan_os_package_list(package_list_text: str, os_distro: str = "Debian") -> str:
    """
    SKILL: Scans a text list of OS packages (e.g., 'dpkg -l' output) for vulnerabilities.
    Args:
        package_list_text: The content of the text file.
        os_distro: 'Debian' (default) or 'Alpine'.
    """
    return scan_os_package_list_logic(package_list_text, os_distro)

def scan_dependency_manifest_logic(file_path: str) -> str:
    """
    Core Logic: Scans build files (requirements.txt, pom.xml, package.json) for CVEs using Trivy.
    """
    import subprocess
    import json
    import tempfile
    import os
    import shutil
    
    # Create a temporary directory for the symlink/copy to trick Trivy
    with tempfile.TemporaryDirectory() as temp_dir:
        # Determine target filename based on content/heuristics if possible, 
        # but for now we default to requirements.txt if it looks like python, or just verify extension.
        # Actually, caller usually knows. But here we just have file_path.
        # Let's assume requirements.txt if not package.json
        target_name = "requirements.txt"
        if "package.json" in os.path.basename(file_path).lower():
            target_name = "package.json"
            
        # Create the symlink/copy
        scan_target = os.path.join(temp_dir, target_name)
        try:
            shutil.copy(file_path, scan_target)
        except Exception:
             return "TRIVY_ERROR: Could not prepare file for scanning."

        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--scanners", "vuln",
            scan_target
        ]
        
        try:
            # Run Trivy
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0 and result.stderr:
                 # verify if just no vulnerabilities or actual error
                 if "Supported files for scanner(s) not found" in result.stderr:
                      # Should not happen with our rename trick
                      return "TRIVY_ERROR: File format not recognized."
            
            data = json.loads(result.stdout)
            
            # Parse Findings
            vulns = []
            if "Results" in data:
                for res in data["Results"]:
                     if "Vulnerabilities" in res:
                         for v in res["Vulnerabilities"]:
                             pkg = v.get("PkgName", "Unknown")
                             ver = v.get("InstalledVersion", "Unknown")
                             vid = v.get("VulnerabilityID", "")
                             
                             vulns.append(f"📦 {pkg} @ {ver}\n  - [{vid}] {v.get('Title', 'No Title')}\n    Fixed in: {v.get('FixedVersion', 'Unknown')}")

            if not vulns:
                return "✓ CLEAN: No vulnerabilities found in manifest."
                
            return "DEPENDENCY VULNERABILITIES FOUND:\n" + "\n".join(vulns)
            
        except json.JSONDecodeError:
             return f"TRIVY_JSON_ERROR: Could not parse output: {result.stdout[:200]}"
        except Exception as e:
            return f"SCAN_ERROR: {str(e)}"

@mcp.tool()
def scan_dependency_manifest(file_path: str) -> str:
    """
    SKILL: Scans build files (requirements.txt, pom.xml, package.json) for CVEs using Trivy.
    Uses Trivy filesystem scan to identify vulnerable libraries and suggest fixed versions.
    """
    return scan_dependency_manifest_logic(file_path)

if __name__ == "__main__":
    # Ensure all logs go to stderr to avoid breaking MCP protocol on stdout
    import sys
    # ... (rest of main)
    # mcp.run() handles the serving loop
    mcp.run()
