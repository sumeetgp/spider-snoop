from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.utils.auth import get_current_active_user
from app.models.user import User
from app.dlp_engine import DLPEngine
from mcp_server import scan_dependencies_logic as scan_dependencies, scan_secrets_codebase_logic as scan_secrets_codebase
import shutil
import os
import uuid
import re
from datetime import datetime
from werkzeug.utils import secure_filename

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")



from app.database import get_db
from app.models.scan import DLPScan, ScanStatus, RiskLevel
from sqlalchemy.orm import Session
import json

@router.post("/api/security/scan")
async def scan_code(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Secure Code Scan Endpoint.
    Handles Manifests (requirements.txt, package.json) and Codebases (zip).
    """
    # Cost: 5 Credits (Standard Code Scan with AI)
    if current_user.credits_remaining < 5:
        raise HTTPException(status_code=402, detail="Insufficient credits. Code Security scan costs 5 credits.")
    
    current_user.credits_remaining -= 5
    db.add(current_user)
    # db.commit() # Commit later with scan creation to be atomic-ish or just now. 
    # Better to commit with Scan creation to ensure both happen or fail? 
    # Actually, let's commit with the scan creation below.
    
    # 1. Sanitize Filename (Fix Path Traversal / DoS)
    safe_filename = secure_filename(file.filename)
    if not safe_filename:
        safe_filename = f"unnamed_file_{uuid.uuid4()}"
        
    file_ext = os.path.splitext(safe_filename)[1].lower()
    temp_filename = f"storage/temp_{uuid.uuid4()}_{safe_filename}"
    
    # Init Scan Record
    # Generate source string based on file type
    source_tag = "CODE_SECURITY"
    if ("requirements" in file.filename.lower() and file.filename.lower().endswith(".txt")) or file.filename.lower() == "package.json":
        # Create scan record
        db_scan = DLPScan(
            user_id=current_user.id,
            source=f"CODE_SECURITY: {file.filename}",
            content="[CODE SECURITY SCAN] " + file.filename, 
            status=ScanStatus.SCANNING
        )
    else:
        # For other file types, use the default CODE_SECURITY tag
        db_scan = DLPScan(
            user_id=current_user.id,
            source=f"{source_tag}:{file.filename}",
            content=f"[FILE_SCAN] {file.filename}", 
            status=ScanStatus.SCANNING
        )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    try:
        # Save uploaded file
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        report = ""
        content = ""
        scan_type = "UNKNOWN"
        
        # 1. Dependency Scan (Manifests)
        # Allow any text file containing 'requirements' (e.g. requirements_vuln.txt)
        if ("requirements" in file.filename.lower() and file.filename.lower().endswith(".txt")) or file.filename.lower() == "package.json":
            scan_type = "Supply Chain (Manifest)"
            with open(temp_filename, "r", errors='ignore') as f:
                content = f.read()
            
            ecosystem = "npm" if "package.json" in file.filename.lower() else "PyPI"
            
            # Try Trivy via MCP first (Preferred)
            try:
                from mcp_server import scan_dependency_manifest_logic as scan_dependency_manifest
                # Note: scan_dependency_manifest logic uses subprocess and expects file path
                trivy_report = scan_dependency_manifest(temp_filename)
                
                if "TRIVY_ERROR" in trivy_report or "SCAN_ERROR" in trivy_report:
                     # Fallback to internal OSV
                     report = scan_dependencies(content, ecosystem)
                else:
                     report = trivy_report
            except Exception as e:
                # Fallback to internal OSV
                report = scan_dependencies(content, ecosystem)
            
        # 2. OS Package List Scan (New)
        elif "package" in file.filename.lower() and file_ext == ".txt":
            scan_type = "Supply Chain (OS Packages)"
            with open(temp_filename, "r", errors='ignore') as f:
                content = f.read()
            
            # Heuristic: does it look like dpkg?
            if "ii" in content or "dpkg" in content or len(content.splitlines()[0].split()) >= 2:
                # Import new tool dynamically or add to imports
                from mcp_server import scan_os_package_list_logic as scan_os_package_list
                report = scan_os_package_list(content, "Debian") # Default to Debian/Ubuntu
            else:
                report = "ERROR: File does not appear to be a valid package list (dpkg -l)."
                
        # 3. Secret Scan (Codebase)
        elif file_ext == ".zip":
            scan_type = "Codebase Secrets"
            report = scan_secrets_codebase(temp_filename)
            
        else:
            db_scan.status = ScanStatus.FAILED
            db_scan.verdict = "SKIPPED: Unsupported file type"
            db.commit()
            return {
                "id": db_scan.id,
                "verdict": "SKIPPED",
                "risk_level": "low",
                "summary": "Unsupported file type.",
                "report": "",
                "findings": []
            } # ... (rest of return structure)

        # --- RAG POLICY INJECTION ---
        policy_context = ""
        try:
            with open("app/core/policy_knowledge_base.json", "r") as f:
                policy_context = f.read()
        except:
             policy_context = "{}"

        # 4. Code Security Analysis
        # A. TruffleHog Check (Secrets in Raw Content)
        dlp = DLPEngine()
        secret_findings = []
        try:
             # Only run secret scan on Manifests/Codebases, not OS Lists (usually safe)
             if scan_type != "Supply Chain (OS Packages)":
                 matcher_results = dlp.matcher.scan(content, secrets_only=True)
                 for severity, items in matcher_results.items():
                     for item in items:
                         secret_findings.append({
                             'type': item['type'],
                             'matches': [item['value']],
                             'count': 1,
                             'severity': severity
                         })
        except Exception as e:
            print(f"Secret Scan Error: {e}")

        # B. AI Analysis with RAG Prompt
        # B. AI Analysis with RAG Prompt
        # Note: Using standard string concatenation to avoid f-string brace escaping hell with JSON
        ai_prompt = """
        You are a Senior DevOps Security Engineer.
        I have scanned a dependency file ({filename}) and found the following vulnerabilities.
        
        CORPORATE POLICY (RAG Context):
        {policy}
        
        SCAN RESULTS:
        {report}
        
        TASK:
        1. Analyze the vulnerabilities found.
        2. CHECK POLICY: Compare found versions against the Corporate Policy. 
        3. Output strictly valid JSON with this structure:
        {{
          "risk_level": "critical|high|medium|low",
          "ai_analysis": {{
              "score": <0-100>,
              "summary": "Scan complete.",
              "remediation": [
                  {{
                      "package": "Package Name",
                      "cve": "CVE ID",
                      "current_version": "Found Version",
                      "fixed_version": "Recommended Version",
                      "action": "Update to X (Policy Compliant)"
                  }}
              ]
          }}
        }}
        5. Do not include markdown formatting (```json). Just the raw JSON object.
        """.format(filename=file.filename, policy=policy_context, report=report[:5000])
        
        # 3. Analyze with AI (Senior DevOps Persona)
        # Use raw_prompt=True to bypass the standard "Analyze this content" wrapper
        # This prevents the AI from analyzing the prompt itself and forces it to EXECUTE the prompt.
        ai_result = await dlp.scan(
            content=ai_prompt,
            use_ai=True,
            force_ai=True,
            skip_regex=True,
            skip_presidio=True,
            raw_prompt=True
        )
        
        
        # C. Parse Raw Report for Structured Findings (Deterministic)
        print(f"DEBUG: Starting Code Security Scan for {file.filename}") # Debug persistence
        report_findings = []
        
        current_pkg_name = "Unknown"
        current_pkg_ver = "Unknown"
        
        if report:
            for line in report.splitlines():
                line = line.strip()
                
                # 1. Parse Package Header: 📦 package @ version
                if line.startswith("📦"):
                    # Example: 📦 Django @ 3.2.5
                    try:
                        clean_line = line.replace("📦", "").strip()
                        if "@" in clean_line:
                            parts = clean_line.split("@")
                            current_pkg_name = parts[0].strip()
                            current_pkg_ver = parts[1].strip()
                        else:
                            current_pkg_name = clean_line.split(" ")[0]
                            current_pkg_ver = "Unknown"
                    except:
                        pass
                    continue

                # 2. Parse Finding: - [CVE-xxx] Desc | Fixed: y.y.y
                # Or TruffleHog: [CRITICAL] ...
                
                # 2. Parse Finding: - [CVE-xxx] Desc
                # 3. Parse Fixed Version: Fixed in: x.x.x (Subsequent line)
                
                # Determine parsing strategy based on line start
                is_vuln_line = line.startswith("- [")
                is_fixed_line = "Fixed in:" in line
                is_secret_line = line.startswith("[") and not line.startswith("-")

                if is_vuln_line:
                    # Vulnerability Line
                    try:
                         # Remove "- "
                        content = line[2:].strip() 
                         # Split [CVE] and rest
                        if content.startswith("["):
                            parts = content.split("]", 1)
                            cve_id = parts[0].replace("[", "").strip()
                            rest = parts[1].strip()
                            
                            new_finding = {
                                'type': 'VULNERABILITY',
                                'severity': 'HIGH', # Default
                                'cve': cve_id,
                                'pkg_name': current_pkg_name,
                                'pkg_version': current_pkg_ver,
                                'detail': rest, 
                                'metadata': {'raw': line, 'fixed_in': 'Check Report'}, # Default
                                'count': 1
                            }
                            report_findings.append(new_finding)
                    except:
                        continue

                elif is_fixed_line and report_findings:
                     # "    Fixed in: 2.2.28"
                     # Update the LAST finding added
                     try:
                         # The scanner outputs Fixed in line immediately after vuln line
                         last_finding = report_findings[-1]
                         if last_finding['type'] == 'VULNERABILITY':
                             fixed_val = line.split("Fixed in:")[1].strip()
                             last_finding['metadata']['fixed_in'] = fixed_val
                             # Also append to detail for robustness?
                             last_finding['detail'] += f" | Fixed: {fixed_val}"
                     except:
                         pass
                
                elif is_secret_line:
                     # Legacy/Secret Line (TruffleHog)
                     # Format: [CRITICAL] Secret found in...
                     try:
                        parts = line.split("]", 1)
                        if len(parts) >= 2:
                            severity = parts[0].replace("[", "").strip().upper()
                            rest = parts[1].strip()
                            report_findings.append({
                                'type': 'SECRET',
                                'severity': severity,
                                'detail': rest,
                                'pkg_name': 'Secret', # Secrets don't belong to packages usually
                                'pkg_version': 'N/A',
                                'metadata': {'raw': line},
                                'count': 1
                            })
                     except:
                        continue

        # D. Merge Findings
        final_findings = secret_findings + report_findings + ai_result.get('findings', [])

        # Clean Extract of AI Data (Handle Recursive Wrapper)
        ai_data = ai_result.get('ai_analysis')
        
        # Debug Log
        print(f"DEBUG_CODE_SEC: Raw AI Result Type: {type(ai_data)}")
        
        if isinstance(ai_data, str):
            try:
                # Try simple load
                ai_data = json.loads(ai_data)
            except:
                # Try ast literal (single quotes)
                try:
                    import ast
                    ai_data = ast.literal_eval(ai_data)
                except:
                    print("DEBUG_CODE_SEC: Failed to parse AI String")
                    ai_data = {}
        
        print(f"DEBUG_CODE_SEC: Parsed AI Data Keys: {ai_data.keys() if isinstance(ai_data, dict) else 'NotDict'}")

        # Intelligent Unwrapping
        # Goal: Find the dict that has 'remediation' or 'summary'
        if isinstance(ai_data, dict):
             # 1. Check if we are already deep
             if "remediation" in ai_data:
                 pass # Good
             # 2. Check wrappers
             elif "ai_analysis" in ai_data and isinstance(ai_data["ai_analysis"], dict):
                 ai_data = ai_data["ai_analysis"]
                 print(f"DEBUG_CODE_SEC: Unwrapped ai_analysis. New Keys: {ai_data.keys()}")
                 # Handle double wrap
                 if "ai_analysis" in ai_data and isinstance(ai_data["ai_analysis"], dict):
                      ai_data = ai_data["ai_analysis"]
                      print("DEBUG_CODE_SEC: Unwrapped double ai_analysis")
             
             # 3. Check if 'summary' is the only thing and remediation is missing?
             # If remediation missing, maybe LLM failed.
        else:
             ai_data = {}
             
        if not ai_data:
             ai_data = {}

        # Determine Final Risk Level
        final_risk = ai_result.get('risk_level', 'low').lower()
        # Fallback if wrapper had it
        if isinstance(ai_result.get('ai_analysis'), dict) and 'risk_level' in ai_result.get('ai_analysis'):
             final_risk = ai_result['ai_analysis'].get('risk_level', final_risk).lower()
        
        # Override based on hard evidence (secrets or vulns)
        all_hard_findings = secret_findings + report_findings
        
        if any(f['severity'] == "CRITICAL" for f in all_hard_findings):
            final_risk = "critical"
        elif any(f['severity'] == "HIGH" for f in all_hard_findings) and final_risk != "critical":
            final_risk = "high"
        elif any(f['severity'] == "MEDIUM" for f in all_hard_findings) and final_risk not in ["critical", "high"]:
             if final_risk == "low": final_risk = "medium"
            
        # ALWAYS Generate Synthetic Remediation (Aggregated)
        # We prefer our deterministic aggregation over the AI's list for table consistency.
        if report_findings:
            print(f"DEBUG_CODE_SEC: Force Generating Aggregated Remediation from {len(report_findings)} findings")
            
            aggregated = {}
            severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
            
            for f in report_findings:
                try:
                    detail = f.get('detail', '')
                    raw_severity = f.get('severity', 'UNKNOWN')
                    sev_score = severity_map.get(raw_severity, 0)
                    
                    # LOG RAW DETAIL FOR DEBUGGING
                    # print(f"DEBUG_FINDING: [{raw_severity}] {detail}")

                    # 1. Get Core Data from Structured Fields (New Logic)
                    pkg_display = f.get('pkg_name', 'Unknown')
                    pkg_ver = f.get('pkg_version', 'Unknown')
                    cve = f.get('cve') 
                    fixed_ver = None
                    
                    # 2. Extract specific Fixed Version from 'detail'
                    # Format: "Description... | Fixed: 1.2.3"
                    if "Fixed:" in detail:
                        try:
                            fixed_part = detail.split("Fixed:")[1].strip()
                            # Clean it (it might contain other text or parens if logic changed)
                            # Assuming "Fixed: 2.2.28" or "Fixed: 2.2.28, 3.2.14" -> take first interesting one
                            fixed_ver = fixed_part.split(' ')[0].split(',')[0].strip()
                        except:
                            pass
                    
                    # 3. Fallback Parsing (Old Logic for '->' style or 'Secrets')
                    if pkg_display == "Unknown" and '->' in detail:
                         parts = detail.split('->')
                         left = parts[0].strip()
                         pkg_display = left.split(' ')[0]
                         if len(left.split(' ')) > 1: pkg_ver = left.split(' ')[1]

                    # 4. Fallback for "CVE-" finding without package context
                    if pkg_display == "Unknown" and cve:
                         # Try header/description scan?
                         pass # rely on cve

                    # Normalize Package Name
                    pkg_norm = pkg_display.lower().replace("python-", "").replace("py-", "")
                    
                    # Canonical Display Name (Capitalize)
                    pkg_canonical = pkg_norm.capitalize()
                    if pkg_canonical == "Django": pkg_canonical = "Django"
                    if pkg_canonical == "Pillow": pkg_canonical = "Pillow"
                    
                    # Skip 'Secret' type packages from Code Security aggregation table?
                    # Or include them? User wants vuln table. Let's include secrets if they look like vulns.
                    if f.get('type') == 'SECRET':
                         pkg_canonical = "Secret Found"
                         cve = "Sensitive Data"
                         fixed_ver = "Revoke Key"

                    if pkg_norm not in aggregated:
                        aggregated[pkg_norm] = {
                            "package": pkg_canonical,
                            "cves": set(),
                            "fixed_versions": set(),
                            "current_versions": set(),
                            "max_severity": sev_score,
                            "raw_severity": raw_severity
                        }
                    
                    entry = aggregated[pkg_norm]
                    if cve: entry['cves'].add(cve)
                    if fixed_ver and fixed_ver != "Check Report": entry['fixed_versions'].add(fixed_ver)
                    if pkg_ver != "Unknown": entry['current_versions'].add(pkg_ver)
                    
                    if sev_score > entry['max_severity']:
                        entry['max_severity'] = sev_score
                        entry['raw_severity'] = raw_severity
                        
                except Exception as e:
                    continue

            # Convert Aggregated to List
            synthetic_remediation = []
            for pkg_norm, data in aggregated.items():
                cve_list = sorted(list(data['cves']))
                
                # Format CVE Column (Show ALL, line broken if needed in UI)
                cve_display = ", ".join(cve_list) if cve_list else "Vulnerability Detected"
                
                # Determine Recommendation (Max Version)
                rec_ver = "Check Report"
                link_url = ""
                
                if data['fixed_versions']:
                     try:
                         # Clean versions to sorting capability
                         sorted_vers = sorted(list(data['fixed_versions']), reverse=True)
                         rec_ver = sorted_vers[0]
                         
                         # Generate PyPI Link for Python packages (safe bet for requirements.txt)
                         # BUT skip if it is a Secret
                         if data['package'] != "Secret Found":
                             link_url = f"https://pypi.org/project/{data['package']}/{rec_ver}/"
                         else:
                             link_url = "" # No link for secrets, just text advice
                     except:
                         rec_ver = list(data['fixed_versions'])[0]
                
                # If we don't have a version link, try a CVE link
                if not link_url and cve_list and data['package'] != "Secret Found":
                    link_url = f"https://nvd.nist.gov/vuln/detail/{cve_list[0]}"

                current_ver_display = ", ".join(list(data['current_versions'])) if data['current_versions'] else "Unknown"

                action = f"Update to {rec_ver}"
                if data['package'] == "Secret Found":
                    action = "Revoke & Rotate Key"
                elif data['raw_severity'] == 'CRITICAL':
                    action += " immediately"
                
                synthetic_remediation.append({
                    "package": data['package'],
                    "cve": cve_display,
                    "current_version": current_ver_display, 
                    "fixed_version": rec_ver,
                    "action": action,
                    "link": link_url,
                    "severity": data['raw_severity']
                })

            # Sort by Severity Descending
            synthetic_remediation.sort(key=lambda x: severity_map.get(x['severity'], 0), reverse=True)
            ai_data['remediation'] = synthetic_remediation

            # Ensure summary exists from verdict
            if 'summary' not in ai_data:
                ai_data['summary'] = db_scan.verdict

            # Ensure summary exists
            if 'summary' not in ai_data:
                ai_data['summary'] = f"Scan complete. {len(report_findings)} vulnerabilities identified."

        # Update DB Record
        db_scan.status = ScanStatus.COMPLETED
        db_scan.risk_level = final_risk
        
        # Custom Verdict Logic for Code Security - SIMPLIFIED
        if secret_findings:
             db_scan.verdict = f"Scan complete. Secrets found in {len(secret_findings)} files."
        else:
             # Extract package names from remediation if available
             remediation_list = ai_data.get('remediation', [])
             if remediation_list:
                 pkgs = [f"{r.get('package', 'Unknown')} {r.get('current_version', '')}" for r in remediation_list[:3]]
                 rest_count = len(remediation_list) - 3
                 verdict_str = f"Scan complete. Vulnerable: {', '.join(pkgs)}"
                 if rest_count > 0:
                     verdict_str += f" and {rest_count} more."
                 db_scan.verdict = verdict_str
             elif report_findings:
                 db_scan.verdict = f"Scan complete. Found {len(report_findings)} vulnerabilities."
             else:
                 db_scan.verdict = "Scan complete. No vulnerabilities found."

        db_scan.findings = final_findings
        db_scan.content = json.dumps({"text": report, "filename": file.filename})
        
        # Save Cleaned AI Data
        if ai_data:
            db_scan.ai_analysis = json.dumps(ai_data)
        
        # Threat Score Calculation (Risk Score: 0=Safe, 100=Critical)
        ai_score = ai_data.get('score', 0)
        
        # Calculate Vulnerability Score from Structured Findings
        vuln_score = 0
        
        # Check Structured Findings
        # We look at 'severity' field in report_findings which we populated (defaults to HIGH for OSV)
        all_findings = report_findings + secret_findings
        
        severities = [f.get('severity', 'UNKNOWN').upper() for f in all_findings]
        
        if "CRITICAL" in severities:
            vuln_score = 95
        elif "HIGH" in severities:
            vuln_score = 80
        elif "MEDIUM" in severities:
            vuln_score = 50
        elif "LOW" in severities:
            vuln_score = 25
            
        # Legacy fallback if nothing found but report has keywords (just in case)
        if vuln_score == 0:
             if "CRITICAL" in report or "[CRITICAL]" in report: vuln_score = 95
             elif "HIGH" in report or "[HIGH]" in report: vuln_score = 80
        
        db_scan.threat_score = max(ai_score, vuln_score)
        
        db_scan.scan_duration_ms = ai_result.get('scan_duration_ms', 0) + 5
        db_scan.completed_at = datetime.utcnow()
        
        db.commit()
        db.refresh(db_scan)
        
        return {
            "id": db_scan.id,
            "verdict": db_scan.verdict,
            "risk_level": db_scan.risk_level,
            "threat_score": db_scan.threat_score,
            "summary": ai_data.get('reason', None) or ai_data.get('summary', "Analysis complete."),
            "report": report,
            "findings": db_scan.findings,
            "ai_analysis": ai_data,
            "created_at": db_scan.created_at.isoformat(),
            "scan_type": scan_type,
            "source": db_scan.source,
            "scan_duration_ms": db_scan.scan_duration_ms
        }

    except Exception as e:
        db_scan.status = ScanStatus.FAILED
        db_scan.verdict = f"ERROR: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
