
"""
Code Scanner
Orchestrator for Path 3: Intelligent Code Security.
Combines Secret Scanning (DLP), Vulnerability Patterns (Regex), and AI Verification (CodeBERT).
"""
import logging
import re
import os
from typing import Dict, Any, List

# Components
from app.core.dlp_patterns import DLPPatternMatcher
from app.core.code_risk_classifier import CodeRiskClassifier
from app.core.remediation_engine import RemediationEngine

logger = logging.getLogger(__name__)

class CodeScanner:
    def __init__(self):
        self.secret_scanner = DLPPatternMatcher()
        self.risk_classifier = CodeRiskClassifier()
        self.remediation_engine = RemediationEngine()
        
        # Simple Regex Patterns for Common Vulnerabilities (Simulating Semgrep/Trivy)
        self.vuln_patterns = {
            "python_eval": {
                "pattern": r'\beval\s*\(',
                "description": "Dangerous Eval Function",
                "type": "Code Injection"
            },
            "python_exec": {
                "pattern": r'\bexec\s*\(',
                "description": "Dangerous Exec Function",
                "type": "Code Injection"
            },
            "python_pickle": {
                "pattern": r'\bpickle\.load\s*\(',
                "description": "Insecure Deserialization",
                "type": "Insecure Deserialization"
            },
            "python_shell_true": {
                "pattern": r'subprocess\..*shell\s*=\s*True',
                "description": "Command Injection Risk",
                "type": "Command Injection"
            },
            "js_innerhtml": {
                "pattern": r'\.innerHTML\s*=',
                "description": "Potential XSS (innerHTML)",
                "type": "Cross Site Scripting"
            }
        }

    async def scan_file(self, file_path: str, content: str = None) -> Dict[str, Any]:
        """
        Scans a code file for secrets and vulnerabilities.
        """
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                return {"error": str(e)}

        findings = []
        
        # 1. Scan for Secrets (using DLP Pattern Matcher in Secrets Mode)
        # Note: DLP Matcher returns dictionary by severity. We flatten it.
        dlp_results = self.secret_scanner.scan(content, secrets_only=True)
        for severity, items in dlp_results.items():
            for item in items:
                # Enrich with AI
                description = item.get("description", "Potential Secret")
                context = item.get("context", "") # DLP Matcher now provides context
                
                # If no context in item (legacy matcher?), slice it
                if not context:
                    # quick slice if not present (though we updated DLP wrapper)
                    # finding position is "char X-Y"
                    pass 
                
                ai_verdict = self.risk_classifier.classify(description, context)
                
                findings.append({
                    "category": "SECRET",
                    "type": item["type"],
                    "description": description,
                    "severity": severity, # Base severity
                    "ai_risk": ai_verdict["risk_type"],
                    "ai_confidence": ai_verdict["confidence"],
                    "action": ai_verdict["action"],
                    "remediation": self.remediation_engine.get_remediation(item["type"])
                })

        # 2. Scan for Vulnerabilities (Regex)
        for vuln_id, v_info in self.vuln_patterns.items():
             for match in re.finditer(v_info["pattern"], content):
                # Extract context
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)
                context_snippet = content[start:end]
                
                ai_verdict = self.risk_classifier.classify(v_info["description"], context_snippet)
                
                findings.append({
                    "category": "VULNERABILITY",
                    "type": v_info["type"],
                    "description": v_info["description"],
                    "severity": "HIGH",
                    "ai_risk": ai_verdict["risk_type"],
                    "ai_confidence": ai_verdict["confidence"],
                    "action": ai_verdict["action"],
                    "remediation": self.remediation_engine.get_remediation(v_info["type"])
                })

        return {
            "file": file_path,
            "total_findings": len(findings),
            "findings": findings
        }

# Global
_code_scanner = None
def get_code_scanner():
    global _code_scanner
    if _code_scanner is None:
        _code_scanner = CodeScanner()
    return _code_scanner
