
"""
DLP Engine
Orchestrator for Path 2: Context-Aware DLP Scanner.
Combines Regex Patterns, ML Intent Classification, and Risk Correlation.
"""
import logging
from typing import Dict, Any, List, Set
from app.core.dlp_patterns import DLPPatternMatcher
from app.core.dlp_intent_classifier import DLPIntentClassifier

logger = logging.getLogger(__name__)

class DLPEngine:
    def __init__(self):
        self.pattern_matcher = DLPPatternMatcher()
        self.intent_classifier = DLPIntentClassifier()

    def scan(self, text: str) -> Dict[str, Any]:
        """
        Main DLP Scan Pipeline.
        """
        # 1. Pattern Matching (with Context Extraction)
        # We ask for all findings flat first
        raw_results = self.pattern_matcher.scan(text)
        
        # Flatten findings from severity buckets for processing
        all_findings = []
        for severity, findings in raw_results.items():
            all_findings.extend(findings)

        enriched_findings = []
        unique_types = set()
        
        # 2. ML Intent Classification
        for finding in all_findings:
            # Classify Intent based on context
            context = finding.get("context", "")
            intent_res = self.intent_classifier.classify(finding["type"], context)
            
            finding["intent"] = intent_res["intent"]
            finding["intent_score"] = intent_res["confidence"]
            finding["action"] = intent_res["action"] # ALLOW / BLOCK / REVIEW
            
            # Update severity based on Intent
            # If it's TEST_DATA or DOCUMENTATION, downgrade severity
            if finding["intent"] in ["TEST_DATA", "DOCUMENTATION", "NOISE"]:
                finding["severity"] = "INFO"
                finding["action"] = "ALLOW"
            
            enriched_findings.append(finding)
            if finding["severity"] in ["CRITICAL", "HIGH"]:
                unique_types.add(finding["type"])

        # 3. Correlation Engine (Risk Escalation)
        # If we see 3+ distinct HIGH/CRITICAL PII types, escalate entire risk
        correlation_risk = "LOW"
        if len(unique_types) >= 3:
            correlation_risk = "CRITICAL"
        elif len(unique_types) >= 2:
             correlation_risk = "HIGH"
             
        # 4. Construct Final Report
        report = {
            "summary": {
                "total_findings": len(enriched_findings),
                "unique_types": list(unique_types),
                "correlation_risk": correlation_risk
            },
            "findings": enriched_findings
        }
        
        return report

    def smart_redact(self, text: str) -> str:
        """
        Redacts REAL PII, but leaves Test/Mock data alone.
        """
        scan_report = self.scan(text)
        findings = scan_report["findings"]
        
        # Sort by start pos descending to replace without offsetting indices
        findings.sort(key=lambda x: int(x["position"].split(" ")[1].split("-")[0]), reverse=True)
        
        redacted_text = text
        
        for f in findings:
            if f["action"] == "ALLOW":
                continue # Skip redaction for allowed/test data
                
            # Parse position "char start-end"
            try:
                pos_str = f["position"].replace("char ", "")
                start, end = map(int, pos_str.split("-"))
                
                # Perform replacement
                original = f["context"] # wait, context is wider. We need exact match pos.
                # finding has exact value but masking might have happened in pattern matcher?
                # Actually DLPPatternMatcher.scan returns masked value in 'value'.
                # But it provides 'position' so we can slice valid ranges.
                
                replacement = f"[REDACTED: {f['type'].upper()}]"
                
                # String slicing replacement
                redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
                
            except Exception as e:
                logger.warning(f"Redaction failed for finding {f}: {e}")
                
        return redacted_text
