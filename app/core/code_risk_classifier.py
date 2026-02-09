
"""
Code Risk Classifier
Uses ML to distinguish between real code risks and safe patterns (tests, examples).
"""
import logging
from typing import Dict, Any, List
from app.core.ml_engine import get_ml_engine

logger = logging.getLogger(__name__)

class CodeRiskClassifier:
    def __init__(self):
        self.ml_engine = get_ml_engine()
        self.risk_labels = [
            "actionable production credential secret key", 
            "vulnerable unsafe code execution exploit",
            "dummy example data placeholder for testing", 
            "safe non-sensitive code documentation",
            "secure patched implementation"
        ]
        
        self.label_map = {
            "actionable production credential secret key": "REAL_SECRET",
            "vulnerable unsafe code execution exploit": "VULNERABLE_LOGIC",
            "dummy example data placeholder for testing": "TEST_MOCK",
            "safe non-sensitive code documentation": "SAFE_CODE",
            "secure patched implementation": "SECURE_CODE"
        }

    def classify(self, issue_type: str, code_snippet: str) -> Dict[str, Any]:
        """
        Classifies the risk of a code snippet.
        """
        results = {
            "risk_type": "UNKNOWN",
            "confidence": 0.0,
            "action": "REVIEW"
        }
        
        try:
            # Construct analysis prompt
            # "Analyze this [Hardcoded Password]: [Snippet]"
            analysis_text = f"Analyze this {issue_type}: {code_snippet}"
            
            prediction = self.ml_engine.compute_similarity(analysis_text, self.risk_labels)
            
            label_desc = prediction["label"]
            score = prediction["confidence"]
            
            risk_type = self.label_map.get(label_desc, "UNKNOWN")
            results["risk_type"] = risk_type
            results["confidence"] = round(score, 4)
            
            # Smart Actions
            if risk_type in ["REAL_SECRET", "VULNERABLE_LOGIC"]:
                # Trust the relative ranking of the zero-shot model
                # If it picked REAL_SECRET over TEST_MOCK, it's a block.
                results["action"] = "BLOCK"
                results["severity"] = "CRITICAL"
                
            elif risk_type in ["TEST_MOCK", "SAFE_CODE", "SECURE_CODE"]:
                results["action"] = "ALLOW"
                results["severity"] = "INFO"
                
        except Exception as e:
            logger.error(f"Code Risk classification failed: {e}")
            results["error"] = str(e)
            
        return results
