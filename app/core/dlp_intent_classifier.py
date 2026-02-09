
"""
DLP Intent Classifier
Classifies the context of a DLP finding to distinguish Real PII from Test/Mock data.
"""
import logging
from typing import Dict, Any, List
from app.core.ml_engine import get_ml_engine

logger = logging.getLogger(__name__)

class DLPIntentClassifier:
    def __init__(self):
        self.ml_engine = get_ml_engine()
        self.intent_labels = [
            "production secret credential real pii", 
            "test data placeholder example mock", 
            "documentation tutorial comment code example",
            "false positive random string gibberish"
        ]
        
        self.label_map = {
            "production secret credential real pii": "REAL_DATA",
            "test data placeholder example mock": "TEST_DATA",
            "documentation tutorial comment code example": "DOCUMENTATION",
            "false positive random string gibberish": "NOISE"
        }

    def classify(self, finding_type: str, context_text: str) -> Dict[str, Any]:
        """
        Classifies the intent based on context.
        """
        results = {
            "intent": "UNKNOWN",
            "confidence": 0.0,
            "action": "REVIEW"
        }
        
        try:
            # Construct a prompt-like string for the semantic model
            # "Context surrounding a [AWS Key]: [Code Snippet...]"
            analysis_text = f"Context surrounding a {finding_type}: {context_text}"
            
            prediction = self.ml_engine.compute_similarity(analysis_text, self.intent_labels)
            
            label_desc = prediction["label"]
            score = prediction["confidence"]
            
            intent = self.label_map.get(label_desc, "UNKNOWN")
            results["intent"] = intent
            results["confidence"] = round(score, 4)
            
            # Smart Actions
            if intent == "REAL_DATA":
                results["action"] = "BLOCK" if score > 0.7 else "REVIEW"
            elif intent == "TEST_DATA":
                results["action"] = "ALLOW" if score > 0.8 else "REVIEW"
            elif intent == "DOCUMENTATION":
                results["action"] = "ALLOW"
            elif intent == "NOISE":
                 results["action"] = "IGNORE"
                
        except Exception as e:
            logger.error(f"DLP Intent classification failed: {e}")
            results["error"] = str(e)
            
        return results
