
"""
Code Risk Classifier
Uses ML to distinguish between real code risks and safe patterns (tests, examples).

Loads a fine-tuned SetFit model from models/code_risk_classifier_finetuned/ if available,
otherwise falls back to zero-shot cosine similarity.
"""
import os
import logging
from typing import Dict, Any
from app.core.ml_engine import get_ml_engine

logger = logging.getLogger(__name__)

_FINETUNED_PATH = "models/code_risk_classifier_finetuned"
LABELS = ["REAL_SECRET", "VULNERABLE_LOGIC", "TEST_MOCK", "SAFE_CODE"]


def _load_finetuned():
    if not os.path.isdir(_FINETUNED_PATH):
        return None
    try:
        from setfit import SetFitModel
        model = SetFitModel.from_pretrained(f"./{_FINETUNED_PATH}")
        logger.info("CodeRiskClassifier: loaded fine-tuned SetFit model from %s", _FINETUNED_PATH)
        return model
    except Exception as e:
        logger.warning("CodeRiskClassifier: could not load fine-tuned model (%s) — falling back to zero-shot", e)
        return None


_finetuned_model = _load_finetuned()


class CodeRiskClassifier:
    def __init__(self):
        self.ml_engine = get_ml_engine()
        # Zero-shot label descriptions (fallback only)
        self.risk_labels = [
            "actionable production credential secret key",
            "vulnerable unsafe code execution exploit",
            "dummy example data placeholder for testing",
            "safe non-sensitive code documentation",
        ]
        self.label_map = {
            "actionable production credential secret key": "REAL_SECRET",
            "vulnerable unsafe code execution exploit":    "VULNERABLE_LOGIC",
            "dummy example data placeholder for testing":  "TEST_MOCK",
            "safe non-sensitive code documentation":       "SAFE_CODE",
        }

    def _action_for(self, risk_type: str) -> Dict[str, str]:
        if risk_type in ("REAL_SECRET", "VULNERABLE_LOGIC"):
            return {"action": "BLOCK", "severity": "CRITICAL"}
        return {"action": "ALLOW", "severity": "INFO"}

    def classify(self, issue_type: str, code_snippet: str) -> Dict[str, Any]:
        results = {"risk_type": "UNKNOWN", "confidence": 0.0, "action": "REVIEW"}

        try:
            text = f"Analyze this {issue_type}: {code_snippet}"

            if _finetuned_model is not None:
                probs = _finetuned_model.predict_proba([text])[0]
                idx = int(probs.argmax())
                risk_type = LABELS[idx]
                confidence = float(probs[idx])
            else:
                prediction = self.ml_engine.compute_similarity(text, self.risk_labels)
                risk_type = self.label_map.get(prediction["label"], "UNKNOWN")
                confidence = prediction["confidence"]

            results["risk_type"] = risk_type
            results["confidence"] = round(confidence, 4)
            results.update(self._action_for(risk_type))

        except Exception as e:
            logger.error("Code Risk classification failed: %s", e)
            results["error"] = str(e)

        return results
