
"""
Context Classifier for File Security
Enriches file analysis with ML-based context and Threat Family classification.
"""
import logging
from typing import Dict, Any, List
from app.core.ml_engine import get_ml_engine

logger = logging.getLogger(__name__)

class ContextClassifier:
    def __init__(self):
        self.ml_engine = get_ml_engine()
        self.threat_labels = [
            "ransomware encrypted file with payment demand", 
            "banking trojan stealing financial credentials", 
            "remote access trojan backdoor control",
            "safe business document financial report", 
            "benign software installer executable",
            "normal text file readme"
        ]
        
        # Map descriptive labels back to short codes
        self.label_map = {
            "ransomware encrypted file with payment demand": "RANSOMWARE",
            "banking trojan stealing financial credentials": "BANKING_TROJAN",
            "remote access trojan backdoor control": "BACKDOOR",
            "safe business document financial report": "BENIGN_DOC",
            "benign software installer executable": "BENIGN_EXE",
            "normal text file readme": "BENIGN_TXT"
        }

    def classify(self, metadata: Dict[str, Any], extracted_text: str = "") -> Dict[str, Any]:
        """
        Classifies file based on metadata and text content.
        """
        results = {
            "threat_family": "UNKNOWN",
            "confidence": 0.0,
            "ml_verdict": "UNCERTAIN"
        }
        
        # Construct Context String for ML
        # Combine filenames, author info, and snippets of text
        context_str = f"Filename: {metadata.get('file_name', '')}. "
        if 'title' in metadata: context_str += f"Title: {metadata['title']}. "
        if 'author' in metadata: context_str += f"Author: {metadata['author']}. "
        if extracted_text: context_str += f"Content: {extracted_text[:512]}" # Truncate for speed
        
        try:
            # Zero-Shot Classification
            prediction = self.ml_engine.compute_similarity(context_str, self.threat_labels)
            
            label_desc = prediction["label"]
            score = prediction["confidence"]
            
            results["threat_family"] = self.label_map.get(label_desc, "UNKNOWN")
            results["confidence"] = round(score, 4)
            
            # Simple ML Verdict based on benign/malicious check
            if "benign" in label_desc or "safe" in label_desc:
                results["ml_verdict"] = "CLEAN"
            else:
                results["ml_verdict"] = "SUSPICIOUS"
                
        except Exception as e:
            logger.error(f"Context classification failed: {e}")
            results["error"] = str(e)
            
        return results
