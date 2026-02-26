
"""
File Security Engine
Orchestrator for Path 1: Deterministic File & Malware Scanner.
Combines Signatures (ClamAV/YARA), Static Heuristics, and ML Context.
"""
import asyncio
import logging
import os
import shutil
from typing import Dict, Any, Tuple

# Components
from app.core.file_guard import FileGuard
from app.core.metadata_extractor import MetadataExtractor
from app.core.static_analyzer import StaticAnalyzer
from app.core.context_classifier import ContextClassifier

logger = logging.getLogger(__name__)

class FileSecurityEngine:
    def __init__(self):
        self.file_guard = FileGuard(rules_path="rules") 
        self.metadata_extractor = MetadataExtractor()
        self.static_analyzer = StaticAnalyzer()
        self.context_classifier = ContextClassifier()

    async def scan(self, file_path: str, extracted_text: str = "") -> Dict[str, Any]:
        """
        Main scanning pipeline.
        Returns a structured verdict.
        """
        logger.info(f"Starting File Security Scan for: {file_path}")
        
        # 1. Foundation: Signatures (ClamAV / YARA)
        is_clean_sig, findings_sig = await asyncio.wait_for(
            self.file_guard.scan_file(file_path), timeout=30.0
        )

        # 2. Metadata & Static Analysis (run in thread pool to avoid blocking the event loop)
        metadata = await asyncio.to_thread(self.metadata_extractor.extract, file_path)
        static_analysis = await asyncio.to_thread(self.static_analyzer.analyze, file_path)

        # 3. ML Context Analysis
        # Enriched with metadata and static signals
        # We append static findings to the context text for the ML model
        # e.g. "Entropy: 7.8 (Packed). Magic Mismatch: True."

        enrichment_str = ""
        if static_analysis.get("is_packed"): enrichment_str += "High Entropy Packed File. "
        if not static_analysis.get("magic_match"): enrichment_str += "File extension does not match content. "

        final_context_text = f"{enrichment_str} {extracted_text}"[:4096]
        
        ml_result = self.context_classifier.classify(metadata, final_context_text)
        
        # 4. Policy & Verdict Logic
        verdict, remediation, evidence = self._apply_policy(
            is_clean_sig, 
            findings_sig, 
            static_analysis, 
            ml_result
        )
        
        return {
            "verdict": verdict,
            "remediation": remediation,
            "evidence": {
                **evidence,
                "metadata": metadata,
                "static_analysis": static_analysis,
                "ml_context": ml_result
            }
        }

    def _apply_policy(
        self, 
        is_clean_sig: bool, 
        findings_sig: list, 
        static: Dict, 
        ml: Dict
    ) -> Tuple[str, str, Dict]:
        """
        Core Policy Logic: Zero-Trust & Deterministic
        """
        evidence_signals = []
        
        # Priority 1: Signatures (Known Bad)
        if not is_clean_sig:
            return "MALICIOUS", "BLOCK", {"reason": "Signature Match", "signals": findings_sig}
            
        # Priority 2: Static Heuristics (Highly Suspicious)
        # e.g. Magic Mismatch + High Entropy -> Block/Review
        if not static.get("magic_match") and static.get("is_packed"):
            return "MALICIOUS", "BLOCK", {"reason": "Evasion Detected (Packed + Mismatch)", "signals": ["magic_mismatch", "packed"]}

        # Priority 3: ML Context + Signals
        # If ML is confident it's bad (> 0.7) OR static signals overlap
        ml_conf = ml.get("confidence", 0.0)
        ml_verdict = ml.get("ml_verdict", "UNCERTAIN")
        
        if ml_verdict == "SUSPICIOUS" and ml_conf >= 0.70:
            return "SUSPICIOUS", "QUARANTINE", {"reason": "High Confidence ML Threat", "signals": [ml.get("threat_family")]}
            
        # Weak Signals (Log only)
        if ml_verdict == "SUSPICIOUS" and ml_conf > 0.50:
             return "UNCERTAIN", "LOG_ONLY", {"reason": "Low Confidence ML Signal", "signals": [ml.get("threat_family")]}

        # Default
        return "CLEAN", "ALLOW", {"reason": "No Threats Detected", "signals": []}

# Global Instance
_engine = None
def get_file_security_engine():
    global _engine
    if _engine is None:
        _engine = FileSecurityEngine()
    return _engine
