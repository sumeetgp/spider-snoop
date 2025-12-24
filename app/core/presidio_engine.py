import logging
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
except ImportError:
    AnalyzerEngine = None
    AnonymizerEngine = None

logger = logging.getLogger(__name__)

class PresidioEngine:
    """
    Wrapper for Microsoft Presidio NER capabilities.
    """
    def __init__(self):
        if AnalyzerEngine:
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
            self.enabled = True
        else:
            self.enabled = False
            logger.warning("Presidio dependencies not found. NER disabled.")

    def scan(self, text: str) -> list:
        """
        Scan text for PII using Presidio NER.
        Returns a list of findings in the internal format.
        """
        if not self.enabled:
            return []

        findings = []
        try:
            results = self.analyzer.analyze(text=text, language='en', score_threshold=0.4)
            
            for result in results:
                # Map Presidio types to our types/severity
                severity = "LOW"
                if result.entity_type in ["CREDIT_CARD", "US_SSN", "US_PASSPORT", "CRYPTO"]:
                    severity = "CRITICAL"
                elif result.entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "MEDICAL_LICENSE"]:
                    severity = "HIGH"
                elif result.entity_type in ["PERSON", "LOCATION", "IP_ADDRESS"]:
                    severity = "MEDIUM"
                
                # Extract value
                value = text[result.start:result.end]
                
                findings.append({
                    "type": result.entity_type.lower(),
                    "description": f"Presidio: {result.entity_type}",
                    "value": self._mask_value(value),
                    "score": result.score,
                    "start": result.start,
                    "end": result.end,
                    "severity": severity
                })
        except Exception as e:
            logger.error(f"Presidio scan failed: {e}")

        return findings

    def _mask_value(self, value: str) -> str:
        if len(value) <= 4: return "***"
        return f"{value[:2]}...{value[-2:]}"

    def redact(self, text: str) -> str:
        """
        Redact PII from text using Presidio Anonymizer.
        """
        if not self.enabled:
            return text
            
        try:
            # Analyze first
            results = self.analyzer.analyze(text=text, language='en', score_threshold=0.4)
            
            # Define operators (default to 'replace')
            # We can customize this to use generic replacements like <PASSPORT>
            
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=results
            )
            
            return anonymized_result.text
            
        except Exception as e:
            logger.error(f"Presidio redaction failed: {e}")
            return text
