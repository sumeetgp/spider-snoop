import logging
import math
import re
try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_anonymizer import AnonymizerEngine
except ImportError:
    AnalyzerEngine = None
    AnonymizerEngine = None
    PatternRecognizer = None
    Pattern = None

logger = logging.getLogger(__name__)

class PresidioEngine:
    """
    Enhanced Presidio wrapper with custom recognizers, entropy analysis, and active verification.
    """
    def __init__(self):
        if AnalyzerEngine:
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            # Explicitly configure to use the smaller, faster model downloaded in Dockerfile
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            self.anonymizer = AnonymizerEngine()
            self.enabled = True
            
            # Add custom recognizers for secrets not covered by default Presidio
            self._add_custom_recognizers()
        else:
            self.enabled = False
            logger.warning("Presidio dependencies not found. NER disabled.")

    def _add_custom_recognizers(self):
        """Adds custom regex patterns that Presidio lacks by default."""
        if not PatternRecognizer or not Pattern:
            return
        
        try:
            # 1. AWS Key ID (AKIA... / ASIA...)
            aws_id_pattern = Pattern(
                name="aws_id_pattern", 
                regex=r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', 
                score=1.0
            )
            aws_recognizer = PatternRecognizer(
                supported_entity="AWS_KEY_ID", 
                patterns=[aws_id_pattern]
            )
            self.analyzer.registry.add_recognizer(aws_recognizer)
            
            # 2. GitHub Token (ghp_... / github_pat_...)
            gh_pattern = Pattern(
                name="gh_token_pattern", 
                regex=r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b', 
                score=1.0
            )
            gh_recognizer = PatternRecognizer(
                supported_entity="GITHUB_TOKEN", 
                patterns=[gh_pattern]
            )
            self.analyzer.registry.add_recognizer(gh_recognizer)

            # 3. Private Key Header
            pk_pattern = Pattern(
                name="private_key_pattern", 
                regex=r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PRIVATE)?\s*PRIVATE\s+KEY-----', 
                score=1.0
            )
            pk_recognizer = PatternRecognizer(
                supported_entity="PRIVATE_KEY", 
                patterns=[pk_pattern],
                context=["private", "key", "rsa", "dsa", "openssh", "secret"]
            )
            self.analyzer.registry.add_recognizer(pk_recognizer)

            # 4. Slack Token (xoxb/xoxp/xoxa/xoxr/xoxs)
            slack_pattern = Pattern(
                name="slack_token_pattern",
                regex=r'\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b',
                score=1.0
            )
            slack_recognizer = PatternRecognizer(
                supported_entity="SLACK_TOKEN",
                patterns=[slack_pattern],
                context=["slack", "token", "bot", "oauth", "webhook", "api"]
            )
            self.analyzer.registry.add_recognizer(slack_recognizer)

            # 5. Google API Key (AIza...)
            google_pattern = Pattern(
                name="google_key_pattern",
                regex=r'\b(AIza[0-9A-Za-z\-_]{35})\b',
                score=1.0
            )
            google_recognizer = PatternRecognizer(
                supported_entity="GOOGLE_API_KEY",
                patterns=[google_pattern],
                context=["google", "gcp", "api", "key", "cloud", "auth"]
            )
            self.analyzer.registry.add_recognizer(google_recognizer)
            
            logger.info("Custom Presidio recognizers added: AWS_KEY_ID, GITHUB_TOKEN, PRIVATE_KEY, SLACK_TOKEN, GOOGLE_API_KEY")
        except Exception as e:
            logger.warning(f"Failed to add custom recognizers: {e}")

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon Entropy to detect random keys vs words.
        High entropy (>3.5) indicates random/cryptographic data.
        Low entropy (<3.5) indicates natural language or patterns.
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _active_verify_aws(self, key_id: str, context_text: str) -> str:
        """
        Active AWS credential verification via boto3 STS.
        Attempts to find the secret key in context and validate the pair.
        
        WARNING: This makes external API calls. Use sparingly.
        """
        # Try to find the Secret Key near the Key ID in the text
        # Look for 40-char base64-like string
        secret_match = re.search(r'[A-Za-z0-9/+=]{40}', context_text)
        if not secret_match:
            return "Unverified (Secret Key not found nearby)"
        
        secret = secret_match.group(0)
        
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            session = boto3.Session(
                aws_access_key_id=key_id, 
                aws_secret_access_key=secret
            )
            sts_client = session.client('sts')
            id_info = sts_client.get_caller_identity()
            
            return f"🚨 LIVE & CRITICAL! Account: {id_info['Account']}"
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['InvalidClientTokenId', 'SignatureDoesNotMatch']:
                return "Inactive/Revoked"
            return f"Unverified (AWS Error: {error_code})"
        except ImportError:
            return "Unverified (boto3 not installed)"
        except Exception as e:
            return f"Unverified (Connection Error: {str(e)[:50]})"

    def scan(self, text: str, active_verification: bool = False) -> list:
        """
        Enhanced scan with:
        - Custom recognizers (AWS, GitHub, Private Keys)
        - Entropy filtering for credentials
        - Optional active AWS verification
        
        Args:
            text: Content to scan
            active_verification: If True, attempts to verify AWS credentials (slow, makes API calls)
        
        Returns:
            List of findings with enhanced metadata
        """
        if not self.enabled:
            return []

        findings = []
        try:
            results = self.analyzer.analyze(text=text, language='en', score_threshold=0.4)
            
            for result in results:
                entity_val = text[result.start:result.end]
                
                # --- LEVEL 2: ENTROPY FILTERING ---
                # Skip low-entropy matches for credential types (reduces false positives)
                if result.entity_type in ["GITHUB_TOKEN", "AWS_KEY_ID", "PRIVATE_KEY", "GOOGLE_API_KEY"]:
                    entropy = self._calculate_entropy(entity_val)
                    if entropy < 3.5:
                        logger.debug(f"Skipping low-entropy {result.entity_type}: {entity_val[:10]}... (entropy: {entropy:.2f})")
                        continue
                
                # --- LEVEL 3: SEVERITY MAPPING ---
                severity = "LOW"
                if result.entity_type in ["AWS_KEY_ID", "GITHUB_TOKEN", "PRIVATE_KEY", "SLACK_TOKEN", "GOOGLE_API_KEY", "US_SSN", "CRYPTO"]:
                    severity = "CRITICAL"
                elif result.entity_type in ["CREDIT_CARD", "US_PASSPORT", "IBAN_CODE", "MEDICAL_LICENSE", "IP_ADDRESS"]:
                    severity = "HIGH"
                elif result.entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER"]:
                    severity = "HIGH"  # Upgraded from MEDIUM for GDPR/CCPA
                elif result.entity_type in ["PERSON", "LOCATION"]:
                    severity = "MEDIUM"
                
                finding = {
                    "type": result.entity_type.lower(),
                    "description": f"Presidio: {result.entity_type}",
                    "value": self._mask_value(entity_val),
                    "score": result.score,
                    "start": result.start,
                    "end": result.end,
                    "severity": severity
                }
                
                # --- LEVEL 4: ACTIVE VERIFICATION (Optional) ---
                if active_verification and result.entity_type == "AWS_KEY_ID":
                    # Extract context window to find secret key
                    context_window = text[result.start:min(len(text), result.end + 150)]
                    verification_result = self._active_verify_aws(entity_val, context_window)
                    finding["verification"] = verification_result
                    
                    # Upgrade severity if live credentials detected
                    if "LIVE & CRITICAL" in verification_result:
                        finding["severity"] = "CRITICAL"
                        finding["description"] += " (VERIFIED LIVE)"
                else:
                    finding["verification"] = "Not verified"
                
                findings.append(finding)
                
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
