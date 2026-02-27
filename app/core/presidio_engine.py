import collections
import logging
import math
import re
import time

from app.config import settings
from app.core.detection_metrics import metrics as _metrics
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
            # Explicitly configure to use the HuggingFace transformer pipeline for NER
            configuration = {
                "nlp_engine_name": "transformers",
                "models": [{"lang_code": "en", "model_name": {"spacy": "en_core_web_sm", "transformers": "dslim/bert-base-NER"}}],
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

    # ── Entropy constants ─────────────────────────────────────────────────────
    _ENTROPY_WINDOW    = 32
    _MIN_ENTROPY_LEN   = 16
    _ENTROPY_THRESHOLD = 3.5
    _COMMENT_PENALTY   = 4.2
    _BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
    _BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)

    def _calculate_entropy(self, data: str) -> float:
        """Shannon entropy using Counter (O(n))."""
        if not data:
            return 0.0
        counter = collections.Counter(data)
        length = len(data)
        return -sum(
            (c / length) * math.log(c / length, 2)
            for c in counter.values()
        )

    def _sliding_window_entropy(self, data: str) -> float:
        """Maximum entropy found in any sliding window of _ENTROPY_WINDOW chars."""
        w = self._ENTROPY_WINDOW
        if len(data) <= w:
            return self._calculate_entropy(data)
        return max(
            self._calculate_entropy(data[i:i + w])
            for i in range(len(data) - w + 1)
        )

    def _is_common_base64(self, value: str) -> bool:
        """True when value is base64 content that decodes to ordinary printable ASCII."""
        if not self._BASE64_RE.match(value):
            return False
        try:
            import base64 as _b64
            decoded = _b64.b64decode(value + '==').decode('utf-8', errors='strict')
            printable = sum(c.isprintable() and ord(c) < 128 for c in decoded)
            return printable / max(len(decoded), 1) > 0.85
        except Exception:
            return False

    def _in_code_comment(self, text: str, match_start: int) -> bool:
        """True when match_start falls inside a // # -- or /* */ comment."""
        line_start = text.rfind('\n', 0, match_start)
        line_start = 0 if line_start == -1 else line_start + 1
        prefix = text[line_start:match_start]
        if re.search(r'(?://|#\s*|--\s*)', prefix):
            return True
        for m in self._BLOCK_COMMENT_RE.finditer(text):
            if m.start() <= match_start < m.end():
                return True
        return False

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
            
            from botocore.config import Config
            session = boto3.Session(
                aws_access_key_id=key_id,
                aws_secret_access_key=secret
            )
            sts_client = session.client(
                'sts', config=Config(connect_timeout=5, read_timeout=5)
            )
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
            _t0 = time.monotonic()
            results = self.analyzer.analyze(text=text, language='en', score_threshold=settings.PRESIDIO_SCORE_THRESHOLD)
            _metrics.record_timing("presidio", (time.monotonic() - _t0) * 1000)

            for result in results:
                entity_val = text[result.start:result.end]
                etype_lower = result.entity_type.lower()
                masked = self._mask_value(entity_val)

                # Count every raw Presidio hit
                _metrics.inc_entity(etype_lower, "presidio", validated=False)

                # --- LEVEL 2: ENTROPY FILTERING ---
                if result.entity_type in ["GITHUB_TOKEN", "AWS_KEY_ID", "PRIVATE_KEY", "GOOGLE_API_KEY"]:
                    # Skip common base64-encoded plaintext
                    if self._is_common_base64(entity_val):
                        logger.debug(f"Skipping common-base64 {result.entity_type}: {entity_val[:10]}...")
                        _metrics.inc_rejection("entropy")
                        _metrics.log_fp_sample(
                            reason="entropy_rejection",
                            entity_type=etype_lower,
                            masked_value=masked,
                            context_snippet=text[max(0, result.start-80):result.end+80],
                            extra={"sub_reason": "common_base64", "source": "presidio"},
                        )
                        continue

                    # Only entropy-check strings long enough to be meaningful
                    if len(entity_val) >= self._MIN_ENTROPY_LEN:
                        entropy = self._sliding_window_entropy(entity_val)

                        # Raise threshold when match is inside a code comment
                        threshold = (
                            self._COMMENT_PENALTY
                            if self._in_code_comment(text, result.start)
                            else self._ENTROPY_THRESHOLD
                        )

                        if entropy < threshold:
                            logger.debug(f"Skipping low-entropy {result.entity_type}: {entity_val[:10]}... (entropy: {entropy:.2f}, threshold: {threshold})")
                            _metrics.inc_rejection("entropy")
                            _metrics.log_fp_sample(
                                reason="entropy_rejection",
                                entity_type=etype_lower,
                                masked_value=masked,
                                context_snippet=text[max(0, result.start-80):result.end+80],
                                extra={"entropy": round(entropy, 3), "threshold": threshold, "source": "presidio"},
                            )
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
                
                # --- LEVEL 4: ACTIVE VERIFICATION (Optional, gated by settings) ---
                if active_verification and result.entity_type == "AWS_KEY_ID" and settings.ENABLE_ACTIVE_AWS_VERIFICATION:
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
                
                # Passed all gates — count as validated
                _metrics.inc_entity(etype_lower, "presidio", validated=True)
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
            results = self.analyzer.analyze(text=text, language='en', score_threshold=settings.PRESIDIO_SCORE_THRESHOLD)

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
