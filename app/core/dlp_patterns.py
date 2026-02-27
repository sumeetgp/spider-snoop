import base64
import collections
import json
import re
import math
import time
from typing import Dict, List

from app.core.detection_metrics import metrics as _metrics

# ── Entropy check constants ───────────────────────────────────────────────────
_ENTROPY_WINDOW    = 32   # Sliding window width (chars) — spec: 20–40
_MIN_ENTROPY_LEN   = 16   # Don't entropy-check strings shorter than this
_ENTROPY_THRESHOLD = 3.5  # Below this → likely not a secret
_COMMENT_PENALTY   = 4.2  # Raise threshold to this when match is inside a comment

# Pure base64 alphabet (no spaces/newlines) — used to detect encoded plaintext
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
# Block comment detector (/* ... */)
_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)

class DLPPatternMatcher:
    """Enhanced DLP Pattern Matcher with comprehensive PII and sensitive data detection"""
    
    def __init__(self):
        # Define all patterns with metadata
        self.patterns = {
            # Financial Data
            "credit_card": {
                "pattern": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                "severity": "CRITICAL",
                "description": "Credit Card Number",
                "validator": self._validate_credit_card  # Luhn + length + BIN prefix
            },
            "ssn": {
                "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
                "severity": "CRITICAL",
                "description": "Social Security Number",
                "validator": self._validate_ssn  # rejects 000/666/9xx, all-same digits
            },
            "bank_account": {
                "pattern": r'\b\d{8,17}\b',
                "severity": "HIGH",
                "description": "Bank Account Number"
            },
            "iban": {
                "pattern": r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
                "severity": "HIGH",
                "description": "IBAN Number"
            },
            "routing_number": {
                "pattern": r'\b\d{9}\b',
                "severity": "HIGH",
                "description": "Bank Routing Number"
            },
            
            # Personal Identifiers
            "email": {
                "pattern": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                "severity": "MEDIUM",
                "description": "Email Address"
            },
            "phone_us": {
                "pattern": r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
                "severity": "MEDIUM",
                "description": "US Phone Number"
            },
            "passport": {
                "pattern": r'\b[A-Z]{1,2}\d{6,9}\b',
                "severity": "CRITICAL",
                "description": "Passport Number"
            },
            "drivers_license": {
                "pattern": r'\b[A-Z]{1,2}\d{5,8}\b',
                "severity": "HIGH",
                "description": "Driver's License"
            },
            "medical_record": {
                "pattern": r'\b(?:MRN|MR#|Medical Record(?:\s+(?:No|Number|#))?|Patient\s+(?:ID|#|Account)|Pt\.?\s+(?:ID|#))[\s:#-]*(\d{6,12})\b',
                "severity": "CRITICAL",
                "description": "Medical Record / Patient ID"
            },

            # Medical / Healthcare (HIPAA)
            "npi_number": {
                "pattern": r'\b(?:NPI|National Provider(?:\s+Identifier)?)[\s:#-]*(\d{10})\b',
                "severity": "HIGH",
                "description": "National Provider Identifier (NPI)",
                "context_keywords": ["npi", "provider", "physician", "prescriber", "clinic", "hospital"],
            },
            "icd10_code": {
                "pattern": r'\b[A-Z]\d{2}(?:\.\d{1,4})?\b',
                "severity": "HIGH",
                "description": "ICD-10 Diagnosis Code",
                "context_keywords": ["diagnosis", "icd", "icd-10", "icd10", "dx", "condition", "disease", "disorder", "admit", "discharge", "principal"],
                "requires_context_keywords": True,
            },
            "dea_number": {
                "pattern": r'\b[A-Z]{2}\d{7}\b',
                "severity": "HIGH",
                "description": "DEA Registration Number",
                "context_keywords": ["dea", "drug enforcement", "schedule", "controlled", "prescriber", "prescription", "registrant"],
                "requires_context_keywords": True,
            },
            "ndc_code": {
                "pattern": r'\b\d{4,5}-\d{3,4}-\d{1,2}\b',
                "severity": "MEDIUM",
                "description": "National Drug Code (NDC)",
                "context_keywords": ["ndc", "drug", "medication", "pharmacy", "rx", "prescription", "dispensed", "dose", "tablet", "capsule"],
                "requires_context_keywords": True,
            },
            
            # Network & Infrastructure
            "ipv4": {
                "pattern": r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                "severity": "LOW",
                "description": "IPv4 Address"
            },
            "ipv6": {
                "pattern": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
                "severity": "LOW",
                "description": "IPv6 Address"
            },
            "mac_address": {
                "pattern": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
                "severity": "MEDIUM",
                "description": "MAC Address"
            },
            
            # API Keys & Secrets
            "aws_access_key": {
                "pattern": r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b',
                "severity": "CRITICAL",
                "description": "AWS Access Key ID",
                "context_keywords": ["aws", "access_key", "secret", "boto", "credentials", "amazon"]
            },
            "aws_secret_key": {
                "pattern": r'\b[A-Za-z0-9/+=]{40}\b',
                "severity": "CRITICAL",
                "description": "AWS Secret Access Key"
            },
            "github_token": {
                "pattern": r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b',
                "severity": "CRITICAL",
                "description": "GitHub Personal Access Token"
            },
            "generic_api_key": {
                "pattern": r'\b(?:api[_-]?key|apikey)[\s=:]+["\']?([a-zA-Z0-9_\-]{20,})["\']?\b',
                "severity": "CRITICAL",
                "description": "Generic API Key"
            },
            "slack_api_token": {
                "pattern": r'\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b',
                "severity": "CRITICAL",
                "description": "Slack API Token"
            },
            "slack_webhook": {
                "pattern": r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                "severity": "CRITICAL",
                "description": "Slack Webhook URL"
            },
            "google_api_key": {
                "pattern": r'\b(AIza[0-9A-Za-z_-]{35})\b',
                "severity": "CRITICAL",
                "description": "Google API Key"
            },
            "aws_session_token": {
                "pattern": r'\b(FQoGZXRfYXJj[a-zA-Z0-9/+=]{20,})\b',
                "severity": "HIGH",
                "description": "AWS Session Token (Base64)"
            },
            "bearer_token": {
                "pattern": r'\bBearer\s+([a-zA-Z0-9\-._~+/]+=*)\b',
                "severity": "CRITICAL",
                "description": "Bearer Token"
            },
            "jwt_token": {
                "pattern": r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b',
                "severity": "HIGH",
                "description": "JWT Token",
                "validator": self._validate_jwt  # base64 decode + JSON header check
            },
            
            # Cryptographic Materials
            "private_key": {
                "pattern": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
                "severity": "CRITICAL",
                "description": "Private Key (PEM format)"
            },
            "ssh_private_key": {
                "pattern": r'-----BEGIN OPENSSH PRIVATE KEY-----',
                "severity": "CRITICAL",
                "description": "SSH Private Key"
            },
            "pgp_private_key": {
                "pattern": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                "severity": "CRITICAL",
                "description": "PGP Private Key"
            },
            
            # Database Credentials
            "db_connection_string": {
                "pattern": r'(?:postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[\w.-]+(?::\d+)?/[\w-]+',
                "severity": "CRITICAL",
                "description": "Database Connection String with Credentials"
            },
            "password_in_code": {
                "pattern": r'(?:password|passwd|pwd)[\s=:]+["\']([^"\']{4,})["\']',
                "severity": "HIGH",
                "description": "Hardcoded Password"
            },
            
            # Date of Birth
            "dob": {
                "pattern": r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b',
                "severity": "MEDIUM",
                "description": "Date of Birth (MM/DD/YYYY)"
            },
            
            # Cryptocurrency
            "bitcoin_address": {
                "pattern": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                "severity": "MEDIUM",
                "description": "Bitcoin Address"
            },
            "ethereum_address": {
                "pattern": r'\b0x[a-fA-F0-9]{40}\b',
                "severity": "MEDIUM",
                "description": "Ethereum Address"
            },

            # ── Cloud & SaaS API Keys ──────────────────────────────────────────

            "stripe_secret_key": {
                "pattern": r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b',
                "severity": "CRITICAL",
                "description": "Stripe Secret API Key",
                "context_keywords": ["stripe", "payment", "billing", "charge", "invoice", "secret"],
            },
            "stripe_publishable_key": {
                "pattern": r'\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b',
                "severity": "HIGH",
                "description": "Stripe Publishable Key",
                "context_keywords": ["stripe", "payment", "billing", "publishable"],
            },
            "stripe_restricted_key": {
                "pattern": r'\b(rk_(?:live|test)_[0-9a-zA-Z]{24,})\b',
                "severity": "CRITICAL",
                "description": "Stripe Restricted Key",
                "context_keywords": ["stripe", "restricted"],
            },
            "twilio_account_sid": {
                "pattern": r'\b(AC[a-f0-9]{32})\b',
                "severity": "HIGH",
                "description": "Twilio Account SID",
                "context_keywords": ["twilio", "account_sid", "accountsid", "sms", "call"],
            },
            "twilio_auth_token": {
                "pattern": r'\b(?:twilio[_\s]?auth[_\s]?token|authtoken)[\s=:\"\']+([a-f0-9]{32})\b',
                "severity": "CRITICAL",
                "description": "Twilio Auth Token",
                "context_keywords": ["twilio", "auth_token", "authtoken"],
                "requires_context_keywords": True,
            },
            "sendgrid_api_key": {
                "pattern": r'\b(SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,})\b',
                "severity": "CRITICAL",
                "description": "SendGrid API Key",
            },
            "mailgun_api_key": {
                "pattern": r'\b(key-[a-f0-9]{32})\b',
                "severity": "CRITICAL",
                "description": "Mailgun API Key",
                "context_keywords": ["mailgun", "api_key", "apikey", "mg.", "smtp"],
                "requires_context_keywords": True,
            },
            "huggingface_token": {
                "pattern": r'\b(hf_[a-zA-Z0-9]{37,})\b',
                "severity": "HIGH",
                "description": "HuggingFace Access Token",
            },
            "npm_access_token": {
                "pattern": r'\b(npm_[a-zA-Z0-9]{36,})\b',
                "severity": "HIGH",
                "description": "NPM Access Token",
            },
            "cloudflare_api_token": {
                "pattern": r'\b(cf_[a-zA-Z0-9]{37,}|[A-Za-z0-9_-]{40})\b',
                "severity": "HIGH",
                "description": "Cloudflare API Token",
                "context_keywords": ["cloudflare", "cf_token", "cf_key", "x-auth-key", "x-auth-email"],
                "requires_context_keywords": True,
            },
            "azure_sas_token": {
                "pattern": r'\b(?:SharedAccessSignature|sig=[a-zA-Z0-9%+/]{20,}[&;])',
                "severity": "CRITICAL",
                "description": "Azure SAS Token",
                "context_keywords": ["azure", "blob", "queue", "table", "servicebus", "sas", "sig="],
            },
            "azure_connection_string": {
                "pattern": r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{64,}',
                "severity": "CRITICAL",
                "description": "Azure Storage Connection String",
            },

            # ── Docker / Container Credentials ────────────────────────────────
            "docker_registry_auth": {
                "pattern": r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
                "severity": "CRITICAL",
                "description": "Docker Registry Auth (base64 credentials)",
                "context_keywords": ["docker", "registry", "auths", "dockerconfigjson"],
                "requires_context_keywords": True,
            },

            # ── Webhook / Notification Tokens ─────────────────────────────────
            "discord_webhook": {
                "pattern": r'https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[a-zA-Z0-9_-]{60,}',
                "severity": "HIGH",
                "description": "Discord Webhook URL",
            },
            "telegram_bot_token": {
                "pattern": r'\b(\d{8,10}:[a-zA-Z0-9_-]{35})\b',
                "severity": "CRITICAL",
                "description": "Telegram Bot Token",
                "context_keywords": ["telegram", "bot", "botfather", "sendmessage"],
                "requires_context_keywords": True,
            },
            "pagerduty_key": {
                "pattern": r'\b([a-z0-9+]{20})\b',
                "severity": "HIGH",
                "description": "PagerDuty Integration Key",
                "context_keywords": ["pagerduty", "routing_key", "integration_key", "service_key"],
                "requires_context_keywords": True,
            },

            # ── Additional Crypto Keys ─────────────────────────────────────────
            "ed25519_private_key": {
                "pattern": r'-----BEGIN (?:ED25519 )?PRIVATE KEY-----',
                "severity": "CRITICAL",
                "description": "Ed25519 Private Key",
            },
            "ecdsa_private_key": {
                "pattern": r'-----BEGIN EC PRIVATE KEY-----',
                "severity": "CRITICAL",
                "description": "ECDSA Private Key",
            },
            "certificate": {
                "pattern": r'-----BEGIN CERTIFICATE-----',
                "severity": "MEDIUM",
                "description": "X.509 Certificate (may contain sensitive details)",
            },
        }
        
        # Sensitive keywords (expanded)
        self.sensitive_keywords = {
            "CRITICAL": [
                "confidential", "top secret", "classified", "secret clearance",
                "private key", "master password", "root password", "admin password"
            ],
            "HIGH": [
                "internal use only", "not for distribution", "proprietary",
                "trade secret", "sensitive data", "do not share"
            ],
            "MEDIUM": [
                "password", "credential", "authentication", "authorization",
                "token", "secret", "private"
            ]
        }
    
    def _validate_luhn(self, number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        digits = [int(d) for d in re.sub(r'\D', '', number)]
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card: length (13-19 digits) + BIN prefix + Luhn."""
        d = re.sub(r'\D', '', number)
        if not (13 <= len(d) <= 19):
            return False
        # BIN prefix check — major networks only
        valid_prefix = (
            d[0] == '4'                                              # Visa
            or d[:2] in ('34', '37')                                 # Amex
            or (len(d) >= 2 and 51 <= int(d[:2]) <= 55)             # Mastercard classic
            or (len(d) >= 4 and 2221 <= int(d[:4]) <= 2720)         # Mastercard 2-series
            or d[:4] == '6011' or d[:2] in ('64', '65')             # Discover
            or (len(d) >= 3 and 300 <= int(d[:3]) <= 305)           # Diners Club
            or d[:2] in ('36', '38')                                 # Diners Club intl
            or (len(d) >= 4 and 3528 <= int(d[:4]) <= 3589)         # JCB
        )
        return valid_prefix and self._validate_luhn(number)

    def _validate_ssn(self, ssn: str) -> bool:
        """Validate SSN: reject known-invalid area/group/serial and repeated patterns."""
        digits = re.sub(r'\D', '', ssn)
        if len(digits) != 9:
            return False
        area   = int(digits[:3])
        group  = int(digits[3:5])
        serial = int(digits[5:])
        # FICA rules: 000, 666, and 900-999 area numbers are never assigned
        if area == 0 or area == 666 or area >= 900:
            return False
        # Group and serial all-zeros are invalid
        if group == 0 or serial == 0:
            return False
        # Reject trivially fake patterns: all same digit or sequential
        if len(set(digits)) == 1:
            return False
        if digits == '123456789':
            return False
        return True

    def _validate_jwt(self, token: str) -> bool:
        """Validate JWT: must have 3 dot-separated parts and a decodeable JSON header."""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        try:
            # URL-safe base64 — restore padding
            padded = parts[0] + '=' * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(padded))
            # A real JWT header is a dict containing 'alg' and/or 'typ'
            return isinstance(header, dict) and ('alg' in header or 'typ' in header)
        except Exception:
            return False
    
    def _extract_word_window(self, text: str, match_start: int, match_end: int, window: int = 50) -> str:
        """
        Extract ±window words surrounding the match position.
        Uses a generous char slack to avoid splitting UTF-8 mid-word.
        """
        char_slack = window * 9          # ~9 chars/word average
        pre_text  = text[max(0, match_start - char_slack):match_start]
        post_text = text[match_end:min(len(text), match_end + char_slack)]
        pre_words  = pre_text.split()[-window:]
        post_words = post_text.split()[:window]
        return ' '.join(pre_words) + ' ' + text[match_start:match_end] + ' ' + ' '.join(post_words)

    def _score_context(self, pattern_name: str, context: str) -> tuple:
        """
        Contextual confidence score [0.0–1.0] based on surrounding words.

        Rules applied in order:
        1. Keyword proximity boost  — real-usage signals raise the score
        2. Code-block / example penalty — doc/test context lowers the score
        3. Financial context boost  — payment words near financial patterns raise it

        Returns (score: float, reasons: list[str])
        """
        ctx_lower = context.lower()
        score = 0.5         # neutral baseline
        reasons = []

        # ── 1. KEYWORD PROXIMITY BOOST ────────────────────────────────────────
        _PROXIMITY_KEYWORDS = {
            "production", "prod", "live", "real", "secret", "private",
            "api_key", "access_key", "token", "credential", "password",
            "authorization", "authenticate", "config", "env", "environment",
            "deploy", "deployed", "server", "database", "connection",
        }
        boost_hits = [kw for kw in _PROXIMITY_KEYWORDS if kw in ctx_lower]
        if boost_hits:
            boost = round(min(0.30, len(boost_hits) * 0.06), 3)
            score += boost
            reasons.append(f"proximity_boost({','.join(boost_hits[:3])})+{boost}")

        # ── 2. CODE-BLOCK / EXAMPLE DETECTION PENALTY ────────────────────────
        _CODE_PENALTY_KEYWORDS = {
            "example", "sample", "placeholder", "dummy", "fake", "test",
            "mock", "demo", "tutorial", "docs", "documentation", "readme",
            "your_", "_here", "replace_", "xxx", "todo",
        }
        penalty_hits = [kw for kw in _CODE_PENALTY_KEYWORDS if kw in ctx_lower]
        code_fence   = ctx_lower.count("```") >= 2 or ctx_lower.count("~~~") >= 2
        if penalty_hits or code_fence:
            penalty = round(min(0.40, len(penalty_hits) * 0.07 + (0.15 if code_fence else 0)), 3)
            score  -= penalty
            hit_desc = ','.join(penalty_hits[:3]) + (",code_fence" if code_fence else "")
            reasons.append(f"code_block_penalty({hit_desc})-{penalty}")

        # ── 3. FINANCIAL CONTEXT BOOST ────────────────────────────────────────
        _FINANCIAL_PATTERNS = {"credit_card", "bank_account", "iban", "routing_number"}
        if pattern_name in _FINANCIAL_PATTERNS:
            _FINANCIAL_KEYWORDS = {
                "payment", "billing", "invoice", "transaction", "charge",
                "purchase", "order", "checkout", "card", "bank", "financial",
                "amount", "total", "price", "customer", "merchant", "receipt",
            }
            fin_hits = [kw for kw in _FINANCIAL_KEYWORDS if kw in ctx_lower]
            if fin_hits:
                boost = round(min(0.25, len(fin_hits) * 0.05), 3)
                score += boost
                reasons.append(f"financial_context_boost({','.join(fin_hits[:3])})+{boost}")

        # ── 4. MEDICAL CONTEXT PENALTY ────────────────────────────────────────
        # Financial patterns in medical documents are likely patient/provider IDs
        # (NPI, patient account numbers, insurance IDs), not real bank/card data.
        _MEDICAL_CONTEXT_TERMS = {
            "patient", "diagnosis", "physician", "doctor", "hospital", "clinic",
            "medical", "prescription", "medication", "icd", "cpt", "npi",
            "laboratory", "lab result", "specimen", "pathology", "discharge",
            "admission", "healthcare", "health plan", "provider", "referral",
            "dosage", "symptom", "procedure code", "radiology", "rx",
        }
        if pattern_name in _FINANCIAL_PATTERNS:
            med_hits = [kw for kw in _MEDICAL_CONTEXT_TERMS if kw in ctx_lower]
            if len(med_hits) >= 2:
                penalty = round(min(0.35, len(med_hits) * 0.07), 3)
                score -= penalty
                reasons.append(f"medical_context_penalty({','.join(med_hits[:3])})-{penalty}")

        return round(max(0.0, min(1.0, score)), 3), reasons

    # ── Entropy helpers ───────────────────────────────────────────────────────

    def _calculate_entropy(self, data: str) -> float:
        """Shannon entropy of a string using Counter (O(n))."""
        if not data:
            return 0.0
        counter = collections.Counter(data)
        length = len(data)
        return -sum(
            (c / length) * math.log(c / length, 2)
            for c in counter.values()
        )

    def _sliding_window_entropy(self, data: str, window: int = _ENTROPY_WINDOW) -> float:
        """
        Return the *maximum* Shannon entropy found in any sliding window of
        `window` characters.  Falls back to full-string entropy when the
        string is shorter than the window.
        """
        if len(data) <= window:
            return self._calculate_entropy(data)
        return max(
            self._calculate_entropy(data[i:i + window])
            for i in range(len(data) - window + 1)
        )

    def _is_common_base64(self, value: str) -> bool:
        """
        Return True when value is base64-alphabet content that decodes to
        ordinary printable ASCII text — i.e. likely *not* a secret.
        """
        if not _BASE64_RE.match(value):
            return False
        try:
            # Pad to a multiple-of-4 length before decoding
            decoded = base64.b64decode(value + '==').decode('utf-8', errors='strict')
            # Printable ASCII with no control chars → probably natural language
            printable = sum(c.isprintable() and ord(c) < 128 for c in decoded)
            if printable / max(len(decoded), 1) > 0.85:
                return True
        except Exception:
            pass
        return False

    def _in_code_comment(self, text: str, match_start: int) -> bool:
        """
        Return True when *match_start* falls inside a code comment.
        Detects:
          • single-line comments: // …  # …  -- …
          • block comments:       /* … */
        """
        # Single-line: look at the text on the same line *before* the match
        line_start = text.rfind('\n', 0, match_start)
        line_start = 0 if line_start == -1 else line_start + 1
        prefix = text[line_start:match_start]
        if re.search(r'(?://|#\s*|--\s*)', prefix):
            return True
        # Block comment: scan all /* … */ regions
        for m in _BLOCK_COMMENT_RE.finditer(text):
            if m.start() <= match_start < m.end():
                return True
        return False
    
    def scan(self, text: str, secrets_only: bool = False) -> Dict[str, List[Dict]]:
        """
        Comprehensive scan of text for all DLP patterns.
        Returns structured findings by severity.
        Emits detection metrics to the global DetectionMetrics singleton.
        """
        _t0 = time.monotonic()

        results = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }

        # Define Secret Patterns (TruffleHog style)
        # PEM header patterns (private_key, ssh_private_key, pgp_private_key,
        # ed25519_private_key, ecdsa_private_key, certificate) are intentionally
        # excluded from entropy gating — PEM headers are already highly specific
        # and the header itself is low-entropy by design.
        secret_types = {
            "aws_access_key", "aws_secret_key", "github_token", "generic_api_key",
            "bearer_token", "jwt_token", "db_connection_string", "password_in_code",
            "slack_api_token", "google_api_key", "aws_session_token",
            # New cloud/SaaS API key patterns
            "stripe_secret_key", "stripe_publishable_key", "stripe_restricted_key",
            "sendgrid_api_key", "twilio_auth_token", "huggingface_token",
            "npm_access_token", "cloudflare_api_token",
        }

        # Scan for all patterns
        for pattern_name, pattern_info in self.patterns.items():
            # If secrets_only mode, skip non-secret patterns
            if secrets_only and pattern_name not in secret_types:
                continue

            matches = re.finditer(pattern_info["pattern"], text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)

                # Count raw detection (before any filter)
                _metrics.inc_entity(pattern_name, "regex", validated=False)

                # Mask early so FP log never stores raw values
                masked_value = self._mask_value(matched_text, pattern_name)

                # ── GATE 1: Validator ─────────────────────────────────────
                if "validator" in pattern_info:
                    if not pattern_info["validator"](matched_text):
                        _metrics.inc_rejection("validator")
                        _metrics.log_fp_sample(
                            reason="validator_rejection",
                            entity_type=pattern_name,
                            masked_value=masked_value,
                            context_snippet=text[max(0, match.start()-80):match.end()+80],
                            extra={"pattern": pattern_info.get("description", "")},
                        )
                        continue

                # ── GATE 2: Entropy (secrets only) ───────────────────────
                if pattern_name in secret_types:
                    if self._is_common_base64(matched_text):
                        _metrics.inc_rejection("entropy")
                        _metrics.log_fp_sample(
                            reason="entropy_rejection",
                            entity_type=pattern_name,
                            masked_value=masked_value,
                            context_snippet=text[max(0, match.start()-80):match.end()+80],
                            extra={"sub_reason": "common_base64"},
                        )
                        continue

                    if len(matched_text) >= _MIN_ENTROPY_LEN:
                        entropy = self._sliding_window_entropy(matched_text)
                        threshold = (
                            _COMMENT_PENALTY
                            if self._in_code_comment(text, match.start())
                            else _ENTROPY_THRESHOLD
                        )
                        if entropy < threshold:
                            _metrics.inc_rejection("entropy")
                            _metrics.log_fp_sample(
                                reason="entropy_rejection",
                                entity_type=pattern_name,
                                masked_value=masked_value,
                                context_snippet=text[max(0, match.start()-80):match.end()+80],
                                extra={"entropy": round(entropy, 3), "threshold": threshold},
                            )
                            continue

                # ── Context windows ───────────────────────────────────────
                start_ctx = max(0, match.start() - 100)
                end_ctx   = min(len(text), match.end() + 100)
                context_window = text[start_ctx:end_ctx]

                word_window = self._extract_word_window(text, match.start(), match.end(), window=50)
                ctx_score, ctx_reasons = self._score_context(pattern_name, word_window)

                finding = {
                    "type": pattern_name,
                    "description": pattern_info["description"],
                    "value": masked_value,
                    "position": f"char {match.start()}-{match.end()}",
                    "severity": pattern_info["severity"],
                    "context": context_window,
                    "context_snippet": word_window[:500],
                    "context_score": ctx_score,
                    "context_score_reasons": ctx_reasons,
                }

                # ── GATE 3: Context keyword gate + boost ──────────────────
                if "context_keywords" in pattern_info:
                    ctx_lower_win = context_window.lower()
                    matched_ctx = [kw for kw in pattern_info["context_keywords"] if kw in ctx_lower_win]
                    if matched_ctx:
                        finding["context_match"] = True
                        finding["context_keywords_found"] = matched_ctx
                    elif pattern_info.get("requires_context_keywords"):
                        _metrics.inc_rejection("context_gate")
                        _metrics.log_fp_sample(
                            reason="context_gate_rejection",
                            entity_type=pattern_name,
                            masked_value=masked_value,
                            context_snippet=context_window[:200],
                            extra={"required_keywords": pattern_info["context_keywords"][:5]},
                        )
                        continue

                # Passed all gates — count as validated
                _metrics.inc_entity(pattern_name, "regex", validated=True)
                # Subtract the raw-only count we added earlier (now upgrading to validated)
                # Note: inc_entity with validated=False already incremented detected_total;
                # the validated=True call adds to validated_total without double-counting detected.

                results[pattern_info["severity"]].append(finding)

        # Scan for sensitive keywords
        for severity, keywords in self.sensitive_keywords.items():
            for keyword in keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
                    finding = {
                        "type": "sensitive_keyword",
                        "description": "Sensitive Keyword",
                        "value": keyword,
                        "position": "multiple",
                        "severity": severity
                    }
                    results[severity].append(finding)

        # Record regex scan timing
        _metrics.record_timing("regex", (time.monotonic() - _t0) * 1000)

        return results
    def _mask_value(self, value: str, pattern_type: str) -> str:
        """Mask sensitive values for safe logging"""
        if pattern_type in ["credit_card", "ssn", "bank_account"]:
            return f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "***"
        elif pattern_type in ["aws_secret_key", "github_token", "bearer_token", "password_in_code", "slack_api_token", "google_api_key"]:
            return f"{value[:6]}...***" if len(value) > 10 else "***"
        elif pattern_type == "email":
            parts = value.split('@')
            if len(parts) == 2:
                return f"{parts[0][:2]}***@{parts[1]}"
        return value[:10] + "..." if len(value) > 10 else value

    def redact(self, text: str) -> str:
        """
        Redact sensitive data from text based on DLP patterns.
        Replaces matches with [REDACTED: Description] to meet compliance.
        """
        all_matches = []
        
        # 1. Gather Regex Matches
        for pattern_name, pattern_info in self.patterns.items():
            for match in re.finditer(pattern_info["pattern"], text, re.IGNORECASE):
                if "validator" in pattern_info and not pattern_info["validator"](match.group(0)):
                    continue
                
                all_matches.append({
                    "start": match.start(),
                    "end": match.end(),
                    "replacement": f"[REDACTED: {pattern_info['description']}]"
                })

        # 2. Gather Keyword Matches
        for severity, keywords in self.sensitive_keywords.items():
            for keyword in keywords:
                for match in re.finditer(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
                     all_matches.append({
                        "start": match.start(),
                        "end": match.end(),
                        "replacement": f"[REDACTED: Sensitive Keyword]"
                    })

        # 3. Sort by Start Position (Ascending)
        all_matches.sort(key=lambda x: x["start"])

        # 4. Construct Redacted String (Handling Overlaps)
        result = []
        current_idx = 0
        
        for m in all_matches:
            # Skip if this match overlaps with a previously processed one
            if m["start"] < current_idx:
                continue
            
            # Append clean text before this match
            result.append(text[current_idx:m["start"]])
            
            # Append replacement
            result.append(m["replacement"])
            
            # Update current index
            current_idx = m["end"]
            
        # Append remaining text
        result.append(text[current_idx:])
        
        return "".join(result)

    def fuzz(self, text: str) -> str:
        """
        Replace sensitive data with realistic fake data (Fuzzing).
        Useful for generating safe test datasets.
        """
        try:
            from faker import Faker
            fake = Faker()
        except ImportError:
            return self.redact(text)  # Fallback if Faker missing

        all_matches = []
        
        # 1. Gather Regex Matches
        for pattern_name, pattern_info in self.patterns.items():
            for match in re.finditer(pattern_info["pattern"], text, re.IGNORECASE):
                if "validator" in pattern_info and not pattern_info["validator"](match.group(0)):
                    continue
                
                # Generate Fake Replacement based on type
                replacement = f"[FAKE-{pattern_name.upper()}]"
                if pattern_name == "credit_card": replacement = fake.credit_card_number()
                elif pattern_name == "ssn": replacement = fake.ssn()
                elif pattern_name == "bank_account": replacement = str(fake.random_int(min=100000000, max=9999999999))
                elif pattern_name == "email": replacement = fake.email()
                elif pattern_name == "phone_us": replacement = fake.phone_number()
                elif pattern_name == "ipv4": replacement = fake.ipv4()
                elif pattern_name == "name": replacement = fake.name()
                elif pattern_name == "address": replacement = fake.address().replace('\n', ', ')
                
                all_matches.append({
                    "start": match.start(),
                    "end": match.end(),
                    "replacement": replacement
                })

        # 2. Gather Keyword Matches (No specific faker for generic keywords, just mask)
        for severity, keywords in self.sensitive_keywords.items():
            for keyword in keywords:
                for match in re.finditer(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
                     all_matches.append({
                        "start": match.start(),
                        "end": match.end(),
                        "replacement": f"[FAKE-SECRET]"
                    })

        # 3. Sort by Start Position
        all_matches.sort(key=lambda x: x["start"])

        # 4. Construct Fuzzed String
        result = []
        current_idx = 0
        
        for m in all_matches:
            if m["start"] < current_idx: continue
            
            result.append(text[current_idx:m["start"]])
            result.append(m["replacement"])
            current_idx = m["end"]
            
        result.append(text[current_idx:])
        return "".join(result)
