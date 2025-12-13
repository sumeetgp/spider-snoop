import re
from typing import Dict, List

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
                "validator": self._validate_luhn
            },
            "ssn": {
                "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
                "severity": "CRITICAL",
                "description": "Social Security Number"
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
                "pattern": r'\b(?:MRN|MR#|Medical Record)[\s:#-]*(\d{6,10})\b',
                "severity": "CRITICAL",
                "description": "Medical Record Number"
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
                "pattern": r'\b(AKIA[0-9A-Z]{16})\b',
                "severity": "CRITICAL",
                "description": "AWS Access Key ID"
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
            "bearer_token": {
                "pattern": r'\bBearer\s+([a-zA-Z0-9\-._~+/]+=*)\b',
                "severity": "CRITICAL",
                "description": "Bearer Token"
            },
            "jwt_token": {
                "pattern": r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b',
                "severity": "HIGH",
                "description": "JWT Token"
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
            }
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
    
    def scan(self, text: str) -> Dict[str, List[Dict]]:
        """
        Comprehensive scan of text for all DLP patterns
        Returns structured findings by severity
        """
        results = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        # Scan for all patterns
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.finditer(pattern_info["pattern"], text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                
                # Apply validator if exists
                if "validator" in pattern_info:
                    if not pattern_info["validator"](matched_text):
                        continue  # Skip invalid matches
                
                # Mask sensitive data in output
                masked_value = self._mask_value(matched_text, pattern_name)
                
                finding = {
                    "type": pattern_name,
                    "description": pattern_info["description"],
                    "value": masked_value,
                    "position": f"char {match.start()}-{match.end()}",
                    "severity": pattern_info["severity"]
                }
                
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
        
        return results
    
    def _mask_value(self, value: str, pattern_type: str) -> str:
        """Mask sensitive values for safe logging"""
        if pattern_type in ["credit_card", "ssn", "bank_account"]:
            return f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "***"
        elif pattern_type in ["aws_secret_key", "github_token", "bearer_token", "password_in_code"]:
            return f"{value[:6]}...***" if len(value) > 10 else "***"
        elif pattern_type == "email":
            parts = value.split('@')
            if len(parts) == 2:
                return f"{parts[0][:2]}***@{parts[1]}"
        return value[:10] + "..." if len(value) > 10 else value
