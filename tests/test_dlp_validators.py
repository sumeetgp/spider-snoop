"""
Unit tests for DLPPatternMatcher validators.
Covers: credit card (Luhn + length + BIN), SSN (range/pattern rules),
AWS key (AKIA/ASIA prefix + context boost), and JWT (header decode).

Run with:
    pytest tests/test_dlp_validators.py -v
"""
import pytest
from app.core.dlp_patterns import DLPPatternMatcher


@pytest.fixture(scope="module")
def matcher():
    return DLPPatternMatcher()


# ─────────────────────────────────────────────────────────────────────────────
# CREDIT CARD
# ─────────────────────────────────────────────────────────────────────────────

class TestCreditCardValidator:
    # ── True positives (should pass) ─────────────────────────────────────────
    @pytest.mark.parametrize("number,label", [
        ("4111111111111111",   "Visa 16-digit"),
        ("4111-1111-1111-1111","Visa with dashes"),
        ("4111 1111 1111 1111","Visa with spaces"),
        ("378282246310005",    "Amex 15-digit"),
        ("5500005555555559",   "Mastercard classic"),
        ("6011111111111117",   "Discover"),
        ("3566002020360505",   "JCB"),
    ])
    def test_valid_card(self, matcher, number, label):
        assert matcher._validate_credit_card(number), f"Should accept {label}: {number}"

    # ── False positives (should be rejected) ─────────────────────────────────
    @pytest.mark.parametrize("number,reason", [
        ("4111111111111112",   "bad Luhn checksum"),
        ("411111111111",       "too short (12 digits)"),
        ("41111111111111111111","too long (20 digits)"),
        ("9999999999999999",   "unknown BIN prefix"),
        ("1234567890123456",   "no recognised issuer (starts with 1)"),
        ("0000000000000000",   "all zeros"),
    ])
    def test_invalid_card(self, matcher, number, reason):
        assert not matcher._validate_credit_card(number), f"Should reject ({reason}): {number}"

    def test_scan_detects_valid_visa(self, matcher):
        results = matcher.scan("Customer paid with 4111-1111-1111-1111 today.")
        cc_findings = results["CRITICAL"]
        assert any(f["type"] == "credit_card" for f in cc_findings), \
            "Valid Visa should appear in CRITICAL findings"

    def test_scan_drops_bad_luhn(self, matcher):
        results = matcher.scan("Card number: 4111-1111-1111-1112")
        cc_findings = [f for f in results["CRITICAL"] if f["type"] == "credit_card"]
        assert len(cc_findings) == 0, "Bad-Luhn card must be filtered out"

    def test_scan_drops_unknown_bin(self, matcher):
        results = matcher.scan("Reference: 9999-9999-9999-9999")
        cc_findings = [f for f in results["CRITICAL"] if f["type"] == "credit_card"]
        assert len(cc_findings) == 0, "Unknown BIN must be filtered out"


# ─────────────────────────────────────────────────────────────────────────────
# SSN
# ─────────────────────────────────────────────────────────────────────────────

class TestSSNValidator:
    # ── True positives ────────────────────────────────────────────────────────
    @pytest.mark.parametrize("ssn,label", [
        ("234-56-7890", "normal valid SSN"),
        ("321-45-6789", "another valid SSN"),
        ("456-78-9012", "yet another"),
    ])
    def test_valid_ssn(self, matcher, ssn, label):
        assert matcher._validate_ssn(ssn), f"Should accept {label}: {ssn}"

    # ── False positives (should be rejected) ─────────────────────────────────
    @pytest.mark.parametrize("ssn,reason", [
        ("000-12-3456", "area 000 never assigned"),
        ("666-12-3456", "area 666 never assigned"),
        ("900-12-3456", "area 900+ never assigned"),
        ("999-56-7890", "area 999 never assigned"),
        ("123-00-4567", "group 00 invalid"),
        ("123-45-0000", "serial 0000 invalid"),
        ("111-11-1111", "all same digit"),
        ("555-55-5555", "all same digit"),
        ("123-45-6789", "sequential 123456789"),
    ])
    def test_invalid_ssn(self, matcher, ssn, reason):
        assert not matcher._validate_ssn(ssn), f"Should reject ({reason}): {ssn}"

    def test_scan_detects_valid_ssn(self, matcher):
        results = matcher.scan("Employee SSN: 234-56-7890")
        ssn_findings = [f for f in results["CRITICAL"] if f["type"] == "ssn"]
        assert len(ssn_findings) >= 1, "Valid SSN should appear in CRITICAL findings"

    def test_scan_drops_all_zeros_area(self, matcher):
        results = matcher.scan("Test SSN: 000-12-3456")
        ssn_findings = [f for f in results["CRITICAL"] if f["type"] == "ssn"]
        assert len(ssn_findings) == 0, "000-xx-xxxx must be filtered out"

    def test_scan_drops_repeated_pattern(self, matcher):
        results = matcher.scan("Fake SSN: 111-11-1111")
        ssn_findings = [f for f in results["CRITICAL"] if f["type"] == "ssn"]
        assert len(ssn_findings) == 0, "111-11-1111 must be filtered out"


# ─────────────────────────────────────────────────────────────────────────────
# AWS ACCESS KEY
# ─────────────────────────────────────────────────────────────────────────────

class TestAWSKeyValidation:
    # Both AKIA and ASIA prefixes should now be detected
    def test_scan_detects_akia_prefix(self, matcher):
        results = matcher.scan("aws_access_key = AKIAZXCVBNMQWERT1234")
        aws_findings = [f for f in results["CRITICAL"] if f["type"] == "aws_access_key"]
        assert len(aws_findings) >= 1, "AKIA-prefixed key must be detected"

    def test_scan_detects_asia_prefix(self, matcher):
        results = matcher.scan("temp_key = ASIAZXCVBNMQWERT1234")
        aws_findings = [f for f in results["CRITICAL"] if f["type"] == "aws_access_key"]
        assert len(aws_findings) >= 1, "ASIA-prefixed (STS temporary) key must be detected"

    def test_context_keyword_boost_when_nearby(self, matcher):
        text = "aws_access_key = AKIAZXCVBNMQWERT1234 secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        results = matcher.scan(text)
        aws_findings = [f for f in results["CRITICAL"] if f["type"] == "aws_access_key"]
        assert len(aws_findings) >= 1
        assert aws_findings[0].get("context_match") is True, \
            "context_match should be True when AWS-related keywords appear nearby"
        kw_found = aws_findings[0].get("context_keywords_found", [])
        assert any(k in kw_found for k in ["aws", "secret"]), \
            f"Expected 'aws' or 'secret' in context_keywords_found, got: {kw_found}"

    def test_no_context_boost_without_keywords(self, matcher):
        # Key in isolation — no surrounding AWS keywords
        text = "token: AKIAZXCVBNMQWERT1234"
        results = matcher.scan(text)
        aws_findings = [f for f in results["CRITICAL"] if f["type"] == "aws_access_key"]
        if aws_findings:
            assert not aws_findings[0].get("context_match"), \
                "context_match should be absent when no AWS keywords nearby"

    def test_wrong_prefix_not_detected(self, matcher):
        # Wrong prefix AKIB — should not match
        results = matcher.scan("key = AKIBZXCVBNMQWERT1234")
        aws_findings = [f for f in results["CRITICAL"] if f["type"] == "aws_access_key"]
        assert len(aws_findings) == 0, "Non-AKIA/ASIA prefix must not be detected"


# ─────────────────────────────────────────────────────────────────────────────
# JWT TOKEN
# ─────────────────────────────────────────────────────────────────────────────

# Standard HS256 JWT from jwt.io — header: {"alg":"HS256","typ":"JWT"}
VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# Header decodes to {"foo":"bar"} — no alg or typ → must be rejected
FAKE_JWT_NO_ALG = (
    "eyJmb28iOiJiYXIifQ"
    ".eyJhIjoiYiJ9"
    ".c2lnbmF0dXJl"
)

class TestJWTValidator:
    def test_valid_jwt_passes(self, matcher):
        assert matcher._validate_jwt(VALID_JWT), "Real JWT with alg+typ should pass"

    def test_two_part_token_rejected(self, matcher):
        two_part = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"
        assert not matcher._validate_jwt(two_part), "Two-part token must be rejected"

    def test_header_without_alg_or_typ_rejected(self, matcher):
        assert not matcher._validate_jwt(FAKE_JWT_NO_ALG), \
            "JWT whose header has no alg/typ must be rejected"

    def test_garbage_string_rejected(self, matcher):
        assert not matcher._validate_jwt("notaJWT.atall.really"), \
            "Non-base64 garbage must be rejected"

    def test_scan_detects_valid_jwt(self, matcher):
        text = f"Authorization: Bearer {VALID_JWT}"
        results = matcher.scan(text)
        jwt_findings = [f for f in results["HIGH"] if f["type"] == "jwt_token"]
        assert len(jwt_findings) >= 1, "Valid JWT must appear in HIGH findings"

    def test_scan_drops_fake_jwt(self, matcher):
        text = f"token: {FAKE_JWT_NO_ALG}"
        results = matcher.scan(text)
        jwt_findings = [f for f in results["HIGH"] if f["type"] == "jwt_token"]
        assert len(jwt_findings) == 0, "Fake JWT (no alg/typ) must be filtered out"
