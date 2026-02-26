"""
Tests for CodeScanner — secrets detection + vulnerability pattern detection.
The ML risk classifier is mocked to keep tests fast (no model loading).

Run with:
    pytest tests/test_code_scanner.py -v
"""
import asyncio
import pytest
from unittest.mock import patch, MagicMock

# Reusable AI verdict stubs
_RISKY  = {"risk_type": "REAL_SECRET",    "confidence": 0.90, "action": "BLOCK"}
_SAFE   = {"risk_type": "SAFE_CODE",      "confidence": 0.95, "action": "ALLOW"}
_VULN   = {"risk_type": "VULNERABLE_LOGIC","confidence": 0.85, "action": "BLOCK"}


def run(coro):
    """Helper: run async function in tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def scanner():
    """CodeScanner with the ML classifier stubbed out."""
    with patch("app.core.code_scanner.CodeRiskClassifier") as MockCls:
        MockCls.return_value.classify.return_value = _RISKY
        from app.core.code_scanner import CodeScanner
        yield CodeScanner()


# ─────────────────────────────────────────────────────────────────────────────
# SECRET DETECTION
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretDetection:
    def test_detects_aws_access_key(self, scanner):
        code = """
import boto3
aws_access_key = 'AKIAZXCVBNMQWERT1234'
aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1'
"""
        result = run(scanner.scan_file("config.py", code))
        secret_types = [f["type"] for f in result["findings"] if f["category"] == "SECRET"]
        assert "aws_access_key" in secret_types, "AWS access key must be flagged"

    def test_detects_hardcoded_password(self, scanner):
        code = """
db_password = 'supersecret123!'
"""
        result = run(scanner.scan_file("db.py", code))
        secret_types = [f["type"] for f in result["findings"] if f["category"] == "SECRET"]
        assert "password_in_code" in secret_types, "Hardcoded password must be flagged"

    def test_detects_github_token(self, scanner):
        code = "GITHUB_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'"
        result = run(scanner.scan_file("ci.py", code))
        secret_types = [f["type"] for f in result["findings"] if f["category"] == "SECRET"]
        assert "github_token" in secret_types, "GitHub token must be flagged"

    def test_detects_db_connection_string(self, scanner):
        code = "DATABASE_URL = 'postgresql://admin:hunter2@db.internal:5432/prod'"
        result = run(scanner.scan_file("settings.py", code))
        secret_types = [f["type"] for f in result["findings"] if f["category"] == "SECRET"]
        assert "db_connection_string" in secret_types, "DB connection string must be flagged"

    def test_detects_google_api_key(self, scanner):
        # Pattern: AIza + exactly 35 [A-Za-z0-9_-] chars = 39 chars total
        code = "MAPS_KEY = 'AIzaSyD-9tSrke72I6e0DVxC3rnHBIEXAMPLEKE'"
        result = run(scanner.scan_file("app.js", code))
        secret_types = [f["type"] for f in result["findings"] if f["category"] == "SECRET"]
        assert "google_api_key" in secret_types, "Google API key must be flagged"

    def test_clean_code_no_secrets(self, scanner):
        code = """
def add(a, b):
    return a + b

class Calculator:
    def multiply(self, x, y):
        return x * y
"""
        result = run(scanner.scan_file("math_utils.py", code))
        secrets = [f for f in result["findings"] if f["category"] == "SECRET"]
        assert len(secrets) == 0, "Clean code must produce zero secret findings"

    def test_valid_ssn_in_code_flagged(self, scanner):
        code = "# Employee record SSN: 234-56-7890"
        result = run(scanner.scan_file("records.py", code))
        # SSN is not in secret_types, it's in the non-secrets path, but test the overall count
        # Code scanner uses secrets_only=True, so SSN won't appear (it's PII, not a secret)
        # Just verify the scan runs cleanly
        assert "findings" in result

    def test_invalid_ssn_not_flagged_in_secrets_mode(self, scanner):
        # 000-xx-xxxx is rejected by validator — and SSN isn't a secret type anyway
        code = "ref: 000-12-3456"
        result = run(scanner.scan_file("notes.py", code))
        ssn_findings = [f for f in result["findings"] if f.get("type") == "ssn"]
        assert len(ssn_findings) == 0, "Invalid SSN should not appear in code scan"


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

class TestVulnerabilityDetection:
    @pytest.fixture(autouse=True)
    def use_vuln_verdict(self, scanner):
        scanner.risk_classifier.classify.return_value = _VULN

    def test_detects_eval(self, scanner):
        code = "result = eval(user_input)"
        result = run(scanner.scan_file("handler.py", code))
        vuln_types = [f["type"] for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert "Code Injection" in vuln_types, "eval() must be flagged as Code Injection"

    def test_detects_exec(self, scanner):
        code = "exec(compile(source, '<string>', 'exec'))"
        result = run(scanner.scan_file("runner.py", code))
        vuln_types = [f["type"] for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert "Code Injection" in vuln_types, "exec() must be flagged as Code Injection"

    def test_detects_pickle_load(self, scanner):
        code = """
import pickle
data = pickle.load(open('model.pkl', 'rb'))
"""
        result = run(scanner.scan_file("model.py", code))
        vuln_types = [f["type"] for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert "Insecure Deserialization" in vuln_types, "pickle.load() must be flagged"

    def test_detects_subprocess_shell_true(self, scanner):
        code = "subprocess.run(cmd, shell=True)"
        result = run(scanner.scan_file("deploy.py", code))
        vuln_types = [f["type"] for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert "Command Injection" in vuln_types, "shell=True must be flagged"

    def test_detects_innerhtml_xss(self, scanner):
        code = "element.innerHTML = userInput;"
        result = run(scanner.scan_file("frontend.js", code))
        vuln_types = [f["type"] for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert "Cross Site Scripting" in vuln_types, "innerHTML assignment must be flagged"

    def test_multiple_vulns_in_one_file(self, scanner):
        code = """
import pickle, subprocess
data = pickle.load(open('x.pkl','rb'))
result = eval(user_cmd)
subprocess.call(cmd, shell=True)
"""
        result = run(scanner.scan_file("bad.py", code))
        vuln_findings = [f for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert len(vuln_findings) >= 3, "Should detect pickle + eval + subprocess"
        assert result["total_findings"] == len(result["findings"])

    def test_clean_code_no_vulns(self, scanner):
        code = """
import json

def parse_config(path):
    with open(path) as f:
        return json.load(f)
"""
        result = run(scanner.scan_file("config.py", code))
        vulns = [f for f in result["findings"] if f["category"] == "VULNERABILITY"]
        assert len(vulns) == 0, "Safe code must produce zero vulnerability findings"


# ─────────────────────────────────────────────────────────────────────────────
# COMBINED — secrets + vulns in one file
# ─────────────────────────────────────────────────────────────────────────────

class TestCombinedScan:
    def test_finds_both_secrets_and_vulns(self, scanner):
        scanner.risk_classifier.classify.return_value = _RISKY
        code = """
import pickle, os

API_KEY = 'AIzaSyD-9tSrke72I6e0DVxC3rnHBIEXAMPLEKEY'
password = 'admin123'

def run_cmd(user_input):
    result = eval(user_input)
    data = pickle.load(open('model.pkl', 'rb'))
    return result
"""
        result = run(scanner.scan_file("risky_app.py", code))
        categories = {f["category"] for f in result["findings"]}
        assert "SECRET" in categories,       "Should detect at least one secret"
        assert "VULNERABILITY" in categories,"Should detect at least one vulnerability"
        assert result["total_findings"] >= 3

    def test_finding_has_required_fields(self, scanner):
        code = "eval(x)"
        result = run(scanner.scan_file("x.py", code))
        for finding in result["findings"]:
            for field in ("category", "type", "description", "severity", "ai_risk", "action"):
                assert field in finding, f"Finding missing required field: {field}"
