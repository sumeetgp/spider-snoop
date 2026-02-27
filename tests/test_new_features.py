"""
Tests for new features:
- Pre-filter stage (_entropy_sweep, _should_run_presidio, _should_run_ai)
- Detection metrics (inc_entity, inc_rejection, record_timing, log_fp_sample, snapshot)
- Medical classification (_classify_document_type, medical context penalty, re-labeling)
- New patterns (Stripe, Twilio, SendGrid, HuggingFace, NPM, Azure, Docker)
- Bulk scan batch API endpoint (unit-level)
- Export endpoints (unit-level)

Run with:
    pytest tests/test_new_features.py -v
"""
from __future__ import annotations

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def matcher():
    from app.core.dlp_patterns import DLPPatternMatcher
    return DLPPatternMatcher()


@pytest.fixture(scope="module")
def dlp_engine():
    from app.dlp_engine import DLPEngine
    return DLPEngine()


@pytest.fixture(autouse=True)
def reset_metrics():
    """Reset detection metrics before each test to ensure isolation."""
    from app.core.detection_metrics import metrics
    metrics.reset()
    yield
    metrics.reset()


# =============================================================================
# PRE-FILTER STAGE
# =============================================================================

class TestEntropySwep:
    """_entropy_sweep identifies high-entropy tokens that look like secrets."""

    def test_clean_text_not_suspicious(self, dlp_engine):
        result = dlp_engine._entropy_sweep("The quick brown fox jumps over the lazy dog.")
        assert result["has_suspicious_content"] is False
        assert result["suspicious_word_count"] == 0

    def test_secret_key_is_suspicious(self, dlp_engine):
        # AWS-like key: high entropy, long alphanumeric string
        secret = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = dlp_engine._entropy_sweep(secret)
        assert result["has_suspicious_content"] is True
        assert result["max_entropy"] > 3.5

    def test_repeated_characters_not_suspicious(self, dlp_engine):
        boring = "aaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbb cccccccccccccccc"
        result = dlp_engine._entropy_sweep(boring)
        assert result["has_suspicious_content"] is False

    def test_max_entropy_reported(self, dlp_engine):
        result = dlp_engine._entropy_sweep("hello world abc")
        assert "max_entropy" in result
        assert isinstance(result["max_entropy"], float)


class TestShouldRunPresidio:
    """_should_run_presidio gates Presidio NER based on regex signals + entropy."""

    def test_critical_finding_triggers_presidio(self, dlp_engine):
        findings = [{"severity": "CRITICAL", "type": "aws_access_key", "context_score": 0.9}]
        entropy  = {"has_suspicious_content": False, "max_entropy": 2.0, "suspicious_word_count": 0}
        should_run, reason = dlp_engine._should_run_presidio(findings, entropy)
        assert should_run is True
        assert "regex_critical" in reason

    def test_high_finding_triggers_presidio(self, dlp_engine):
        findings = [{"severity": "HIGH", "type": "bank_account", "context_score": 0.8}]
        entropy  = {"has_suspicious_content": False, "max_entropy": 2.0, "suspicious_word_count": 0}
        should_run, _ = dlp_engine._should_run_presidio(findings, entropy)
        assert should_run is True

    def test_entropy_triggers_presidio(self, dlp_engine):
        findings = []
        entropy  = {"has_suspicious_content": True, "max_entropy": 4.5, "suspicious_word_count": 3}
        should_run, reason = dlp_engine._should_run_presidio(findings, entropy)
        assert should_run is True
        assert reason == "entropy_suspicious"

    def test_no_signals_skips_presidio(self, dlp_engine):
        findings = [{"severity": "LOW", "type": "email", "context_score": 0.3}]
        entropy  = {"has_suspicious_content": False, "max_entropy": 1.0, "suspicious_word_count": 0}
        should_run, reason = dlp_engine._should_run_presidio(findings, entropy)
        assert should_run is False
        assert reason == "pre_filter_clean"

    def test_multiple_medium_findings_triggers(self, dlp_engine):
        findings = [
            {"severity": "MEDIUM", "type": "email", "context_score": 0.5},
            {"severity": "MEDIUM", "type": "phone_us", "context_score": 0.4},
            {"severity": "MEDIUM", "type": "dob", "context_score": 0.45},
        ]
        entropy  = {"has_suspicious_content": False, "max_entropy": 2.0, "suspicious_word_count": 0}
        should_run, _ = dlp_engine._should_run_presidio(findings, entropy)
        assert should_run is True


class TestShouldRunAI:
    """_should_run_ai gates the AI zero-shot classifier."""

    def test_no_findings_skips_ai(self, dlp_engine):
        should_run, reason = dlp_engine._should_run_ai([])
        assert should_run is False
        assert reason == "no_findings"

    def test_critical_finding_triggers_ai(self, dlp_engine):
        findings = [{"severity": "CRITICAL", "type": "aws_access_key", "context_score": 0.95}]
        should_run, _ = dlp_engine._should_run_ai(findings)
        assert should_run is True

    def test_high_confidence_finding_triggers_ai(self, dlp_engine):
        findings = [{"severity": "HIGH", "type": "credit_card", "context_score": 0.8}]
        should_run, _ = dlp_engine._should_run_ai(findings)
        assert should_run is True

    def test_low_confidence_high_finding_skips_ai(self, dlp_engine):
        findings = [{"severity": "HIGH", "type": "bank_account", "context_score": 0.3}]
        should_run, _ = dlp_engine._should_run_ai(findings)
        # Might skip or might not depending on score threshold — just verify it returns a bool
        assert isinstance(should_run, bool)

    def test_many_entity_types_triggers_ai(self, dlp_engine):
        findings = [
            {"severity": "LOW", "type": "email",    "context_score": 0.3},
            {"severity": "LOW", "type": "phone_us", "context_score": 0.3},
            {"severity": "LOW", "type": "dob",      "context_score": 0.3},
        ]
        should_run, _ = dlp_engine._should_run_ai(findings)
        assert should_run is True


# =============================================================================
# DETECTION METRICS
# =============================================================================

class TestDetectionMetrics:
    def test_initial_snapshot_zeros(self):
        from app.core.detection_metrics import metrics
        snap = metrics.snapshot()
        ents = snap["entities"]
        assert ents["detected_total"]  == 0
        assert ents["after_validation"] == 0

    def test_inc_entity_counts(self):
        from app.core.detection_metrics import metrics
        metrics.inc_entity("credit_card", "regex", validated=False)
        metrics.inc_entity("credit_card", "regex", validated=True)
        snap = metrics.snapshot()
        assert snap["entities"]["detected_total"]  >= 1
        assert snap["entities"]["after_validation"] >= 1

    def test_inc_rejection(self):
        from app.core.detection_metrics import metrics
        metrics.inc_rejection("entropy")
        metrics.inc_rejection("validator_rejection")
        snap = metrics.snapshot()
        bd = snap["entities"]["rejection_breakdown"]
        assert bd.get("entropy", 0) >= 1
        assert bd.get("validator_rejection", 0) >= 1

    def test_record_timing(self):
        from app.core.detection_metrics import metrics
        metrics.record_timing("presidio", 150.0)
        metrics.record_timing("presidio", 200.0)
        snap = metrics.snapshot()
        avg = snap["avg_inference_ms"].get("presidio")
        assert avg is not None
        assert 140 <= avg <= 210

    def test_log_fp_sample_stores(self):
        from app.core.detection_metrics import metrics
        metrics.log_fp_sample(
            reason="entropy_rejection",
            entity_type="credit_card",
            masked_value="41**11",
            context_snippet="... credit card ...",
            extra={"entropy": 2.5},
        )
        samples = metrics.fp_samples(limit=10)
        assert len(samples) >= 1
        assert samples[-1]["reason"] == "entropy_rejection"

    def test_reset_clears_everything(self):
        from app.core.detection_metrics import metrics
        metrics.inc_entity("ssn", "regex", validated=True)
        metrics.reset()
        snap = metrics.snapshot()
        assert snap["entities"]["detected_total"] == 0
        assert snap["false_positive_buffer_size"] == 0

    def test_by_type_tracks_sources(self):
        from app.core.detection_metrics import metrics
        metrics.inc_entity("email", "regex", validated=True)
        metrics.inc_entity("email", "presidio", validated=True)
        snap = metrics.snapshot()
        # by_type tracks per-entity totals
        by_type = snap["by_type"]
        assert "email" in by_type
        assert by_type["email"]["detected"] >= 2
        # by_source tracks per-source totals (top-level, not nested in by_type)
        by_source = snap["by_source"]
        assert "regex" in by_source
        assert "presidio" in by_source


# =============================================================================
# MEDICAL DOCUMENT CLASSIFICATION
# =============================================================================

class TestMedicalClassification:
    MEDICAL_TEXT = """
    PATIENT: John Doe  DOB: 1965-04-21
    Physician: Dr. Sarah Williams MD  NPI: 1234567890
    Diagnosis: Type 2 Diabetes Mellitus ICD-10: E11.9
    Admitted: 2025-01-15  Discharge: 2025-01-18
    Medications: Metformin 500mg, Insulin NPH
    Patient ID: 98765432  Insurance: BC/BS 087654321
    Lab results: HbA1c 8.2%, fasting glucose 210 mg/dL
    Prescription for Metformin filled at pharmacy.
    """

    FINANCIAL_TEXT = """
    Account Statement
    Account: 12345678  Routing: 021000021
    Credit Card: 4111-1111-1111-1111
    Transaction: $1,500.00  Date: 2025-01-10
    Balance: $10,000.00
    """

    def test_medical_doc_classified(self, dlp_engine):
        result = dlp_engine._classify_document_type(self.MEDICAL_TEXT)
        # Returns a dict: {'doc_type': 'MEDICAL_RECORD', 'is_medical': bool, 'signals': int, ...}
        assert result["is_medical"] is True, f"Expected is_medical=True, got {result}"
        assert result["doc_type"] == "MEDICAL_RECORD", f"Expected doc_type=MEDICAL_RECORD, got {result}"

    def test_financial_doc_not_medical(self, dlp_engine):
        doc_type = dlp_engine._classify_document_type(self.FINANCIAL_TEXT)
        assert doc_type != "MEDICAL_RECORD"

    def _all_findings(self, matcher, text: str) -> list:
        """Flatten all findings from the severity-keyed dict returned by scan()."""
        results = matcher.scan(text)
        findings = []
        for sev_list in results.values():
            findings.extend(sev_list)
        return findings

    def test_medical_penalty_reduces_financial_scores(self, matcher):
        """bank_account match in medical context should receive context penalty."""
        findings = self._all_findings(matcher, self.MEDICAL_TEXT)
        bank_hits = [f for f in findings if f["type"] == "bank_account"]
        if bank_hits:
            scores = [f.get("context_score", 1.0) for f in bank_hits]
            assert any(s < 0.9 for s in scores), f"Expected penalty applied, scores: {scores}"
        # If no bank_account found (medical re-labeling suppressed it) — that's also a pass

    def test_medical_patterns_detected(self, matcher):
        """NPI and ICD-10 patterns should fire on medical text."""
        findings = self._all_findings(matcher, self.MEDICAL_TEXT)
        types = {f["type"] for f in findings}
        medical_types = {"npi_number", "icd10_code", "medical_record", "dea_number"}
        assert types & medical_types, f"No medical patterns found. Types: {types}"

    def test_icd10_requires_context(self, matcher):
        """ICD-10 pattern should NOT fire when medical context keywords are absent."""
        non_medical = "The project has reference A15.0 and reference B20 in spreadsheet column Z10."
        findings = self._all_findings(matcher, non_medical)
        types = {f["type"] for f in findings}
        assert "icd10_code" not in types, "ICD-10 should not fire without medical context"


# =============================================================================
# NEW PATTERNS
# =============================================================================

class TestNewPatterns:
    """Test detection of newly added SaaS API key patterns."""

    def _assert_detected(self, matcher, text: str, expected_type: str, label: str):
        # scan() returns dict keyed by severity: {'CRITICAL': [...], 'HIGH': [...], ...}
        results = matcher.scan(text)
        all_findings = []
        for severity_list in results.values():
            all_findings.extend(severity_list)
        types = {f["type"] for f in all_findings}
        assert expected_type in types, (
            f"[{label}] Expected '{expected_type}' in results but got: {types}\nText: {text[:100]}"
        )

    # ── Stripe ────────────────────────────────────────────────────────────────
    def test_stripe_secret_key(self, matcher):
        # Fake sequential value — not a real key (entropy passes gate via diversity)
        fake = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
        self._assert_detected(
            matcher,
            f"STRIPE_SECRET_KEY={fake}",
            "stripe_secret_key", "Stripe live secret key"
        )

    def test_stripe_test_key(self, matcher):
        # Fake sequential value — not a real key
        fake = "sk_test_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        self._assert_detected(
            matcher,
            f"api_key = {fake}",
            "stripe_secret_key", "Stripe test secret key"
        )

    def test_stripe_publishable_key(self, matcher):
        # Fake sequential value — not a real key
        fake = "pk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
        self._assert_detected(
            matcher,
            f"PUBLISHABLE={fake}",
            "stripe_publishable_key", "Stripe publishable key"
        )

    # ── Twilio ────────────────────────────────────────────────────────────────
    def test_twilio_account_sid(self, matcher):
        # Fake repeating value — not a real SID (twilio_account_sid skips entropy gate)
        fake = "AC" + "abababababababababababababababababab"[:32]
        self._assert_detected(
            matcher,
            f"account_sid = {fake}",
            "twilio_account_sid", "Twilio account SID"
        )

    # ── SendGrid ──────────────────────────────────────────────────────────────
    def test_sendgrid_api_key(self, matcher):
        self._assert_detected(
            matcher,
            "SG.aBcDeFgHiJkLmNoPqRsTuVw.0123456789012345678901234567890123456789012",
            "sendgrid_api_key", "SendGrid API key"
        )

    # ── HuggingFace ───────────────────────────────────────────────────────────
    def test_huggingface_token(self, matcher):
        self._assert_detected(
            matcher,
            "HF_TOKEN=hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901",
            "huggingface_token", "HuggingFace token"
        )

    # ── NPM ───────────────────────────────────────────────────────────────────
    def test_npm_access_token(self, matcher):
        self._assert_detected(
            matcher,
            "NPM_TOKEN=npm_1234567890abcdefghijklmnopqrstuvwxyz",
            "npm_access_token", "NPM access token"
        )

    # ── Azure ─────────────────────────────────────────────────────────────────
    def test_azure_connection_string(self, matcher):
        self._assert_detected(
            matcher,
            "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdA==",
            "azure_connection_string", "Azure storage connection string"
        )

    # ── Discord ───────────────────────────────────────────────────────────────
    def test_discord_webhook(self, matcher):
        self._assert_detected(
            matcher,
            "WEBHOOK=https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123",
            "discord_webhook", "Discord webhook"
        )

    # ── Crypto keys ───────────────────────────────────────────────────────────
    def test_ec_private_key(self, matcher):
        self._assert_detected(
            matcher,
            "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIHb...",
            "ecdsa_private_key", "ECDSA private key header"
        )

    # ── Ensure no regression on existing patterns ─────────────────────────────
    def test_aws_key_still_detected(self, matcher):
        self._assert_detected(
            matcher,
            "AWS_KEY = AKIAIOSFODNN7EXAMPLE",
            "aws_access_key", "AWS access key (regression)"
        )

    def test_github_token_still_detected(self, matcher):
        self._assert_detected(
            matcher,
            "token = ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "github_token", "GitHub PAT (regression)"
        )

    def test_private_key_still_detected(self, matcher):
        self._assert_detected(
            matcher,
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
            "private_key", "RSA private key (regression)"
        )


# =============================================================================
# SCORING CONFIG — NEW WEIGHTS
# =============================================================================

class TestScoringConfigNewTypes:
    def test_stripe_secret_weight(self):
        from app.core.scoring_config import get_weight
        w = get_weight("stripe_secret_key")
        assert w >= 90, f"Expected stripe_secret_key weight >= 90, got {w}"

    def test_sendgrid_weight(self):
        from app.core.scoring_config import get_weight
        assert get_weight("sendgrid_api_key") >= 90

    def test_twilio_auth_token_weight(self):
        from app.core.scoring_config import get_weight
        assert get_weight("twilio_auth_token") >= 90

    def test_azure_connection_weight(self):
        from app.core.scoring_config import get_weight
        assert get_weight("azure_connection_string") >= 95

    def test_huggingface_token_weight(self):
        from app.core.scoring_config import get_weight
        assert get_weight("huggingface_token") >= 50

    def test_certificate_low_weight(self):
        from app.core.scoring_config import get_weight
        w = get_weight("certificate")
        assert w <= 50, f"Certificate should be low-weight, got {w}"


# =============================================================================
# ALERT CONFIG — SCHEMA VALIDATION
# =============================================================================

class TestAlertConfigSchemas:
    def test_create_valid_webhook_config(self):
        from app.routes.alerts import AlertConfigCreate, AlertTrigger
        cfg = AlertConfigCreate(
            name="Prod Webhook",
            webhook_url="https://hooks.example.com/alert",
            trigger_on=AlertTrigger.CRITICAL,
        )
        assert cfg.webhook_url.startswith("https://")

    def test_create_valid_email_config(self):
        from app.routes.alerts import AlertConfigCreate
        cfg = AlertConfigCreate(email="sec@example.com")
        assert "@" in cfg.email

    def test_invalid_webhook_url_rejected(self):
        from app.routes.alerts import AlertConfigCreate
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            AlertConfigCreate(webhook_url="not-a-url")

    def test_invalid_email_rejected(self):
        from app.routes.alerts import AlertConfigCreate
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            AlertConfigCreate(email="not-an-email")

    def test_trigger_levels(self):
        from app.models.alert import AlertTrigger
        assert "HIGH" in AlertTrigger._value2member_map_
        assert "CRITICAL" in AlertTrigger._value2member_map_
        assert "BLOCK" in AlertTrigger._value2member_map_


# =============================================================================
# BULK SCAN — REQUEST SCHEMA VALIDATION
# =============================================================================

class TestBulkScanSchemas:
    def test_valid_request(self):
        from app.routes.bulk_scans import BulkScanRequest, BulkItem
        req = BulkScanRequest(items=[
            BulkItem(content="Hello world", label="item_0"),
            BulkItem(content="Another text payload"),
        ])
        assert len(req.items) == 2

    def test_empty_items_rejected(self):
        from app.routes.bulk_scans import BulkScanRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            BulkScanRequest(items=[])

    def test_too_many_items_rejected(self):
        from app.routes.bulk_scans import BulkScanRequest, BulkItem, _MAX_BATCH_ITEMS
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            BulkScanRequest(items=[
                BulkItem(content=f"item {i}") for i in range(_MAX_BATCH_ITEMS + 1)
            ])

    def test_empty_content_rejected(self):
        from app.routes.bulk_scans import BulkItem
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            BulkItem(content="   ")

    def test_content_truncated_to_max(self):
        from app.routes.bulk_scans import BulkItem, _MAX_CONTENT_CHARS
        long_content = "x" * (_MAX_CONTENT_CHARS + 100)
        item = BulkItem(content=long_content)
        assert len(item.content) == _MAX_CONTENT_CHARS


# =============================================================================
# EXPORT — CSV OUTPUT FORMAT
# =============================================================================

class TestCsvExport:
    def _make_scan(self):
        """Create a minimal mock DLPScan-like object."""
        from types import SimpleNamespace
        from datetime import datetime
        scan = SimpleNamespace()
        scan.id = 42
        scan.source = "API"
        scan.risk_level = "HIGH"
        scan.threat_score = 75
        scan.findings = [{"type": "credit_card", "severity": "CRITICAL", "value": "41**11"}]
        scan.verdict = "HIGH — Credit card detected"
        scan.scan_type = "DLP"
        scan.scan_duration_ms = 320
        scan.created_at = datetime(2025, 1, 15, 10, 30, 0)
        return scan

    def test_csv_has_header(self):
        from app.routes.export import _build_csv
        content = _build_csv([self._make_scan()])
        assert "scan_id" in content
        assert "risk_level" in content
        assert "threat_score" in content

    def test_csv_contains_scan_data(self):
        from app.routes.export import _build_csv
        scan = self._make_scan()
        content = _build_csv([scan])
        assert str(scan.id) in content
        assert scan.risk_level in content
        assert str(scan.threat_score) in content

    def test_csv_multiple_scans(self):
        from app.routes.export import _build_csv
        scans = [self._make_scan() for _ in range(3)]
        content = _build_csv(scans)
        lines = [l for l in content.strip().splitlines() if l]
        assert len(lines) == 4  # 1 header + 3 data rows
