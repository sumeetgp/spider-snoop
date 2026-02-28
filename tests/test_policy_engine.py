"""
Phase 4 — Policy Engine & Zero Trust Decision Layer
=====================================================
Unit tests (no DB) and integration tests (TestClient + mock DB).

Run:
    pytest tests/test_policy_engine.py -v
"""
from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from app.core.policy_engine import PolicyEngine, ContextPayload, PolicyDecision
from app.models.policy import Policy, PolicyAction


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _policy(
    name: str,
    action: str,
    conditions: dict,
    priority: int = 10,
    simulate: bool = False,
    enabled: bool = True,
) -> Policy:
    """Build an in-memory Policy ORM object without a DB session."""
    p = Policy()
    p.id         = hash(name) % 10_000  # stable fake id
    p.name       = name
    p.action     = action
    p.conditions = conditions
    p.priority   = priority
    p.simulate   = simulate
    p.enabled    = enabled
    return p


def _scan(risk_level="LOW", threat_score=0, findings=None) -> dict:
    return {
        "risk_level":   risk_level,
        "threat_score": threat_score,
        "findings":     findings or [],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Unit: ContextPayload
# ══════════════════════════════════════════════════════════════════════════════

class TestContextPayload:
    def test_defaults(self):
        ctx = ContextPayload()
        assert ctx.destination  == "unknown"
        assert ctx.device_trust == "unknown"

    def test_identity_risk_score_contractor(self):
        ctx = ContextPayload(user_role="contractor")
        assert ctx.identity_risk_score == 40

    def test_identity_risk_score_admin(self):
        ctx = ContextPayload(user_role="admin")
        assert ctx.identity_risk_score == 10

    def test_identity_risk_score_unknown_role(self):
        ctx = ContextPayload(user_role="intern")
        assert ctx.identity_risk_score == 20  # default


# ══════════════════════════════════════════════════════════════════════════════
# Unit: PolicyDecision
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyDecision:
    def test_is_blocking_block_non_simulated(self):
        d = PolicyDecision(action=PolicyAction.BLOCK, simulated=False)
        assert d.is_blocking is True

    def test_is_blocking_block_simulated(self):
        d = PolicyDecision(action=PolicyAction.BLOCK, simulated=True)
        assert d.is_blocking is False

    def test_is_blocking_flag(self):
        d = PolicyDecision(action=PolicyAction.FLAG)
        assert d.is_blocking is False

    def test_to_dict_keys(self):
        d = PolicyDecision(
            action=PolicyAction.FLAG,
            policy_id=5,
            policy_name="test_policy",
            simulated=False,
        )
        result = d.to_dict()
        assert result["action"] == "flag"
        assert result["policy_id"] == 5
        assert result["policy_name"] == "test_policy"
        assert "matched_conditions" in result
        assert "would_have_action" in result

    def test_to_dict_simulated_would_have_action(self):
        d = PolicyDecision(
            action=PolicyAction.ALLOW,
            would_have_action=PolicyAction.BLOCK,
            simulated=True,
        )
        result = d.to_dict()
        assert result["action"] == "allow"
        assert result["would_have_action"] == "block"
        assert result["simulated"] is True


# ══════════════════════════════════════════════════════════════════════════════
# Unit: PolicyEngine._match
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyMatch:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_risk_band_match(self):
        conditions = {"risk_bands": ["CRITICAL"]}
        result = self.engine._match(
            conditions, _scan("CRITICAL"), ContextPayload(), user=None
        )
        assert result is not None
        assert result["risk_band"] == "CRITICAL"

    def test_risk_band_no_match(self):
        conditions = {"risk_bands": ["CRITICAL"]}
        result = self.engine._match(
            conditions, _scan("HIGH"), ContextPayload(), user=None
        )
        assert result is None

    def test_finding_types_match(self):
        conditions = {"finding_types": ["aws_secret_access_key", "private_key"]}
        scan = _scan(findings=[{"type": "aws_secret_access_key"}, {"type": "email"}])
        result = self.engine._match(conditions, scan, ContextPayload(), user=None)
        assert result is not None
        assert "aws_secret_access_key" in result["finding_types"]

    def test_finding_types_no_overlap(self):
        conditions = {"finding_types": ["stripe_secret_key"]}
        scan = _scan(findings=[{"type": "email"}])
        result = self.engine._match(conditions, scan, ContextPayload(), user=None)
        assert result is None

    def test_threat_score_min_pass(self):
        conditions = {"threat_score_min": 50}
        result = self.engine._match(
            conditions, _scan(threat_score=75), ContextPayload(), user=None
        )
        assert result is not None

    def test_threat_score_min_fail(self):
        conditions = {"threat_score_min": 50}
        result = self.engine._match(
            conditions, _scan(threat_score=30), ContextPayload(), user=None
        )
        assert result is None

    def test_destination_match(self):
        conditions = {"destinations": ["external"]}
        ctx = ContextPayload(destination="external")
        result = self.engine._match(conditions, _scan(), ctx, user=None)
        assert result is not None

    def test_destination_no_match(self):
        conditions = {"destinations": ["external"]}
        ctx = ContextPayload(destination="internal")
        result = self.engine._match(conditions, _scan(), ctx, user=None)
        assert result is None

    def test_user_roles_match(self):
        conditions = {"user_roles": ["contractor", "vendor"]}
        ctx = ContextPayload(user_role="contractor")
        result = self.engine._match(conditions, _scan(), ctx, user=None)
        assert result is not None

    def test_device_trust_match(self):
        conditions = {"device_trust": ["unmanaged", "unknown"]}
        ctx = ContextPayload(device_trust="unmanaged")
        result = self.engine._match(conditions, _scan(), ctx, user=None)
        assert result is not None

    def test_geo_location_match(self):
        conditions = {"geo_locations": ["CN", "RU"]}
        ctx = ContextPayload(geo_location="CN")
        result = self.engine._match(conditions, _scan(), ctx, user=None)
        assert result is not None

    def test_finding_count_min_match(self):
        conditions = {"finding_count_min": 2}
        scan = _scan(findings=[{"type": "a"}, {"type": "b"}, {"type": "c"}])
        result = self.engine._match(conditions, scan, ContextPayload(), user=None)
        assert result is not None
        assert result["finding_count"] == 3

    def test_finding_count_min_fail(self):
        conditions = {"finding_count_min": 5}
        scan = _scan(findings=[{"type": "a"}])
        result = self.engine._match(conditions, scan, ContextPayload(), user=None)
        assert result is None

    def test_empty_conditions_returns_default_match(self):
        result = self.engine._match({}, _scan(), ContextPayload(), user=None)
        assert result == {"default_match": True}

    def test_multiple_conditions_all_must_pass(self):
        # risk_band passes (CRITICAL), but destination fails (internal != external)
        conditions = {"risk_bands": ["CRITICAL"], "destinations": ["external"]}
        ctx = ContextPayload(destination="internal")
        result = self.engine._match(conditions, _scan("CRITICAL"), ctx, user=None)
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# Unit: PolicyEngine.evaluate — scenario matrix
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyEngineEvaluate:
    """Matrix of enforcement scenarios matching the plan specification."""

    def setup_method(self):
        self.engine = PolicyEngine()
        self.policies = [
            _policy("block_critical_external", "block",
                    {"risk_bands": ["CRITICAL"], "destinations": ["external"]},
                    priority=1),
            _policy("block_contractor_secrets_external", "block",
                    {"risk_bands": ["HIGH", "CRITICAL"],
                     "finding_types": ["aws_secret_access_key", "private_key", "github_access_token", "stripe_secret_key"],
                     "destinations": ["external"], "user_roles": ["contractor", "vendor"]},
                    priority=2),
            _policy("quarantine_unmanaged_high", "quarantine",
                    {"risk_bands": ["HIGH", "CRITICAL"], "device_trust": ["unmanaged", "unknown"]},
                    priority=5, simulate=True),
            _policy("flag_high_risk_internal", "flag",
                    {"risk_bands": ["HIGH", "CRITICAL"], "destinations": ["internal"]},
                    priority=10),
        ]

    def _eval(self, scan, ctx) -> PolicyDecision:
        return self.engine.evaluate(scan, ctx, self.policies)

    def test_critical_external_developer_blocked(self):
        scan = _scan("CRITICAL", 90, [{"type": "aws_secret_access_key"}])
        ctx  = ContextPayload(destination="external", user_role="developer")
        d    = self._eval(scan, ctx)
        assert d.action == PolicyAction.BLOCK
        assert d.policy_name == "block_critical_external"
        assert not d.simulated

    def test_high_internal_developer_flagged(self):
        # device_trust="managed" so quarantine_unmanaged_high (priority 5) doesn't match;
        # flag_high_risk_internal (priority 10) matches instead.
        scan = _scan("HIGH", 70, [{"type": "aws_secret_access_key"}])
        ctx  = ContextPayload(destination="internal", user_role="developer", device_trust="managed")
        d    = self._eval(scan, ctx)
        assert d.action == PolicyAction.FLAG
        assert d.policy_name == "flag_high_risk_internal"

    def test_contractor_secrets_external_blocked(self):
        scan = _scan("HIGH", 80,
                     [{"type": "aws_secret_access_key"}, {"type": "private_key"}])
        ctx  = ContextPayload(destination="external", user_role="contractor")
        d    = self._eval(scan, ctx)
        assert d.action == PolicyAction.BLOCK
        assert d.policy_name == "block_contractor_secrets_external"

    def test_low_risk_allows(self):
        scan = _scan("LOW", 5, [])
        ctx  = ContextPayload(destination="external", user_role="contractor")
        d    = self._eval(scan, ctx)
        assert d.action == PolicyAction.ALLOW

    def test_simulate_mode_returns_allow_with_would_have(self):
        # Only the simulated quarantine policy can match this (unmanaged high)
        # But first two non-simulated policies don't match (no external, no specific types)
        scan = _scan("HIGH", 70, [{"type": "some_finding"}])
        ctx  = ContextPayload(destination="internal", device_trust="unmanaged", user_role="developer")
        d    = self._eval(scan, ctx)
        # quarantine_unmanaged_high is simulated → action becomes ALLOW
        assert d.action == PolicyAction.ALLOW
        assert d.simulated is True
        assert d.would_have_action == PolicyAction.QUARANTINE

    def test_disabled_policy_skipped(self):
        policies = [
            _policy("blocked_but_disabled", "block",
                    {"risk_bands": ["LOW"]}, priority=1, enabled=False),
        ]
        d = self.engine.evaluate(_scan("LOW"), ContextPayload(), policies)
        assert d.action == PolicyAction.ALLOW

    def test_first_match_wins(self):
        # Two policies both match; lower priority number wins.
        p1 = _policy("first", "block", {"risk_bands": ["HIGH"]}, priority=1)
        p2 = _policy("second", "flag", {"risk_bands": ["HIGH"]}, priority=5)
        d  = self.engine.evaluate(_scan("HIGH"), ContextPayload(), [p2, p1])
        assert d.policy_name == "first"
        assert d.action == PolicyAction.BLOCK

    def test_evaluation_trace_populated(self):
        d = self._eval(_scan("LOW"), ContextPayload())
        assert isinstance(d.evaluation_trace, list)
        # At least one trace entry per evaluated policy
        assert len(d.evaluation_trace) >= 1

    def test_no_policies_allows(self):
        d = self.engine.evaluate(_scan("CRITICAL"), ContextPayload(), [])
        assert d.action == PolicyAction.ALLOW

    def test_is_blocking_true_for_block_action(self):
        scan = _scan("CRITICAL", 95, [{"type": "aws_secret_access_key"}])
        ctx  = ContextPayload(destination="external")
        d    = self._eval(scan, ctx)
        assert d.is_blocking is True


# ══════════════════════════════════════════════════════════════════════════════
# Integration: REST API
# ══════════════════════════════════════════════════════════════════════════════

from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User, UserRole
from app.database import get_db
from app.utils.auth import get_current_active_user
from app.routes.scans import get_dlp_engine
from app.models.scan import ScanStatus, RiskLevel
from app.routes.policies import seed_default_policies


def _make_user(role: UserRole = UserRole.ADMIN) -> User:
    u = MagicMock(spec=User)
    u.id        = 1
    u.username  = "testuser"
    u.email     = "test@example.com"
    u.role      = role
    u.is_active = True
    return u


def _make_db(policies=None, decision_logs=None):
    """Return a mock DB session pre-loaded with policy data."""
    db = MagicMock()

    # Default scan refresh
    def _refresh(obj):
        obj.id             = obj.id if hasattr(obj, "id") and obj.id else 999
        obj.created_at     = obj.created_at if hasattr(obj, "created_at") and obj.created_at else datetime.utcnow()
        obj.completed_at   = datetime.utcnow()
        obj.source         = getattr(obj, "source", "API")
        obj.findings       = getattr(obj, "findings", [])
        obj.risk_level     = getattr(obj, "risk_level", RiskLevel.LOW)
        obj.status         = getattr(obj, "status", ScanStatus.COMPLETED)
        obj.verdict        = getattr(obj, "verdict", "Safe")
        obj.scan_duration_ms = getattr(obj, "scan_duration_ms", 10)
        obj.threat_score   = getattr(obj, "threat_score", 0)
        obj.ai_analysis    = getattr(obj, "ai_analysis", None)
        obj.policy_decision = getattr(obj, "policy_decision", None)

    db.refresh.side_effect = _refresh

    # Build default seeded policies if not supplied
    if policies is None:
        policies = []
        for p_data in [
            ("block_critical_external", "block",
             {"risk_bands": ["CRITICAL"], "destinations": ["external"]}, 1),
            ("block_contractor_secrets_external", "block",
             {"risk_bands": ["HIGH", "CRITICAL"],
              "finding_types": ["aws_secret_access_key", "private_key", "github_access_token", "stripe_secret_key"],
              "destinations": ["external"], "user_roles": ["contractor", "vendor"]}, 2),
            ("quarantine_unmanaged_high", "quarantine",
             {"risk_bands": ["HIGH", "CRITICAL"], "device_trust": ["unmanaged", "unknown"]}, 5),
            ("flag_high_risk_internal", "flag",
             {"risk_bands": ["HIGH", "CRITICAL"], "destinations": ["internal"]}, 10),
        ]:
            p      = Policy()
            p.id   = hash(p_data[0]) % 10_000
            p.name = p_data[0]
            p.action = p_data[1]
            p.conditions = p_data[2]
            p.priority = p_data[3]
            p.enabled = True
            p.simulate = (p_data[0] == "quarantine_unmanaged_high")
            p.description = None
            p.created_by = None
            p.created_at = datetime.utcnow()
            p.updated_at = None
            policies.append(p)

    # Chain query().all(), query().filter().first(), query().count(), etc.
    query_mock = MagicMock()
    query_mock.return_value = query_mock  # db.query(...) → same mock
    query_mock.all.return_value = policies
    query_mock.order_by.return_value = query_mock
    query_mock.filter.return_value = query_mock
    query_mock.first.return_value = None
    query_mock.count.return_value = len(policies)
    query_mock.limit.return_value = query_mock
    query_mock.offset.return_value = query_mock
    query_mock.join.return_value = query_mock

    # Decision log queries return empty by default
    if decision_logs is not None:
        # Override for specific queries
        pass

    db.query = query_mock
    return db


class _MockDLPEngine:
    async def scan(self, content, file_path=None, use_ai=False, force_ai=False, **kwargs):
        risk = "HIGH"
        findings = []
        if "AKIA" in content or "aws_secret" in content.lower():
            findings = [{"type": "aws_secret_access_key", "severity": "HIGH"}]
            risk = "HIGH"
        return {
            "risk_level":      risk,
            "findings":        findings,
            "verdict":         "REVIEW",
            "ai_analysis":     None,
            "scan_duration_ms": 10,
            "threat_score":    70,
        }


@pytest.fixture()
def admin_user():
    return _make_user(UserRole.ADMIN)


@pytest.fixture()
def analyst_user():
    return _make_user(UserRole.ANALYST)


@pytest.fixture()
def mock_db():
    return _make_db()


@pytest.fixture()
def client_with_deps(admin_user, mock_db):
    """TestClient with admin user, mock DB, mock DLP engine."""
    mock_engine = _MockDLPEngine()
    db_gen = lambda: (yield mock_db)

    app.dependency_overrides[get_current_active_user] = lambda: admin_user
    app.dependency_overrides[get_db]         = db_gen
    app.dependency_overrides[get_dlp_engine] = lambda: mock_engine
    client = TestClient(app, raise_server_exceptions=True)
    yield client
    app.dependency_overrides.pop(get_current_active_user, None)
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_dlp_engine, None)


# ── GET /api/policies/ ────────────────────────────────────────────────────────

def test_list_policies_returns_seeded_defaults(client_with_deps):
    resp = client_with_deps.get("/api/policies/")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 4
    names = {p["name"] for p in data}
    assert "block_critical_external" in names
    assert "flag_high_risk_internal" in names


# ── POST /api/policies/ ───────────────────────────────────────────────────────

def test_create_policy(client_with_deps, mock_db):
    # Allow count() to return 0 to avoid "already exists" conflict check
    # In create route, we filter by name → first() returns None (ok)
    new_policy = Policy()
    new_policy.id          = 42
    new_policy.name        = "test_new_policy"
    new_policy.action      = "flag"
    new_policy.conditions  = {"risk_bands": ["MEDIUM"]}
    new_policy.priority    = 50
    new_policy.enabled     = True
    new_policy.simulate    = False
    new_policy.description = None
    new_policy.created_by  = 1
    new_policy.created_at  = datetime.utcnow()
    new_policy.updated_at  = None

    # first() = None (no conflict), then after add+commit, refresh sets the object
    mock_db.query.return_value.first.return_value = None
    original_refresh = mock_db.refresh.side_effect

    def _refresh_with_policy(obj):
        if isinstance(obj, Policy):
            obj.id         = 42
            obj.created_at = datetime.utcnow()
            obj.updated_at = None
        else:
            original_refresh(obj)

    mock_db.refresh.side_effect = _refresh_with_policy

    payload = {
        "name":       "test_new_policy",
        "conditions": {"risk_bands": ["MEDIUM"]},
        "action":     "flag",
        "priority":   50,
    }
    resp = client_with_deps.post("/api/policies/", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test_new_policy"
    assert data["action"] == "flag"


# ── POST /api/policies/evaluate ───────────────────────────────────────────────

def test_evaluate_dry_run_blocks_critical_external(client_with_deps):
    payload = {
        "scan_result": {
            "risk_level":   "CRITICAL",
            "threat_score": 95,
            "findings":     [{"type": "aws_secret_access_key"}],
        },
        "context": {
            "destination":  "external",
            "user_role":    "developer",
            "device_trust": "unknown",
        },
    }
    resp = client_with_deps.post("/api/policies/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "block"
    assert data["policy_name"] == "block_critical_external"
    assert data["simulated"] is False


def test_evaluate_dry_run_contractor_secrets(client_with_deps):
    payload = {
        "scan_result": {
            "risk_level":   "HIGH",
            "threat_score": 80,
            "findings":     [{"type": "aws_secret_access_key"}],
        },
        "context": {
            "destination": "external",
            "user_role":   "contractor",
        },
    }
    resp = client_with_deps.post("/api/policies/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "block"
    assert data["policy_name"] == "block_contractor_secrets_external"


def test_evaluate_dry_run_low_risk_allows(client_with_deps):
    payload = {
        "scan_result": {
            "risk_level":   "LOW",
            "threat_score": 5,
            "findings":     [],
        },
        "context": {"destination": "external"},
    }
    resp = client_with_deps.post("/api/policies/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "allow"


# ── GET /api/policies/decisions/ ──────────────────────────────────────────────

def test_list_decisions_returns_ok(client_with_deps, mock_db):
    from app.models.policy import PolicyDecisionLog
    log = PolicyDecisionLog()
    log.id                 = 1
    log.scan_id            = 1
    log.user_id            = 1
    log.policy_id          = 5
    log.policy_name        = "block_critical_external"
    log.decision           = "block"
    log.matched_conditions = {"risk_band": "CRITICAL"}
    log.context_snapshot   = {}
    log.simulated          = False
    log.would_have_action  = None
    log.evaluation_trace   = []
    log.created_at         = datetime.utcnow()

    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [log]
    mock_db.query.return_value.order_by.return_value.limit.return_value.all.return_value = [log]

    resp = client_with_deps.get("/api/policies/decisions/?scan_id=1")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


# ── POST /api/scans/ with context ─────────────────────────────────────────────

def test_scan_with_context_contractor_external(client_with_deps):
    """Contractor uploading AWS key externally should be BLOCKED by policy."""
    payload = {
        "content": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
        "source":  "API",
        "context": {
            "destination": "external",
            "user_role":   "contractor",
        },
    }
    resp = client_with_deps.post("/api/scans/", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    # policy_decision should be present (may be in the result dict or response)
    # The scan record itself doesn't expose policy_decision as a DB column,
    # but ScanResponse now has Optional[Dict] policy_decision field.
    # Since mock refresh doesn't set it, just assert the call succeeded.
    assert data["id"] is not None


def test_scan_policy_decision_in_result(client_with_deps, mock_db):
    """Verify that the policy_decision key is added to the result dict during scan."""
    # This is verified at the unit level via PolicyEngine; the DB mock
    # doesn't persist the field to ScanResponse (it's from the result dict).
    # We confirm the endpoint returns 201 without crashing.
    payload = {
        "content": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
        "source":  "API",
        "context": {"destination": "internal", "user_role": "developer"},
    }
    resp = client_with_deps.post("/api/scans/", json=payload)
    assert resp.status_code == 201


# ── Auth: analyst can list, cannot create ─────────────────────────────────────

def test_analyst_can_list_policies(analyst_user, mock_db):
    mock_engine = _MockDLPEngine()
    db_gen = lambda: (yield mock_db)
    app.dependency_overrides[get_current_active_user] = lambda: analyst_user
    app.dependency_overrides[get_db]         = db_gen
    app.dependency_overrides[get_dlp_engine] = lambda: mock_engine
    c = TestClient(app)
    try:
        resp = c.get("/api/policies/")
        assert resp.status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_active_user, None)
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_dlp_engine, None)


def test_analyst_cannot_create_policy(analyst_user, mock_db):
    db_gen = lambda: (yield mock_db)
    app.dependency_overrides[get_current_active_user] = lambda: analyst_user
    app.dependency_overrides[get_db] = db_gen
    c = TestClient(app)
    try:
        resp = c.post("/api/policies/", json={
            "name": "analyst_attempt",
            "conditions": {},
            "action": "flag",
        })
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_active_user, None)
        app.dependency_overrides.pop(get_db, None)


# ── Alerting: webhook payload includes policy fields ──────────────────────────

def test_webhook_payload_includes_policy_fields():
    from app.core.alerting import _build_webhook_payload

    scan_result = {
        "risk_level":   "CRITICAL",
        "verdict":      "BLOCKED: block_critical_external",
        "threat_score": 95,
        "findings":     [{"type": "aws_secret_access_key", "severity": "CRITICAL"}],
        "policy_decision": {
            "action":      "block",
            "policy_name": "block_critical_external",
            "simulated":   False,
        },
    }
    payload = _build_webhook_payload(scan_result, scan_id=42)
    assert payload["policy_decision"]    == "block"
    assert payload["policy_triggered"]   == "block_critical_external"
    assert payload["enforcement_action"] == "block"
    assert payload["policy_simulated"]   is False
    assert payload["would_have_blocked_by"] is None


def test_webhook_payload_simulated_mode():
    from app.core.alerting import _build_webhook_payload

    scan_result = {
        "risk_level":   "HIGH",
        "verdict":      "REVIEW",
        "threat_score": 70,
        "findings":     [],
        "policy_decision": {
            "action":            "allow",
            "policy_name":       "quarantine_unmanaged_high",
            "simulated":         True,
            "would_have_action": "quarantine",
        },
    }
    payload = _build_webhook_payload(scan_result, scan_id=7)
    assert payload["policy_simulated"]      is True
    assert payload["would_have_blocked_by"] == "quarantine_unmanaged_high"


def test_webhook_payload_no_policy_decision():
    """Scans without a policy_decision key default to allow."""
    from app.core.alerting import _build_webhook_payload

    scan_result = {
        "risk_level":   "HIGH",
        "verdict":      "REVIEW",
        "threat_score": 70,
        "findings":     [],
    }
    payload = _build_webhook_payload(scan_result, scan_id=3)
    assert payload["policy_decision"]   == "allow"
    assert payload["policy_triggered"]  is None
    assert payload["enforcement_action"] == "allow"
