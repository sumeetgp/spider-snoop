"""
Entity Scoring Configuration
=============================
Loads entity threat weights from app/config/entity_weights.yaml at runtime.

Hot-reload: the file is re-read automatically whenever its mtime changes —
no API restart required.  Edit entity_weights.yaml and the next scan picks
up the new values.

Scoring model
-------------
Scores are CUMULATIVE.  A document containing multiple findings accumulates
the weight of every finding:

    raw_score = sum(get_weight(entity_type) for each finding)

Two thresholds in the config file govern automatic actions:
    _incident_threshold      (default 100)  → risk level HIGH / INCIDENT
    _block_action_threshold  (default 250)  → risk level CRITICAL / BLOCK

The DB stores a normalised 0–100 threat_score; use normalize_score() for that.

Public API
----------
    get_weight(entity_type, fallback_severity=None)  → int
    score_findings(findings)                         → int  (raw cumulative)
    normalize_score(raw_score)                       → int  (0–100)
    get_action(raw_score)                            → str  "ALLOW"|"INCIDENT"|"BLOCK"
    get_incident_threshold()                         → int
    get_block_threshold()                            → int
    reload_weights()                                 → None (force reload)
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "entity_weights.yaml"

# ── Alias map: internal DLP engine names → config file keys ──────────────────
# Add entries here when a new internal entity type is introduced.
_ALIAS: Dict[str, str] = {
    # Secrets / credentials
    "aws_secret_key":         "aws_secret_access_key",
    "aws_access_key":         "aws_secret_access_key",
    "aws_session_token":      "aws_secret_access_key",
    "github_token":           "github_access_token",
    "slack_api_token":        "slack_bot_token",
    "slack_webhook":          "slack_bot_token",
    "generic_api_key":        "aws_secret_access_key",  # treat unknown API keys as critical
    "bearer_token":           "jwt_secret_key",
    "jwt_token":              "jwt_secret_key",
    "google_api_key":         "gcp_service_account_key",
    "password_in_code":       "database_password",
    "db_connection_string":   "database_password",

    # PEM / key blocks
    "ssh_private_key":        "private_key",
    "pgp_private_key":        "private_key",
    "ed25519_private_key":    "private_key",
    "ecdsa_private_key":      "private_key",
    "certificate":            "certificate",

    # Cloud & SaaS API keys (new patterns)
    "stripe_secret_key":      "stripe_secret_key",
    "stripe_publishable_key": "stripe_publishable_key",
    "stripe_restricted_key":  "stripe_restricted_key",
    "twilio_account_sid":     "twilio_account_sid",
    "twilio_auth_token":      "twilio_auth_token",
    "sendgrid_api_key":       "sendgrid_api_key",
    "mailgun_api_key":        "mailgun_api_key",
    "huggingface_token":      "huggingface_token",
    "npm_access_token":       "npm_access_token",
    "cloudflare_api_token":   "cloudflare_api_token",
    "azure_sas_token":        "azure_sas_token",
    "azure_connection_string":"azure_connection_string",
    "docker_registry_auth":   "docker_registry_auth",
    "discord_webhook":        "discord_webhook",
    "telegram_bot_token":     "telegram_bot_token",
    "pagerduty_key":          "pagerduty_key",

    # Financial / health PII
    "credit_card":            "validated_credit_card",
    "ssn":                    "us_social_security_number",
    "medical_record":         "medical_record_number",
    "bank_account":           "bank_account_number",
    "routing_number":         "bank_routing_number",
    "iban":                   "bank_account_number",

    # Medical / Healthcare (HIPAA)
    "icd_10":                 "icd10_code",
    "icd10":                  "icd10_code",
    "icd_code":               "icd10_code",
    "dea":                    "dea_number",
    "npi":                    "npi_number",
    "national_provider":      "npi_number",
    "ndc":                    "ndc_code",
    "drug_code":              "ndc_code",
    "patient_id":             "medical_patient_id",

    # General PII
    "passport":               "passport_number",
    "dob":                    "date_of_birth",
    "email":                  "email_address",
    "phone_us":               "phone_number",
    "ipv4":                   "ip_address_v4",
    "ipv6":                   "ip_address_v6",

    # Presidio NER entity types
    "us_ssn":                 "us_social_security_number",
    "email_address":          "email_address",
    "phone_number":           "phone_number",
    "credit_card":            "validated_credit_card",
    "person":                 "person_name",
    "location":               "physical_address",
    "us_passport":            "passport_number",
    "iban_code":              "bank_account_number",
    "ip_address":             "ip_address_v4",
    "aws_key_id":             "aws_secret_access_key",
    "github_token":           "github_access_token",
    "google_api_key":         "gcp_service_account_key",
    "private_key":            "private_key",
    "slack_token":            "slack_bot_token",
}

# ── Module cache ──────────────────────────────────────────────────────────────
_weights:    Dict[str, int] = {}
_global:     Dict[str, int] = {}
_last_mtime: float = 0.0


def _load() -> None:
    """Parse entity_weights.yaml into the module cache."""
    global _weights, _global, _last_mtime

    try:
        with open(_CONFIG_PATH, "r") as f:
            raw: dict = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.error(f"entity_weights.yaml not found at {_CONFIG_PATH}; scoring disabled")
        return
    except yaml.YAMLError as exc:
        logger.error(f"entity_weights.yaml parse error: {exc}; keeping previous config")
        return

    _weights = {k: int(v) for k, v in raw.items() if not str(k).startswith("_")}
    _global  = {k: int(v) for k, v in raw.items() if     str(k).startswith("_")}
    _last_mtime = _CONFIG_PATH.stat().st_mtime

    logger.info(
        f"Loaded {len(_weights)} entity weights | "
        f"incident_threshold={get_incident_threshold()} "
        f"block_threshold={get_block_threshold()}"
    )


def _maybe_reload() -> None:
    """Re-load config if the file has been modified since last load."""
    try:
        if _CONFIG_PATH.stat().st_mtime != _last_mtime:
            logger.info("entity_weights.yaml changed — hot-reloading")
            _load()
    except FileNotFoundError:
        pass


def reload_weights() -> None:
    """Force an immediate reload (call from an admin endpoint if needed)."""
    _load()


# ── Public accessors ──────────────────────────────────────────────────────────

def get_incident_threshold() -> int:
    return _global.get("_incident_threshold", 100)


def get_block_threshold() -> int:
    return _global.get("_block_action_threshold", 250)


def get_weight(entity_type: str, fallback_severity: Optional[str] = None) -> int:
    """
    Return the configured weight for *entity_type*.

    Resolution order:
      1. Exact match in config (after lowercasing)
      2. Alias map lookup
      3. Fallback to _default_unmapped_entity (default 0)
    """
    _maybe_reload()
    key = (entity_type or "").lower().strip()

    if key in _weights:
        return _weights[key]

    canonical = _ALIAS.get(key)
    if canonical and canonical in _weights:
        return _weights[canonical]

    return _global.get("_default_unmapped_entity", 0)


def score_findings(findings: List[dict]) -> int:
    """
    Return the raw cumulative threat score for a list of finding dicts.

    Each finding contributes its entity weight independently — an entity
    appearing multiple times is counted once (deduplicated by type).
    Compare the result against get_incident_threshold() /
    get_block_threshold() to determine the appropriate action.
    """
    _maybe_reload()
    if not findings:
        return 0

    # Deduplicate by entity type so a single entity found in 10 places
    # doesn't inflate the score unreasonably.
    seen_types: set = set()
    total = 0
    for f in findings:
        etype = (f.get("type") or "").lower().strip()
        if etype not in seen_types:
            seen_types.add(etype)
            total += get_weight(etype, f.get("severity"))
    return total


def normalize_score(raw_score: int) -> int:
    """
    Map a raw cumulative score to a 0–100 value for DB storage.

    Uses _block_action_threshold as the 100% mark so the full range
    is exploited.  Scores at or above the block threshold return 100.
    """
    block = get_block_threshold()
    return min(int(raw_score / block * 100), 100)


def get_action(raw_score: int) -> str:
    """
    Return the recommended action string for a given raw cumulative score.

        "BLOCK"    — raw_score >= _block_action_threshold
        "INCIDENT" — raw_score >= _incident_threshold
        "ALLOW"    — below both thresholds
    """
    if raw_score >= get_block_threshold():
        return "BLOCK"
    if raw_score >= get_incident_threshold():
        return "INCIDENT"
    return "ALLOW"


# Eager load at import time
_load()
