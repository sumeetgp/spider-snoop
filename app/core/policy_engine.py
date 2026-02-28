"""Policy Evaluation Engine — Zero Trust Decision Layer"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from app.models.policy import Policy, PolicyAction

ROLE_RISK_SCORES: Dict[str, int] = {
    "contractor": 40,
    "vendor":     45,
    "viewer":     15,
    "analyst":    20,
    "developer":  20,
    "finance":    25,
    "admin":      10,
}


@dataclass
class ContextPayload:
    destination:  str = "unknown"   # "internal"|"external"|"cloud"|"api"
    user_role:    str = ""
    department:   str = ""
    device_trust: str = "unknown"   # "managed"|"unmanaged"|"unknown"
    geo_location: str = ""

    @property
    def identity_risk_score(self) -> int:
        return ROLE_RISK_SCORES.get(self.user_role.lower(), 20)


@dataclass
class PolicyDecision:
    action:             PolicyAction           = PolicyAction.ALLOW
    policy_id:          Optional[int]          = None
    policy_name:        Optional[str]          = None
    matched_conditions: Optional[dict]         = None
    simulated:          bool                   = False
    would_have_action:  Optional[PolicyAction] = None
    evaluation_trace:   List[dict]             = field(default_factory=list)

    @property
    def is_blocking(self) -> bool:
        return self.action == PolicyAction.BLOCK and not self.simulated

    def to_dict(self) -> dict:
        return {
            "action":             self.action.value,
            "policy_id":          self.policy_id,
            "policy_name":        self.policy_name,
            "matched_conditions": self.matched_conditions,
            "simulated":          self.simulated,
            "would_have_action":  self.would_have_action.value if self.would_have_action else None,
        }


class PolicyEngine:
    """First-match priority policy evaluator."""

    def evaluate(
        self,
        scan_result: dict,
        context: ContextPayload,
        policies: List[Policy],
        user=None,
    ) -> PolicyDecision:
        enabled = sorted([p for p in policies if p.enabled], key=lambda p: p.priority)
        trace: List[dict] = []

        for policy in enabled:
            matched = self._match(policy.conditions, scan_result, context, user)
            trace.append({
                "policy":   policy.name,
                "priority": policy.priority,
                "matched":  bool(matched),
            })
            if matched:
                action = PolicyAction(policy.action)
                return PolicyDecision(
                    action=PolicyAction.ALLOW if policy.simulate else action,
                    would_have_action=action if policy.simulate else None,
                    policy_id=policy.id,
                    policy_name=policy.name,
                    matched_conditions=matched,
                    simulated=policy.simulate,
                    evaluation_trace=trace,
                )

        return PolicyDecision(action=PolicyAction.ALLOW, evaluation_trace=trace)

    def _match(
        self,
        conditions: dict,
        scan_result: dict,
        context: ContextPayload,
        user,
    ) -> Optional[dict]:
        matched: dict = {}
        rl       = scan_result.get("risk_level", "LOW").upper()
        findings = scan_result.get("findings", [])
        score    = scan_result.get("threat_score", 0)

        # risk_bands
        if bands := conditions.get("risk_bands"):
            if rl not in [b.upper() for b in bands]:
                return None
            matched["risk_band"] = rl

        # finding_types
        if ftypes := conditions.get("finding_types"):
            overlap = {f["type"] for f in findings} & set(ftypes)
            if not overlap:
                return None
            matched["finding_types"] = list(overlap)

        # threat_score_min
        if (min_score := conditions.get("threat_score_min")) is not None:
            if score < min_score:
                return None
            matched["threat_score"] = score

        # destinations
        if dests := conditions.get("destinations"):
            if context.destination not in dests:
                return None
            matched["destination"] = context.destination

        # user_roles
        if roles := conditions.get("user_roles"):
            role_val = context.user_role.lower() or (
                getattr(user.role, "value", str(user.role)).lower() if user else ""
            )
            if role_val not in [r.lower() for r in roles]:
                return None
            matched["user_role"] = role_val

        # departments
        if depts := conditions.get("departments"):
            if context.department not in depts:
                return None
            matched["department"] = context.department

        # device_trust
        if trust := conditions.get("device_trust"):
            if context.device_trust not in trust:
                return None
            matched["device_trust"] = context.device_trust

        # geo_locations
        if geos := conditions.get("geo_locations"):
            if context.geo_location not in geos:
                return None
            matched["geo_location"] = context.geo_location

        # finding_count_min
        if (min_count := conditions.get("finding_count_min")) is not None:
            if len(findings) < min_count:
                return None
            matched["finding_count"] = len(findings)

        return matched if matched else {"default_match": True}
