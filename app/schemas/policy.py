"""Policy Engine Pydantic schemas"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class ConditionSchema(BaseModel):
    risk_bands:        List[str]     = []
    finding_types:     List[str]     = []
    threat_score_min:  Optional[int] = None
    destinations:      List[str]     = []
    user_roles:        List[str]     = []
    departments:       List[str]     = []
    device_trust:      List[str]     = []
    geo_locations:     List[str]     = []
    finding_count_min: Optional[int] = None


class PolicyCreate(BaseModel):
    name:        str
    description: Optional[str]      = None
    conditions:  ConditionSchema
    action:      str                 # "allow"|"flag"|"quarantine"|"block"
    priority:    int                 = 100
    enabled:     bool                = True
    simulate:    bool                = False


class PolicyUpdate(BaseModel):
    name:        Optional[str]             = None
    description: Optional[str]            = None
    conditions:  Optional[ConditionSchema] = None
    action:      Optional[str]            = None
    priority:    Optional[int]            = None
    enabled:     Optional[bool]           = None
    simulate:    Optional[bool]           = None


class PolicyOut(BaseModel):
    id:          int
    name:        str
    description: Optional[str]
    conditions:  Dict[str, Any]
    action:      str
    priority:    int
    enabled:     bool
    simulate:    bool
    created_by:  Optional[int]
    created_at:  datetime
    updated_at:  Optional[datetime]

    class Config:
        from_attributes = True


class ContextInput(BaseModel):
    destination:  str = "unknown"
    user_role:    str = ""
    department:   str = ""
    device_trust: str = "unknown"
    geo_location: str = ""


class PolicyEvaluateRequest(BaseModel):
    scan_result: Dict[str, Any]
    context:     ContextInput = ContextInput()


class PolicyDecisionOut(BaseModel):
    action:             str
    policy_id:          Optional[int]
    policy_name:        Optional[str]
    matched_conditions: Optional[Dict]
    simulated:          bool
    would_have_action:  Optional[str]
    evaluation_trace:   Optional[List[Dict]]


class PolicyDecisionLogOut(BaseModel):
    id:                 int
    scan_id:            Optional[int]
    user_id:            Optional[int]
    policy_id:          Optional[int]
    policy_name:        Optional[str]
    decision:           str
    matched_conditions: Optional[Dict]
    context_snapshot:   Optional[Dict]
    simulated:          bool
    would_have_action:  Optional[str]
    evaluation_trace:   Optional[List[Dict]]
    created_at:         datetime

    class Config:
        from_attributes = True
