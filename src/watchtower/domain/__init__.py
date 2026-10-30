"""Domain contracts: canonical targets, scope rules and shared records."""

from watchtower.domain.errors import (
    AuthenticationFailed,
    InvalidScopeRule,
    InvalidTarget,
    NotFound,
    PermissionDenied,
    ScopeViolation,
    WatchtowerError,
)
from watchtower.domain.scope import (
    AuthorizationKind,
    AuthorizationReference,
    DecisionReason,
    NewScopeRevision,
    RedirectDecision,
    RuleEffect,
    RuleKind,
    ScopeDecision,
    ScopePolicy,
    ScopeRevision,
    ScopeRule,
)
from watchtower.domain.targets import PortSet, Target, TargetKind, canonical_hostname, canonical_ip, parse_target, parse_url

__all__ = [
    "AuthenticationFailed",
    "AuthorizationKind",
    "AuthorizationReference",
    "DecisionReason",
    "InvalidScopeRule",
    "InvalidTarget",
    "NewScopeRevision",
    "NotFound",
    "PermissionDenied",
    "PortSet",
    "RedirectDecision",
    "RuleEffect",
    "RuleKind",
    "ScopeDecision",
    "ScopePolicy",
    "ScopeRevision",
    "ScopeRule",
    "ScopeViolation",
    "Target",
    "TargetKind",
    "WatchtowerError",
    "canonical_hostname",
    "canonical_ip",
    "parse_target",
    "parse_url",
]
