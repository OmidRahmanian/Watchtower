"""Immutable URL/scheme/check policy, independent of all outbound transports."""
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from watchtower.domain.errors import InvalidScopeRule
from watchtower.domain.scope import AuthorizationKind, AuthorizationReference, ScopeExecution, ScopePolicy, ScopeRevision, ScopeRule
from watchtower.domain.targets import PortSet


def policy():
    project = uuid4()
    revision = ScopeRevision(id=uuid4(), project_id=project, number=1, rules=(ScopeRule.parse("example.com"),),
        authorization=AuthorizationReference(AuthorizationKind.ASSET_OWNER, "owned fixture", "Test owner"),
        permitted_ports=PortSet.parse("80,443"), created_at=datetime.now(timezone.utc),
        execution_policy=ScopeExecution(allowed_schemes=("https",), allowed_paths=("/api",), excluded_paths=("/api/private",),
                                        allowed_check_kinds=("http",), max_requests_per_run=20))
    return ScopePolicy(project, revision)


@pytest.mark.parametrize("path", ["/api", "/api/health", "/api/v1/resource"])
def test_allowed_path_prefix_respects_boundaries(path):
    assert policy().check_url("https://example.com" + path)


@pytest.mark.parametrize("path", ["/", "/api-other", "/api/private", "/api/private/child", "/api/%2e%2e/admin",
                                   "/api/%252e%252e/admin", "/api/private%2fchild", "/api/private;session=1"])
def test_exclusions_traversal_and_ambiguous_paths_are_denied(path):
    assert not policy().check_url("https://example.com" + path)


def test_scheme_host_and_address_checks_are_independent_of_paths():
    p = policy()
    assert not p.check_url("http://example.com/api")
    assert not p.check_url("https://example.com.attacker.test/api")
    assert not p.check_connection("example.com", 443, ["169.254.169.254"])
    assert p.execution_policy.max_requests_per_run == 20


@pytest.mark.parametrize("kwargs", [{"allowed_schemes": ("ftp",)}, {"allowed_paths": ("//evil",)},
                                    {"allowed_paths": ("/api/../admin",)}, {"max_requests_per_run": 0}])
def test_invalid_scope_execution_policy_is_rejected(kwargs):
    with pytest.raises((InvalidScopeRule, ValueError)):
        ScopeExecution(**kwargs)
