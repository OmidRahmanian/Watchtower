from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from watchtower.config import load_settings
from watchtower.domain.errors import AuthenticationFailed, PermissionDenied
from watchtower.security.auth import (
    Permission,
    Principal,
    PrincipalKind,
    ProjectContext,
    ProjectRole,
    generate_token,
    parse_token,
    token_matches,
)

PROFILES = Path(__file__).resolve().parents[2] / "config" / "profiles"


def test_profiles_load_and_environment_overrides() -> None:
    env = {
        "WATCHTOWER_PROFILE_DIR": str(PROFILES),
        "WATCHTOWER__DATABASE__URL": "postgresql://u:p@db/watchtower",
        "WATCHTOWER__SCOPE__MAX_REDIRECTS": "2",
        "WATCHTOWER__SCOPE__EXTRA_PROHIBITED_NETWORKS": '["203.0.113.0/24"]',
    }
    settings = load_settings("production", environ=env)
    assert settings.profile == "production"
    assert settings.database.pool_size == 10
    assert settings.database.sqlalchemy_url() == "postgresql+psycopg://u:p@db/watchtower"
    assert settings.scope.max_redirects == 2
    assert "p@db" not in repr(settings)  # secrets are masked


@pytest.mark.parametrize("profile", ["development", "test", "production"])
def test_every_profile_is_valid(profile: str) -> None:
    assert load_settings(profile, environ={"WATCHTOWER_PROFILE_DIR": str(PROFILES)}).profile == profile


def test_unknown_settings_are_rejected() -> None:
    with pytest.raises(ValidationError):
        load_settings(environ={"WATCHTOWER_PROFILE_DIR": str(PROFILES), "WATCHTOWER__SCOPE__ALLOW_EVERYTHING": "1"})


def test_non_postgres_url_rejected() -> None:
    with pytest.raises(ValidationError):
        load_settings(environ={"WATCHTOWER_PROFILE_DIR": str(PROFILES), "WATCHTOWER__DATABASE__URL": "mongodb://x"})


def test_missing_named_profile_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_settings("staging", environ={"WATCHTOWER_PROFILE_DIR": str(tmp_path)})
    with pytest.raises(ValueError):
        load_settings("../etc/passwd", environ={"WATCHTOWER_PROFILE_DIR": str(tmp_path)})


def test_bad_prohibited_network_rejected() -> None:
    with pytest.raises(ValidationError):
        load_settings(environ={"WATCHTOWER_PROFILE_DIR": str(PROFILES), "WATCHTOWER__SCOPE__EXTRA_PROHIBITED_NETWORKS": '["10.0.0.1/8"]'})


def test_tokens() -> None:
    token, prefix, digest = generate_token()
    assert parse_token(token) == prefix
    assert token_matches(token, digest)
    assert not token_matches(token + "x", digest)
    assert digest not in token
    for bad in ["", "wt_short_x", token.replace("wt_", "xx_"), token + "!"]:
        with pytest.raises(AuthenticationFailed):
            parse_token(bad)


def test_roles_and_permissions() -> None:
    principal = Principal(uuid4(), PrincipalKind.USER, "Analyst")
    viewer = ProjectContext(uuid4(), principal, ProjectRole.VIEWER)
    assert viewer.can(Permission.VIEW)
    with pytest.raises(PermissionDenied):
        viewer.require(Permission.MANAGE_SCOPE)
    operator = ProjectContext(uuid4(), principal, ProjectRole.OPERATOR)
    assert operator.can(Permission.OPERATE) and not operator.can(Permission.MANAGE_SCOPE)
    owner = ProjectContext(uuid4(), principal, ProjectRole.OWNER)
    assert all(owner.can(permission) for permission in Permission)
    disabled = ProjectContext(uuid4(), Principal(uuid4(), PrincipalKind.USER, "Gone", disabled=True), ProjectRole.OWNER)
    assert not disabled.can(Permission.VIEW)
