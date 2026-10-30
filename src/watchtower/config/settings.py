"""Typed configuration loaded from a profile file and environment variables.

Precedence, lowest to highest: model defaults, ``config/profiles/<profile>.toml``,
then environment variables named ``WATCHTOWER__<SECTION>__<KEY>`` (for example
``WATCHTOWER__DATABASE__URL``). The profile is chosen by ``WATCHTOWER_PROFILE``
(default ``development``). Profiles are looked up in ``WATCHTOWER_PROFILE_DIR``,
or in ``config/profiles`` under the current directory.

Secrets such as the database URL belong in the environment, not in profiles.
"""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from watchtower.domain.targets import PortSet
from watchtower.security.destinations import DestinationPolicy

ENV_PREFIX = "WATCHTOWER__"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatabaseSettings(_Section):
    url: SecretStr | None = None
    pool_size: int = Field(default=5, ge=1, le=100)
    max_overflow: int = Field(default=5, ge=0, le=100)
    statement_timeout_ms: int = Field(default=30_000, ge=0)
    echo: bool = False

    @field_validator("url")
    @classmethod
    def _postgres_only(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("database.url must be a postgresql:// or postgresql+psycopg:// URL")
        return value

    def sqlalchemy_url(self) -> str:
        if self.url is None:
            raise ValueError("database.url is not configured; set WATCHTOWER__DATABASE__URL")
        url = self.url.get_secret_value()
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
        return url


class ScopeSettings(_Section):
    default_permitted_ports: str = "80,443"
    max_redirects: int = Field(default=5, ge=0, le=20)
    allow_https_downgrade: bool = False
    allow_private_networks: bool = False
    extra_prohibited_networks: tuple[str, ...] = ()
    extra_prohibited_hostnames: tuple[str, ...] = ()
    policy_cache_seconds: float = Field(default=5.0, ge=0, le=300)

    @field_validator("default_permitted_ports")
    @classmethod
    def _ports(cls, value: str) -> str:
        return str(PortSet.parse(value))

    @model_validator(mode="after")
    def _destinations_parse(self) -> ScopeSettings:
        self.destination_policy()
        return self

    def destination_policy(self) -> DestinationPolicy:
        return DestinationPolicy.build(
            allow_private_networks=self.allow_private_networks,
            extra_networks=self.extra_prohibited_networks,
            extra_hostnames=self.extra_prohibited_hostnames,
        )


class AuthSettings(_Section):
    token_ttl_days: int | None = Field(default=90, ge=1)


class Settings(_Section):
    profile: str = "development"
    log_level: str = "INFO"
    database: DatabaseSettings = DatabaseSettings()
    scope: ScopeSettings = ScopeSettings()
    auth: AuthSettings = AuthSettings()


def load_settings(profile: str | None = None, *, environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    profile = profile or env.get("WATCHTOWER_PROFILE", "development")
    if not profile.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"invalid profile name: {profile!r}")
    directory = Path(env.get("WATCHTOWER_PROFILE_DIR", "config/profiles"))
    path = directory / f"{profile}.toml"
    data: dict[str, Any] = {}
    if path.is_file():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    elif "WATCHTOWER_PROFILE" in env or profile != "development":
        raise FileNotFoundError(f"settings profile not found: {path}")
    data = _merge(data, _from_environment(env))
    data["profile"] = profile
    return Settings.model_validate(data)


def _from_environment(env: Mapping[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, raw in env.items():
        if not name.startswith(ENV_PREFIX):
            continue
        path = [part.lower() for part in name.removeprefix(ENV_PREFIX).split("__") if part]
        if not path:
            continue
        value: Any = raw
        if raw[:1] in "[{":
            value = json.loads(raw)
        node = result
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value
    return result


def _merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged
