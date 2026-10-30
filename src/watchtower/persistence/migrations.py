"""Run the Alembic migrations without an ini file."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config


def migrations_directory() -> Path:
    """Locate the migrations: ``WATCHTOWER_MIGRATIONS_DIR``, the source tree, or the installed wheel."""
    override = os.environ.get("WATCHTOWER_MIGRATIONS_DIR")
    candidates = [Path(override)] if override else []
    package = Path(__file__).resolve().parent.parent
    candidates += [package.parent.parent / "migrations", package / "_migrations"]
    for candidate in candidates:
        if (candidate / "env.py").is_file():
            return candidate
    raise FileNotFoundError("WatchTower migrations directory not found")


def alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(migrations_directory()))
    # Alembic's config parser treats % as interpolation.
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def upgrade(url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(url), revision)


def downgrade(url: str, revision: str) -> None:
    command.downgrade(alembic_config(url), revision)


def current(url: str) -> None:
    command.current(alembic_config(url), verbose=False)
