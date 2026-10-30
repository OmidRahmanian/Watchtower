"""Project-scoped HTTP API and dashboard. Build the application with ``create_app``.

``create_app`` is imported lazily so the CLI can use the query and schema
modules without the optional web dependencies installed.
"""

from __future__ import annotations

from typing import Any

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from watchtower.api.app import create_app

        return create_app
    raise AttributeError(name)
