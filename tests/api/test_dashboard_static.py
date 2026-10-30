"""The dashboard renders captured content as text and runs under a strict CSP."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from watchtower.api import create_app
from watchtower.persistence import Database
from watchtower.services.evidence_store import FilesystemBlobStore

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


def test_script_never_parses_data_as_html_or_code():
    script = (FRONTEND / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                 "setTimeout(\"", "javascript:"):
        assert sink not in script, sink


def test_page_has_no_inline_code_or_styles():
    page = (FRONTEND / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", page)
    assert not re.search(r"\son[a-z]+=", page)
    assert "style=" not in page and "<style" not in page


@pytest.fixture
def client(tmp_path):
    # No route used here touches the database, so the engine never connects.
    database = Database(create_engine("postgresql+psycopg://unused@127.0.0.1:9/unused"))
    with TestClient(create_app(database, blobs=FilesystemBlobStore(tmp_path), runs=None)) as test_client:
        yield test_client


def test_dashboard_and_assets_are_served_with_security_headers(client):
    page = client.get("/")
    assert page.status_code == 200 and "WatchTower" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp
    script = client.get("/static/app.js")
    assert script.status_code == 200 and script.headers["x-content-type-options"] == "nosniff"
    assert client.get("/static/../pyproject.toml").status_code == 404


def test_no_third_party_docs_pages_on_the_dashboard_origin(client):
    assert client.get("/api/v1/docs").status_code == 404
    assert client.get("/api/v1/openapi.json").json()["info"]["title"] == "WatchTower"
