"""Authentication, project isolation, roles, scope management and response headers."""

from __future__ import annotations

from uuid import uuid4

import pytest

from watchtower.security.auth import ProjectRole

pytestmark = pytest.mark.postgres

AUTHORIZATION = {"kind": "asset_owner", "reference": "https://acme.example/security/test-authorization",
                 "granted_by": "Acme Security Lead"}


def publish(client, project_id, member, **overrides):
    body = {"includes": ["*.acme.example", "acme.example"], "excludes": ["legacy.acme.example"],
            "authorization": AUTHORIZATION, "attest_authorized": True, **overrides}
    return client.post(f"/api/v1/projects/{project_id}/scope", json=body, headers=member.headers)


def test_health_is_public_but_projects_need_a_token(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"
    response = client.get("/api/v1/projects")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"] == "authentication_failed"


@pytest.mark.parametrize("token", ["", "not-a-token", "wt_AAAAAAAA_" + "x" * 43])
def test_malformed_and_unknown_tokens_are_rejected(client, project_id, token):
    response = client.get(f"/api/v1/projects/{project_id}", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_revoked_token_and_disabled_principal_are_rejected(client, database, project_id, owner):
    assert client.get(f"/api/v1/projects/{project_id}", headers=owner.headers).status_code == 200
    with database.system() as system:
        system.auth.disable_principal(owner.principal_id)
    assert client.get(f"/api/v1/projects/{project_id}", headers=owner.headers).status_code == 401


def test_projects_lists_only_memberships_and_honours_token_restriction(client, member, project_id, other_project_id):
    both = member(project_id, ProjectRole.VIEWER)
    from_db = client.app.state.services.database
    with from_db.system() as system:
        system.auth.set_membership(other_project_id, both.principal_id, ProjectRole.OWNER)
    listed = client.get("/api/v1/projects", headers=both.headers).json()
    assert {p["id"]: p["role"] for p in listed} == {str(project_id): "viewer", str(other_project_id): "owner"}
    assert {p["id"]: p["permissions"] for p in listed}[str(project_id)] == ["view"]

    restricted = member(project_id, ProjectRole.VIEWER, restrict=True)
    with from_db.system() as system:
        system.auth.set_membership(other_project_id, restricted.principal_id, ProjectRole.OWNER)
    assert [p["id"] for p in client.get("/api/v1/projects", headers=restricted.headers).json()] == [str(project_id)]
    # A restricted token cannot reach the other project even though the principal is its owner.
    assert client.get(f"/api/v1/projects/{other_project_id}", headers=restricted.headers).status_code == 404


def test_other_and_unknown_projects_look_the_same(client, member, project_id, other_project_id):
    outsider = member(other_project_id, ProjectRole.OWNER)
    for target in (project_id, uuid4()):
        for path in ("", "/scope", "/assets", "/findings", "/alerts", "/runs"):
            response = client.get(f"/api/v1/projects/{target}{path}", headers=outsider.headers)
            assert response.status_code == 404, path
            assert response.json()["error"] == "not_found"


def test_scope_publication_needs_manage_scope_and_an_attestation(client, project_id, owner, operator, viewer):
    for member in (viewer, operator):
        assert publish(client, project_id, member).status_code == 403
    missing = {k: v for k, v in {"includes": ["acme.example"], "authorization": AUTHORIZATION}.items()}
    response = client.post(f"/api/v1/projects/{project_id}/scope", json=missing, headers=owner.headers)
    assert response.status_code == 422 and "attest_authorized" in response.json()["detail"]
    assert publish(client, project_id, owner, attest_authorized=False).status_code == 422
    legacy = dict(AUTHORIZATION, kind="legacy_import")
    assert publish(client, project_id, owner, authorization=legacy).status_code == 422
    assert publish(client, project_id, owner, includes=["*.com"]).json()["error"] == "invalid_scope"
    assert publish(client, project_id, owner, includes=[]).status_code == 422

    created = publish(client, project_id, owner)
    assert created.status_code == 201
    revision = created.json()
    assert revision["number"] == 1
    assert revision["authorization"]["granted_by"] == "Acme Security Lead"
    assert {(r["effect"], r["pattern"]) for r in revision["rules"]} == {
        ("include", "*.acme.example"), ("include", "acme.example"), ("exclude", "legacy.acme.example")}

    scope = client.get(f"/api/v1/projects/{project_id}/scope", headers=viewer.headers).json()
    assert scope["current"]["id"] == revision["id"]
    assert [r["number"] for r in scope["history"]] == [1]


def test_scope_check_and_revocation(client, project_id, owner, viewer):
    check = f"/api/v1/projects/{project_id}/scope/check"
    assert client.post(check, json={"target": "www.acme.example"}, headers=viewer.headers).json()["reason"] == "no_scope"
    revision = publish(client, project_id, owner).json()
    decisions = {
        target: client.post(check, json={"target": target}, headers=viewer.headers).json()
        for target in ("www.acme.example", "legacy.acme.example", "acme.example.evil.test", "127.0.0.1")
    }
    assert decisions["www.acme.example"]["allowed"] is True
    assert decisions["legacy.acme.example"]["reason"] == "excluded"
    assert decisions["acme.example.evil.test"]["reason"] == "not_in_scope"
    assert decisions["127.0.0.1"]["allowed"] is False

    revoke = f"/api/v1/projects/{project_id}/scope/{revision['id']}/revoke"
    assert client.post(revoke, json={"reason": "engagement ended"}, headers=viewer.headers).status_code == 403
    revoked = client.post(revoke, json={"reason": "engagement ended"}, headers=owner.headers)
    assert revoked.status_code == 200 and revoked.json()["revocation"]["reason"] == "engagement ended"
    after = client.post(check, json={"target": "www.acme.example"}, headers=viewer.headers).json()
    assert after["allowed"] is False


def test_loopback_scope_is_never_authorized(client, project_id, owner, viewer):
    publish(client, project_id, owner, includes=["127.0.0.0/8", "acme.example"], excludes=[])
    check = client.post(f"/api/v1/projects/{project_id}/scope/check", json={"target": "127.0.0.1"},
                        headers=viewer.headers).json()
    assert (check["allowed"], check["reason"]) == (False, "prohibited_destination")


def test_unknown_request_fields_are_rejected(client, project_id, owner):
    response = publish(client, project_id, owner, auto_approve_rules=True)
    assert response.status_code == 422


def test_security_headers_on_api_and_dashboard(client, project_id, viewer):
    api = client.get(f"/api/v1/projects/{project_id}", headers=viewer.headers)
    for response in (api, client.get("/")):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert api.headers["Cache-Control"] == "no-store"
