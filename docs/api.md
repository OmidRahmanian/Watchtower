# HTTP API

Base path: `/api/v1`. The OpenAPI document is at `/api/v1/openapi.json`. Load it into any OpenAPI viewer; the server does not host one, because viewers load third-party scripts.

## Authentication and authorization

Every route except `/health` needs `Authorization: Bearer wt_<prefix>_<secret>`. Create tokens with `watchtower bootstrap` or `watchtower member add` ([installation.md](installation.md#3-create-a-project-and-its-owner)). Only a token's SHA-256 digest is stored.

Project routes live under `/projects/{project_id}`. For each request the API resolves the token's role in that project, checks the permission the action needs, and reads through a project-scoped database transaction, so PostgreSQL row-level security confines it to that project.

| Permission | Roles | Routes |
| --- | --- | --- |
| `view` | viewer, operator, owner | every `GET`, `POST /scope/check` |
| `operate` | operator, owner | `POST /runs`, `POST /runs/{id}/cancel`, `POST /findings/{id}/status`, `POST /findings/{id}/retest`, asset/finding `PATCH`, change acknowledgement and prioritization |
| `manage_scope` | owner | `POST /scope`, `POST /scope/{revision}/revoke` |

Two cases return `404 not_found`, not `403`, so the API does not reveal which projects exist: a project you are not a member of, and a token restricted to a different project.

## Errors

Errors are JSON: `{"error": "<code>", "detail": "<message>"}`.

| Status | `error` | When |
| --- | --- | --- |
| 401 | `authentication_failed` | missing, malformed, unknown, expired or revoked token, or a disabled principal |
| 403 | `permission_denied` | your role lacks the permission |
| 404 | `not_found` | no such project (for you), asset, finding, evidence or run |
| 409 | `scope_violation` | the action needs authorization the current scope does not give, such as a run with no published scope |
| 409 | `invalid_transition` | a workflow change the finding lifecycle forbids, such as marking a finding resolved by hand |
| 409 | `request_conflict` | a run idempotency key is reused with different arguments or scope |
| 409 | `run_cancelled` | work for a run that was cancelled |
| 422 | `invalid_request`, `invalid_scope`, `invalid_target`, `invalid_cursor` | the request does not validate |
| 503 | `runs_unavailable` | the monitoring runtime is not installed on this server |

## Pagination

Listings return `{"items": [...], "next_cursor": "..." | null}`. Pass `cursor` and `limit` (1–200, default 50) to get the next page. Cursors are keyset positions, so pages do not repeat or skip rows when new rows arrive. A cursor from one listing is rejected by another.

## Routes

| Method and path | Purpose |
| --- | --- |
| `GET /health` | liveness and version; no token needed |
| `GET /projects` | the projects your token can use, with your role and permissions |
| `GET /projects/{id}` | one project |
| `GET /projects/{id}/overview` | current scope, totals, the latest runs, and each detection rule's approval state |
| `GET /projects/{id}/scope` | the current revision and full history |
| `POST /projects/{id}/scope` | publish a revision: `includes`, `excludes`, `permitted_ports`, `authorization {kind, reference, granted_by, valid_from?, valid_until?}`, and `attest_authorized: true` |
| `POST /projects/{id}/scope/{revision}/revoke` | `{"reason": ...}` |
| `POST /projects/{id}/scope/check` | `{"target": ..., "port"?: ...}`; returns the decision and sends nothing |
| `GET /projects/{id}/assets` | inventory; filter with `kind`, `search`, `owner`, `tag`, `technology` |
| `GET /projects/{id}/assets/{asset}` | one asset with its recent observations |
| `GET /projects/{id}/findings` | filter with `status` and `severity` (both repeatable) and `asset_id`, `owner`, `confidence`, `priority` |
| `GET /projects/{id}/findings/{finding}` | the full record: detection, remediation, history and evidence list |
| `POST /projects/{id}/findings/{finding}/status` | triage: `{"status": "triaged" \| "in_progress" \| "open" \| "accepted_risk" \| "false_positive", "reason": ...}` |
| `POST /projects/{id}/findings/{finding}/retest` | queue a retest of this finding's check and endpoint |
| `GET /projects/{id}/evidence/{evidence}` | evidence metadata, plus its redacted content as JSON data |
| `GET /projects/{id}/evidence/{evidence}/download` | the stored bytes as an attachment (below) |
| `GET /projects/{id}/runs` | runs, newest first |
| `POST /projects/{id}/runs` | queue a run: `{"targets"?: [...], "phases"?: [...], "reason"?: ...}` |
| `GET /projects/{id}/runs/{run}` | jobs, phase snapshots, `checks_not_run`, and `retest_outcome` |
| `POST /projects/{id}/runs/{run}/cancel` | `{"reason": ...}` |
| `GET /projects/{id}/alerts` | the notification outbox, newest first; filter with `event_type` |

## Reading results correctly

- **Run `status`** is one of `queued`, `running`, `succeeded`, `partial`, `failed` or `cancelled`. `partial` means the run finished but its coverage was incomplete, for example because rules are pending approval or a phase could not compare. `failed` and `cancelled` are never reported as success.
- **Phase `comparison`** is `baseline`, `unchanged`, `changed`, `partial`, `failed` or `uncertain`. `uncertain` and `failed` mean the phase could not see its targets. Clients show them as problems, not as "no change".
- **Finding `status`** is the workflow state. Only a relevant, conclusive negative retest moves a finding to `resolved`. It cannot be set by hand.
- **Finding `remediation`** says how far a fix has been verified:

  | Value | Meaning |
  | --- | --- |
  | `not_retested` | no retest has been requested |
  | `retest_pending` | a retest was requested and has no conclusive result yet |
  | `retest_failed` | the last retest could not run its request, so it proves nothing |
  | `retest_inconclusive` | the last retest got a response that cannot establish a negative, so it proves nothing |
  | `still_present` | the last retest detected the issue again |
  | `verified_fixed` | a conclusive negative retest resolved the finding |

- **`checks_not_run`** on a run lists rules that should have run but did not, usually pending maintainer approval. Those checks prove nothing either way.

## Evidence

Evidence is redacted when it is captured: secrets, credential-bearing headers and every value of `.env`-style files are removed before storage. Only redacted content is ever stored. The JSON route returns it as data. The dashboard renders it with `textContent` only, and the CLI escapes control characters.

The download route checks the token, the role and the project, and confirms that the stored blob belongs to that project and still matches its SHA-256 digest. It then responds with:

```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="evidence-<id>.json"
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; sandbox
Cache-Control: no-store
X-WatchTower-SHA256: <digest of the stored bytes>
```

A browser therefore saves the file instead of rendering it, even if captured content looks like HTML or script.

## Response headers

Every response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and a Content Security Policy that allows only same-origin scripts and styles, with no inline code. API responses also carry `Cache-Control: no-store`.

## Investigation and execution controls

All paths below share `/projects/{id}`. See the OpenAPI schemas for exact fields.

| Method and path | Purpose |
| --- | --- |
| `PATCH /assets/{asset}` | owner, tags, importance, human ownership state; operator/owner |
| `GET /assets/{asset}/timeline` | paginated observations |
| `GET /candidates` | provenance and live authorization status, separately from human ownership |
| `PATCH /findings/{finding}` | owner, remediation/mitigation notes, priority override and reason |
| `POST /findings/{finding}/prioritize` | recompute explainable priority from cached intelligence |
| `GET /changes` | paginated phase changes and latest acknowledgement |
| `POST /changes/{change}/acknowledge` | append a reason and actor without rewriting a snapshot |
| `GET /exports` | `dataset=assets|findings`, `format=json|csv`, bounded `limit` and `cursor` |
| `GET /intelligence` | freshness and reviewable applicability; asset paging via `after_asset` |
| `GET /settings` | redacted effective settings and rule approvals; read only |

Publishing scope accepts `execution_policy`: `allowed_schemes`, `allowed_paths`,
`excluded_paths`, `allowed_check_kinds`, `max_requests_per_run`. Path prefixes
are canonical and exclusions take precedence. `/scope/check` accepts an
absolute HTTP(S) URL to check these restrictions without sending traffic.
Authorization dates must contain a timezone. See [operations](operations.md).

`POST /runs` accepts `idempotency_key` and `reuse_active`. A retry with the same
key and payload returns the same run; a changed payload/scope returns 409.
Equivalent active-run reuse is opt-in and still constrained to one project and
scope revision. Dashboard and terminal requests use both controls.

Status transitions accept `risk_expires_at` for a future, time-limited accepted
risk. Owner maintenance returns expired exceptions to triage; it never marks a
finding fixed. Feed refresh and maintenance remain owner CLI operations.

Exports omit evidence and secrets, escape CSV formulas, and return downloads
with private, inert headers. JSON includes `next_cursor`; CSV uses
`X-Next-Cursor`. Evidence downloads past the configured retention period return
404 while historical metadata remains available.
