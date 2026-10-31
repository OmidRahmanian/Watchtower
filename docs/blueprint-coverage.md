# Research blueprint coverage and release gates

Audit of `WatchTower_Research_and_Build_Blueprint.md` (31 October 2026).
The source is a phased proposal, not a claim that all future releases should
ship together. Commercial descriptions/research links are context. Suggested
frameworks/table names/routes are choices; later and explicitly deferred
features are not silently enabled by this build.

| Blueprint area | Current implementation / evidence |
| --- | --- |
| Authorized monitoring loop (sections 1, 3, 19, 22) | CLI/API, durable inventory, phase comparisons, grouped alerts, findings and relevant retests; `tests/e2e/` covers baseline/change/failure/fix/recurrence with synthetic approved rules |
| Scope and authorization (4) | Host boundaries, wildcard/apex distinction, IDN/IP canonicalization, exclusions, permitted schemes/ports and canonical path prefixes, validity windows, immutable revisions, live mid-job revocation, pinned connections; `tests/foundation/`, `tests/inventory/`, `tests/runtime/test_blueprint_controls.py` |
| Request budgets and egress (4, 11) | Shared durable host/project/global minute caps and cumulative run cap; production namespace firewall covers subprocesses as well as Python. IPv6 egress is disabled in that topology; laptop mode is not an OS sandbox |
| Candidates/provenance (5) | Manual/CSV/passive sources, per-source sightings, root seed, confidence score and separate human ownership state. Excluded candidates remain investigable and are never authorized by ownership alone |
| DNS, web and certificate inventory (5, 6) | DNS A/AAAA/CNAME, wildcard suppression, pinned native HTTP, response/time/title/header/body-digest/TLS metadata; hostname identity remains stable as addresses change |
| Monitoring/change detection (7) | Append-only snapshots, baseline/unchanged/changed/partial/failed/uncertain, debounce, DNS and HTTP changes, body/banner/certificate fingerprint and expiry changes; Changes page and acknowledgement |
| Rules/evidence (8) | Pinned native checks with source/license/engine/request/effect/evidence/remediation metadata, redaction, private content-addressed blobs, authenticated inert downloads and retention. All shipped rules remain pending human approval |
| Intelligence/priority (9) | KEV/EPSS/normalized advisories, preserving cache on failures, freshness, exact product/range matching, unknown/prerequisite handling, applicability-review output, approved component checks, explainable priority with asset importance and documented overrides |
| Findings/remediation (10) | In-progress and other workflow states, owners, reasons/expiry for exceptions, separate mitigation/remediation notes, history, recurrence, failed/inconclusive retests and verified resolution only |
| Durable operations (11) | Idempotent persistence, run request keys, optional equivalent-run reuse, leases/heartbeats, retries, cancellation/process groups, phase coverage and outbox. External chat delivery remains at least once |
| Architecture/storage (12, 13, 16, 17) | Modular Python/FastAPI/PostgreSQL/Alembic application, Celery/RabbitMQ option, typed profiles, project RLS/composite keys and append-only history; some facts are normalized JSON attributes rather than separate suggested tables |
| API (14) | Project-scoped authenticated scope/assets/timelines/candidates/findings/changes/runs/evidence/exports/intelligence/settings routes, paging and validated mutation models. Project/member creation stays in the database-admin CLI rather than granting global administration to an ordinary project token |
| Interface (15) | Overview, Scope, Candidates, Inventory/details/timeline, Changes, Findings/details, Intelligence, Runs, Alerts and read-only Settings. Persistent terminal Home with separate processing/dashboard windows |
| Public-release documentation (16, 19) | Installation, operations, coverage, architecture, threat model, private reporting guidance, placeholder environment, third-party component inventory and isolated lab instructions |
| Verification (20) | Synthetic tests for boundaries/rebinding/revocation, wildcard DNS, identity/deduplication, failed/partial scans, recovery, redaction, project authorization, stale feeds, exports and durable controls. No public-target scan is part of CI |

## Deliberate alternatives and limits

- The platform uses a pinned native HTTP implementation instead of the external
  Go httpx tool, and small native checks instead of unrestricted Nuclei templates.
  The legacy tools remain separate. Broad Nuclei/template, browser, callback,
  credential, IDOR, business-logic and XSS coverage is not claimed.
- The dashboard is plain DOM JavaScript rather than React/TypeScript. Captured
  data is rendered as text under a restrictive CSP.
- Host/CIDR/port and user-defined HTTP path-prefix policies are supported.
  Non-HTTP service enumeration, authenticated assessments and richer
  per-application access models require later adapters and acceptance tests.
- Advisory correlation produces reviewable applicability, not automatic
  exploitation. Full NVD CPE expression evaluation, automatic threat-triggered
  public scans, issue trackers, cloud/SaaS inventory and mitigation integrations
  are not enabled. The blueprint explicitly defers several of these to 0.3+.
- Runtime schedules and integrations are configured through typed profiles,
  environment and worker/cron commands. The Settings page shows them safely;
  it does not edit secrets or promote rules through the browser.

## Maintainer release gates

This is not a claim that every sentence in the roadmap is implemented.

1. A human must review and approve detection rules before enabling them. The
   production manifest is still pending; automated tests approve temporary
   fixture copies only. The normal lab reports partial coverage until approval.
2. The maintainer selected MIT for WatchTower and its native rules. Preserve
   third-party notices and review the actual dependency/tool/data versions
   included in a distribution; see `LICENSE` and `THIRD_PARTY_NOTICES.md`.
3. Reproduce the isolated Docker lab on the deployment host, review effective
   budgets and egress exceptions, configure notification destinations and
   schedule feed refresh/maintenance. Synthetic precision or throughput is not
   a commercial-platform parity claim.

Later roadmap work remains explicit so a quiet dashboard is never presented
as evidence that unsupported assessments ran.
