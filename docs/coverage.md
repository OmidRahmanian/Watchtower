# Coverage

This page covers three things: what WatchTower looks at, what it deliberately does not do, and which automated tests prove each step of the user journey. Read it before relying on a quiet dashboard: an absence of findings only covers what is listed here.

## What a run examines

A run works through four phases for each root domain in the current scope revision. Every request is checked against that revision first.

| Phase | What it does | Sources | Never does |
| --- | --- | --- | --- |
| discovery | finds hostnames under the root | `subfinder` (passive sources), or a seed file / CSV (`manual`) | brute-force names; add a name that is out of scope |
| dns | resolves A, AAAA and CNAME for known hosts, with wildcard detection | the system resolver, or `pipeline.dns_nameservers` | treat a failed lookup as a removal |
| http | probes each host over the configured schemes and records status, title, headers, body digest and TLS certificate | a pinned connection to an address the scope approved | follow a redirect out of scope; send credentials |
| checks | runs the approved detection rules against each HTTP endpoint | `rules/` | run a rule that is pending approval |

Changes between runs become alerts: new assets, DNS and HTTP changes, opened, reopened and resolved findings. By default, a DNS or HTTP modification must be seen on two consecutive runs before it alerts (`pipeline.confirm_changes`), which filters out flapping. A baseline run never alerts.

## Detection rules

| Rule | Kind | Severity | Request | Detects |
| --- | --- | --- | --- | --- |
| `exposed-env-file` | http | critical | `GET /.env` | a readable environment file (values are redacted in evidence) |
| `exposed-git-config` | http | high | `GET /.git/config` | a readable Git repository configuration |
| `directory-listing` | http | low | `GET /` | an enabled directory index |
| `server-version-disclosure` | http | info | `HEAD /` | a `Server` header with a version; feeds `vulnerable-component` |
| `vulnerable-component` | component | medium | none | a disclosed product version inside an advisory's affected range |

**As shipped, all five rules are pending maintainer approval.** They load and are listed, but they never run, so no run can open or resolve a finding with them. Runs report them in `checks_not_run`, and the run status is `partial`. A maintainer approves a rule by pinning its hash in `rules/manifest.json` ([rules/README.md](../rules/README.md)). Nothing in WatchTower approves a rule on its own.

## Out of scope

WatchTower is an exposure monitor, not a vulnerability scanner. It does not:

- scan ports beyond those the scope permits (80 and 443 by default), or speak any protocol but HTTP(S) and DNS;
- authenticate to targets, submit forms, render JavaScript, or crawl beyond the paths a rule names;
- exploit anything; every rule is a single `GET` or `HEAD` with no request body;
- contact loopback, link-local, cloud metadata, multicast, documentation or reserved addresses, whatever a scope says. Private ranges are allowed only in a profile that enables `scope.allow_private_networks` (the lab);
- keep raw response bodies. Evidence keeps a bounded, redacted excerpt and a digest of the redacted body.

## How results are reported

- A **failed** or **cancelled** run is shown in red or grey and is never counted as a successful scan. A **partial** run finished with gaps (pending rules, or phases that could not compare), and is never shown as success either.
- Phases that could not see their targets read `uncertain` or `failed`, shown in red in the CLI and dashboard. They never change an asset or finding.
- Only a **relevant, conclusive negative retest** resolves a finding: the same rule, against the same endpoint, after the latest detection. Routine scan negatives, failed retests, inconclusive retests and retests whose rule did not run are recorded but change nothing. Remediation is shown as `verified_fixed` only in that case. Otherwise it reads `retest_failed`, `retest_inconclusive`, `still_present` or `retest_pending`.

## Test coverage of the user journey

Every test below runs against PostgreSQL with row-level security as a non-superuser role. CI runs the full suite and fails if any test is skipped.

| Journey step | What is proved | Tests |
| --- | --- | --- |
| Authorize a target | Nothing runs without scope. Only owners publish, and they must attest. Legacy and invalid scopes are refused, and loopback is never authorized. Revocation stops authorization at once. | `tests/e2e/test_user_journey.py`, `tests/api/test_api_auth_scope.py`, `tests/foundation/test_scope_policy.py`, `tests/foundation/test_scope_store.py`, `tests/test_launcher_platform.py` |
| Authenticate | Bad, revoked and disabled credentials are rejected. Roles are enforced. Other projects look nonexistent, and restricted tokens stay in their project. | `tests/api/test_api_auth_scope.py`, `tests/api/test_cli.py`, `tests/foundation/test_config_and_auth.py`, `tests/foundation/test_migrations_and_isolation.py` |
| Establish a baseline | The first run records every phase as `baseline` and sends no alert. | `tests/e2e/test_user_journey.py`, `tests/runtime/` |
| Introduce a change, receive an alert | A new host, an HTTP change and an exposure produce one grouped alert. It is delivered to the webhook and printed by `watchtower run start --watch`. | `tests/e2e/test_user_journey.py`, `tests/runtime/test_runtime_alerts.py` |
| Inspect a finding | The finding lists its check, endpoint and history. Evidence is redacted, can be read as data, and downloads only as an inert attachment from its own project. | `tests/e2e/test_user_journey.py`, `tests/api/test_api_data.py`, `tests/test_evidence.py`, `tests/test_evidence_store.py` |
| Failed scan | A crashed scan is a `failed` run with a `monitor.run_failed` alert and changes no finding. | `tests/e2e/test_user_journey.py` |
| Failed retest | A retest that cannot connect reports `retest_failed`, and the finding stays open. | `tests/e2e/test_user_journey.py`, `tests/api/test_api_data.py`, `tests/api/test_cli.py`, `tests/test_findings_postgres.py` |
| Fix and retest | The finding is resolved only by a conclusive negative retest. It then shows as `verified_fixed`, with a `finding.resolved` alert. | `tests/e2e/test_user_journey.py`, `tests/test_findings.py` |
| Rules pending approval | Checks send nothing and runs are `partial` with `checks_not_run`. No finding opens or resolves. | `tests/e2e/test_user_journey.py`, `tests/test_checks.py` |
| Safe rendering | The dashboard never parses data as HTML and runs under a strict CSP. The CLI escapes terminal control characters. | `tests/api/test_dashboard_static.py`, `tests/api/test_cli.py` |
| Pagination | Assets, findings, runs and alerts page without gaps or repeats. Malformed or foreign cursors are rejected. | `tests/api/test_api_data.py` |

The end-to-end tests drive the real API, CLI, run service, worker and notifier. Only outbound DNS, HTTP and webhook calls are answered in-process (`tests/runtime/runtime_support.py`), and detection uses a temporary, test-only approved copy of the rule manifest (`tests/checks_support.py`). The [lab](../lab/README.md) runs the same journey against real containers.
