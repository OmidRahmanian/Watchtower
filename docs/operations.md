# Investigation and operations

Use an owner token for feed refresh and maintenance. Operators can annotate,
triage, prioritize, retest and acknowledge; viewers can inspect and export.
Every action remains scoped to a project. Load `.env` before direct CLI use.

## Inventory and findings

The dashboard Inventory filters by hostname text, owner, tag and a Server-banner
technology hint. Click an asset for its observation timeline and owner/tag/
importance controls. Candidates show provenance separately from authorization:
an operator's ownership annotation never grants permission to scan.

Findings support `open`, `triaged`, `in_progress`, `accepted_risk`,
`false_positive` and `resolved`. Resolution still requires a relevant negative
retest. Owner, remediation notes and temporary mitigation notes are separate
fields, retained across later observations. Priority overrides need a reason
and do not replace the source severity, confidence or computed factors.

```bash
watchtower --project acme finding annotate <id> --owner 'Application Team' \
  --remediation-notes 'Upgrade the affected service' \
  --mitigation-notes 'Temporary access restriction'
watchtower --project acme finding annotate <id> --priority P2 --reason 'Critical customer-facing application'
watchtower --project acme finding triage <id> --status in_progress
watchtower --project acme finding triage <id> --status accepted_risk \
  --reason 'Time-limited exception approved in TICKET-4' --risk-expires-at '2026-12-01T00:00:00Z'
```

The Changes page shows phase before/after data and records acknowledgement
reasons without deleting or modifying snapshots. Timestamps are stored in UTC;
the CLI and browser render the user's local timezone.

## Exports

```bash
watchtower --project acme export --dataset assets --format csv --limit 200 --output inventory.csv
watchtower --project acme export --dataset findings --format json --output findings.json
```

Exports are bounded pages (1-200 rows). JSON includes `next_cursor`; CSV/API
responses use `X-Next-Cursor`, and the CLI prints it separately. Pass that cursor
with `--cursor` to continue. Existing output files are never overwritten and
new files have mode 600. CSV cells are escaped to prevent formula execution.
The dashboard labels its first-page export limit; it does not imply that a
large inventory is contained in one download. Reports omit private evidence
and webhook/connection credentials.

## Threat intelligence

KEV and EPSS are public context feeds. Vendor advisories are normalized,
operator-reviewed JSON, such as the synthetic `tests/fixtures/advisories.json`.
Set `WATCHTOWER__INTELLIGENCE__ADVISORY_FILE` or the reviewed HTTPS
`WATCHTOWER__INTELLIGENCE__ADVISORY_URL` in `.env`, then:

```bash
watchtower --project acme intelligence refresh kev
watchtower --project acme intelligence refresh epss
watchtower --project acme intelligence refresh advisories
watchtower --project acme intelligence status
watchtower --project acme intelligence correlate --limit 50
watchtower --project acme finding prioritize <id>
```

Refreshing is explicit and rate-limited per feed (one hour by default; forced refreshes still have a one-minute floor). Configure a conservative cron schedule if desired and
respect provider quotas. Downloads are capped, resolve only to public approved
addresses, use pinned HTTPS and follow no redirects or proxy settings. Failed,
empty, truncated or older data does not erase a previous snapshot. The
dashboard displays freshness, failures and applicability-review rows. Matching
uses curated product IDs, not a loose vendor string; unknown versions and
unverified platform/prerequisite conditions are not confirmed vulnerabilities.
EPSS remains CVE context, not an asset compromise probability.

When enabled in `pipeline.check_kinds`, an approved native component rule
consumes cached advisories and evidence from its approved source HTTP rule.
A missing configured feed or missing source evidence is reported as not run.
Pending rules never execute. HTTP-only profiles can explicitly select
`WATCHTOWER__PIPELINE__CHECK_KINDS='["http"]'`; excluded classes remain visible
in phase diagnostics. Feed ingestion does not automatically launch a scan.

## Scope execution policy

Scope revisions pin schemes, ports, canonical path prefixes, excluded paths,
check classes and a cumulative target-request budget. Exclusions win and path
prefixes respect segment boundaries (`/api` does not include `/api-other`).
Encoded traversal and ambiguous paths are denied. The Scope page exposes
these controls and optional authorization validity dates. Equivalent CLI:

```bash
watchtower --project acme scope publish --include example.com \
  --allow-scheme https --allow-path /api --exclude-path /api/private \
  --check-kind http --max-requests 100 \
  --authorization-kind asset_owner --reference INTERNAL-42 \
  --granted-by 'Asset Owner' --i-am-authorized
watchtower --project acme scope check https://example.com/api/health
```

HTTP inventory probes the first allowed prefix; it does not crawl every prefix.
Each native detection rule's fixed URL is authorized independently, so a
`/api`-only scope cannot run a rule requesting `/.env` or `/`. Redirect following
is disabled by default; enabling it retains scope/path/address checks at every
hop. Jobs reload pinned revision validity before outbound decisions, including
after rate-limit waits. Revocation cannot recall an already-sent request.

## Request controls and retries

Scope profiles provide `per_host_requests_per_minute`,
`per_project_requests_per_minute`, `global_requests_per_minute` and
`max_requests_per_run`. Shared counters persist in PostgreSQL across workers
and retries. Minute windows wait cancellably; cumulative run exhaustion is a
coverage failure, never an empty successful scan. Passive-source requests
made inside Subfinder use its own provider/time/output controls.

```bash
watchtower --project acme run start --idempotency-key ticket-42 --reuse-active --json
```

Repeat the same key and arguments to retrieve the same run, including after
completion. A different payload/scope conflicts. `--reuse-active` also reuses
an equivalent active scan under the same scope. Keys are scoped to principal
and project. Without the flag, independent runs remain supported for explicit
operational use. The dashboard and terminal Home use reuse/idempotency controls.

## Retention and expiring exceptions

`pipeline.evidence_retention_days` defaults to 90. Expired evidence content
cannot be downloaded through the API or CLI, but its historical metadata is
retained. Review and then apply project maintenance:

```bash
watchtower --project acme maintenance
watchtower --project acme maintenance --apply
```

Apply removes expired blob files only when no newer reference needs the same
content. It also moves expired accepted-risk items back to triage and records
the reason in history; it does not change detection or resolve a finding.
Schedule this explicit owner operation if automatic housekeeping is wanted.
Use encrypted host storage when required; private file modes are not encryption.

Settings and rule approvals are shown read-only in the dashboard and
`watchtower --project acme settings --json`. Change typed profiles/environment
and restart services to apply settings. Human approval of pinned rules remains
a source-controlled manifest change, not an automatic dashboard action.
