# Threat model and boundaries

Assume scanned hosts, DNS answers, redirect locations, certificate metadata,
feed payloads and captured page titles are hostile. A logged-in viewer is not
an operator, and a project owner is not authorized to read another project's
data. Database credentials and the host operating account are administrative
credentials; a person who controls them can administer the installation.

| Threat | Controls | Remaining boundary |
| --- | --- | --- |
| SSRF, DNS rebinding, redirects to metadata/private hosts | Canonical scope, full address-set validation, pinned sockets, redirects disabled by default, live revocation checks | Target scope must actually reflect authorization; a policy URL is not proof of permission |
| External tools bypassing Python socket checks | Production worker/notifier share a dedicated firewall namespace without capabilities | Laptop mode has no equivalent OS sandbox; unreviewed external check engines remain outside platform coverage |
| Cross-project access | Bearer authentication, roles, project-scoped queries, forced RLS, composite foreign keys, isolated evidence paths | Application database role must remain non-superuser without BYPASSRLS |
| Captured content executes in UI or terminal | DOM textContent, restrictive CSP, inert authenticated evidence downloads, escaped terminal text | Downloaded evidence should still be treated as untrusted data |
| Sensitive output leaks | Response caps, evidence redaction, secret configuration, bounded notification summaries, private file modes | Redaction is heuristic; do not scan endpoints expected to expose personal or highly sensitive data |
| Feed causes arbitrary requests or false applicability | Pinned public HTTPS fetch, no redirects/proxies/URL credentials, bounded compressed and decompressed input, exact product mapping, unknown/prerequisite handling | Normalized advisories need operator review; not all CPE semantics are implemented |
| Retries duplicate work or falsely resolve findings | Durable idempotency records, unique finding fingerprints, append-only observations, leases, coverage states, relevant negative retests only | External chat delivery is at least once; receivers must deduplicate delivery keys |
| Resource exhaustion | Timeouts, output caps, run/host/project/global request budgets, job concurrency limits | Budgets are minute-window counters, not calibrated capacity claims; host filesystem quotas remain operator-managed |
| Stale exceptions and evidence kept forever | Explicit risk expiry back to triage, retention checks on reads, preview/apply maintenance with shared-blob protection | Schedule maintenance; immutable historical metadata remains. Use encrypted host storage for at-rest encryption |
| Build/publish leaks local secrets | Docker context excludes .env, tool histories, virtualenvs, databases, evidence and exports; Git ignores local state | Review staged files; removing a secret from a commit does not revoke it |

The firewall guard has NET_ADMIN to initialize its own network namespace. It
does not run scans, mount the Docker socket or use host networking. The worker
containers sharing it remain unprivileged. Exact infrastructure exceptions
are necessary and trusted. The bundled topology assumes PostgreSQL/RabbitMQ
addresses remain stable for the guard's lifetime; restart/recreate the guard
and dependent workers when those addresses change. A firewall bootstrap
failure leaves the guard unhealthy and prevents dependent workers starting.

Future authenticated scanning, cloud credentials, external callback templates,
resource claiming and mitigation integrations require new threat modeling and
explicit policy controls. They are not enabled by this build.
