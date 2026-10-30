# Check rules

Rules here are data, not code. A rule loads only if `manifest.json` pins it by SHA-256 and gives it a review record. If a pinned file is edited, missing, unreviewed, or renamed without updating the manifest, the whole manifest is rejected.

A rule also runs only after a human maintainer approves it. Until then its review record has `"status": "pending"`: the rule loads and can be listed, but every check refuses to run it with `RuleNotApproved`, before any authorization or network request. A pending rule therefore never produces a result, so it can never resolve a finding.

```bash
python -m watchtower.adapters.checks            # verify every pin and list rules pending approval
python -m watchtower.adapters.checks --hashes   # print hashes after a reviewed edit
```

## Review records

```json
"review": {
  "status": "approved",
  "reviewer": "Who reviewed the definition",
  "date": "2026-10-30",
  "notes": "What was checked",
  "approved_by": "Jane Maintainer <jane@example.com>",
  "approved_at": "2026-11-02",
  "approved_sha256": "<the entry's sha256>"
}
```

- `status` is `pending` or `approved`. A pending record must not carry `approved_by`, `approved_at`, or `approved_sha256`.
- An approved record needs all three. `approved_at` is a `YYYY-MM-DD` date, and `approved_sha256` must equal the entry's pinned `sha256`, so an approval covers exactly one version of the rule file.
- `approved_by` must name a human maintainer. Identities that look automated (agents, Claude or other AI models, bots, CI) are refused. This is only a guard against self-approval. The real control is that a maintainer makes or reviews the change to this file.

## Approving a rule (maintainers)

1. Read the rule file and its review notes, and confirm the request is safe to send to in-scope targets.
2. Re-pin it: run `python -m watchtower.adapters.checks --hashes` and check that the rule's hash matches the manifest entry's `sha256`. If it doesn't, the file changed since it was pinned, so review the change and update `sha256` first.
3. Edit the manifest entry's `review`: set `"status": "approved"`, and add `approved_by` (your name), `approved_at` (today), and `approved_sha256` (the same hash as `sha256`).
4. Verify with `python -m watchtower.adapters.checks`. It should exit 0 and no longer list the rule as pending.
5. Commit the manifest change yourself, or approve the pull request that contains it.

## Changing a rule

1. Edit the rule file and bump its `version`.
2. Have someone other than the author review the change. Copy the new hash from `--hashes` into the manifest entry, then update `version` and `review`. Editing an approved rule invalidates its approval, because `approved_sha256` no longer matches. Set the record back to `pending` until a maintainer approves the new hash.
3. Keep the `id`. The id is part of every finding fingerprint, so changing it would create duplicate findings. To rename a rule, give it a new `id` and put the old one in the manifest entry's `aliases`.

## How checks connect

HTTP checks never follow redirects and never resolve a hostname twice. The authorizer resolves the hostname once, checks that address set against scope with `check_connection`, and returns the approved addresses. The fetcher then opens the socket to one of those addresses only, using `PinnedHTTPConnection` or `PinnedHTTPSConnection` from `watchtower.adapters.probing`. The hostname is used only for SNI, certificate verification, and the `Host` header. A DNS answer that changes after authorization cannot redirect the request.

## HTTP rules (`kind: "http"`)

| Field | Meaning |
| --- | --- |
| `request.method` / `request.path` | `GET` or `HEAD` only, with a path relative to the target. Redirects are never followed. |
| `match.status` | The response status must be in this list. |
| `match.body_all` / `body_any` / `body_none` | Regexes that must all match, at least one must match, or none may match. |
| `match.headers` | Header name mapped to a regex that its value must match. |
| `negative_status` | A response without a match counts as a negative only for these statuses. Any other status, or a truncated body, is inconclusive. |
| `extract` | Values saved as observations, such as `{"server": {"header": "Server"}}`. |
| `evidence.profile` | `default`, or `env` to redact every `KEY=value` value. |
| `severity`, `confidence`, `cves` | Copied onto the finding. Priority is computed separately. |

## Component rules (`kind: "component"`)

Component rules send no traffic. They read an observation from `source_rule`, map product names through `product_map`, and match versions against advisories. Each advisory becomes its own finding variant. A version with a vendor suffix, such as `2.4.49-1ubuntu1`, may include a backported fix, so it is only tentative. A missing version or a banner that is no longer shown is inconclusive and cannot prove a fix.

## Advisory format

`AdvisoryFeed` reads curated advisories in this normalized form:

```json
{
  "generated_at": "2026-10-30T00:00:00Z",
  "advisories": [
    {
      "id": "CVE-2021-41773",
      "cves": ["CVE-2021-41773"],
      "product": "apache:http_server",
      "affected": [{"introduced": "2.4.49", "fixed": "2.4.50"}],
      "cvss": 7.5,
      "summary": "Apache HTTP Server 2.4.49 path traversal"
    }
  ]
}
```

Each range may have `introduced` plus either `fixed` (exclusive) or `last_affected` (inclusive).
