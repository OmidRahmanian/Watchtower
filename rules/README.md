# Check rules

Rules here are data, not code. A rule runs only if `manifest.json` pins it by SHA-256 and gives it a review record. If a pinned file is edited, missing, unreviewed, or renamed without updating the manifest, the whole manifest is rejected.

```bash
python -m watchtower.adapters.checks            # verify every pin
python -m watchtower.adapters.checks --hashes   # print hashes after a reviewed edit
```

## Changing a rule

1. Edit the rule file and bump its `version`.
2. Have someone other than the author review the change. Copy the new hash from `--hashes` into the manifest entry, then update `version` and `review`.
3. Keep the `id`. The id is part of every finding fingerprint, so changing it would create duplicate findings. To rename a rule, give it a new `id` and put the old one in the manifest entry's `aliases`.

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
