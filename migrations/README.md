# Database migrations

WatchTower stores everything in PostgreSQL and manages the schema with Alembic.

```bash
export WATCHTOWER__DATABASE__URL=postgresql+psycopg://watchtower:<password>@127.0.0.1:5432/watchtower
watchtower-db upgrade          # apply all migrations
watchtower-db current          # show the applied revision
watchtower-db downgrade base   # remove the schema (development only)
```

## Rules for new revisions

- Number revisions sequentially (`0002_<topic>.py`, `down_revision = "0001"`), and tell the other workstreams before taking a number.
- Mirror every change in `src/watchtower/persistence/tables.py`. `test_fresh_database_migrates_to_head_and_matches_metadata` fails if the ORM metadata and the migrated schema differ.
- Every project-owned table needs a `project_id` column, composite `(project_id, id)` foreign keys to other project-owned tables, and the `project_isolation` policy:

  ```sql
  ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
  ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
  CREATE POLICY project_isolation ON <t>
      USING (watchtower_is_system() OR project_id = watchtower_current_project())
      WITH CHECK (watchtower_is_system() OR project_id = watchtower_current_project());
  ```

- Records that must not change after they are written get the `watchtower_reject_change()` trigger (see `0001_foundation.py`).
- Run the application and the migrations as a role that is neither a superuser nor `BYPASSRLS`. Row-level security does not apply to superusers.

## Importing the legacy MongoDB inventory

The legacy deployment keeps one MongoDB database per target (`example-com`), with `all` (discovered names), `resolve` (names that resolved) and `httpx` (latest HTTP snapshot) collections. Scope comes from `targets.json`. The import is one-way and repeatable:

1. **Dry run.** No PostgreSQL connection is needed. It reports, per target, how many records would be imported and how many are out of scope, excluded or malformed. It also lists MongoDB databases that no target maps to.

   ```bash
   pip install -e '.[legacy-import]'
   watchtower-db import-mongo --targets targets.json --dry-run
   ```

2. **Import.** `--authorized-by` names the person attesting that the legacy scope is still authorized. It is recorded on the scope revision and in the audit log.

   ```bash
   watchtower-db upgrade
   watchtower-db import-mongo --targets targets.json --authorized-by "Jane Analyst"
   ```

   For each target, this:
   - creates the project `legacy-<database>` (for example `legacy-example-com`) unless it exists;
   - publishes scope revision 1 unless the project already has one. The revision includes `example.com` and `*.example.com`, excludes each `out_of_scope` host exactly, uses the configured default ports, and records a `legacy_import` authorization whose reference is the target's `report_url`;
   - checks every MongoDB record against that scope and the prohibited-destination list. Records that pass become `hostname` assets with observations: `discovery` from `all`, `dns_resolution` from `resolve` and `http_response` from `httpx`. Legacy dates become `observed_at`;
   - sets each observation's `source_ref` to `mongo:<database>/<collection>/<_id>`, so re-running the import adds nothing twice.

3. **Review.** Legacy authorizations are a stopgap. Publish a fresh revision for each project with the current program policy or contract as its authorization. Publishing supersedes revision 1, and history keeps the import.

Two targets whose names map to the same MongoDB database (`a-b.com` and `a.b.com` both map to `a-b-com`) share their legacy data, and the import refuses them. Import the inventory for such targets by hand. MongoDB stays untouched, so the legacy scripts keep working until the platform replaces them.
