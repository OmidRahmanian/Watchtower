# Installing WatchTower

This guide installs the WatchTower platform: PostgreSQL, the `watchtower` CLI, the HTTP API and dashboard, and the monitoring workers. To try everything first without installing anything but Docker, run the [demonstration lab](../lab/README.md).

The legacy MongoDB scripts (`watch.py`, `manager.py`, the legacy path of `launcher.py`) are documented in the [README](../README.md#legacy-discovery). They are separate from the platform.

## Requirements

| Component | Version | Used for |
| --- | --- | --- |
| Python | 3.11 or newer (CI uses 3.12) | the platform package |
| PostgreSQL | 17 (16 works) | all platform state |
| Docker with Compose | any recent | the bundled PostgreSQL and the lab (optional) |
| Subfinder | optional | the `subfinder` discovery source |

macOS and Linux are supported.

## 1. Install the package

```bash
git clone https://github.com/OmidRahmanian/Watchtower.git
cd Watchtower
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[api]'
```

The `api` extra adds the HTTP server. Add `workers` for Celery (`'.[api,workers]'`), or `dev` to run the tests.

## 2. Start PostgreSQL and migrate

```bash
cp deploy/.env.example deploy/.env          # then replace both passwords
docker compose -f deploy/compose.yaml --env-file deploy/.env up -d postgres
```

Put the application's connection URL in `.env` at the repository root. `.env` is ignored by Git, and `run.sh` and the launcher load it:

```bash
WATCHTOWER__DATABASE__URL='postgresql+psycopg://watchtower:<WATCHTOWER_DB_PASSWORD>@127.0.0.1:5432/watchtower'
```

Then apply the schema:

```bash
set -a; . ./.env; set +a
watchtower-db upgrade
```

The application connects as the non-superuser `watchtower` role, so PostgreSQL row-level security confines each request to one project. Do not point it at a superuser.

## 3. Create a project and its owner

```bash
watchtower bootstrap acme --name "Acme" --owner "Ada Lovelace" --save-token ~/.config/watchtower/token
export WATCHTOWER_PROJECT=acme
```

`bootstrap` and `member add` talk to the database directly, so they are for whoever holds the database URL. Each prints, or saves with mode 600, a token that is shown once. Every other command, and the API, authenticate with a token and act with that member's role:

| Role | Can |
| --- | --- |
| viewer | read scope, inventory, findings, evidence, runs and alerts |
| operator | also start and cancel runs, triage findings, request retests |
| owner | also publish and revoke scope |

```bash
watchtower member add "Grace Hopper" --role operator --save-token /secure/place/grace.token
watchtower token revoke <token-id>
```

## 4. Authorize targets

Nothing is scanned until an owner publishes a scope revision, together with the authorization behind it:

```bash
watchtower scope publish \
  --include acme.example --include '*.acme.example' --exclude legacy.acme.example \
  --authorization-kind contract --reference "SOW-2026-14" --granted-by "Acme CISO" \
  --i-am-authorized
watchtower scope check www.acme.example        # sends nothing; explains the decision
```

`--i-am-authorized` records your statement that the authorization covers every included target. Revoking the current revision (`watchtower scope revoke <revision> --reason ...`) stops scanning at once. Loopback, link-local, cloud metadata and reserved addresses are refused whatever a scope says. Private ranges are refused unless the profile sets `scope.allow_private_networks`.

## 5. Monitor

```bash
watchtower run start --watch --work      # run now, in this terminal, and follow it
watchtower watch --work                  # follow runs and alerts as they happen
watchtower alerts
watchtower findings
watchtower finding show <id>
watchtower finding retest <id> --watch --work
```

`--work` runs the queued jobs inside the CLI process, which suits a laptop or the lab. For a long-running deployment, run the workers separately and leave `--work` off:

```bash
watchtower-worker serve                   # workers and the notifier
watchtower-worker schedule --every 6h     # from cron, to queue scheduled runs
```

Alerts go to the destinations in `notifications.destinations` (Discord, Slack, Telegram or a webhook). Set them in the environment, because their URLs are credentials:

```bash
WATCHTOWER__NOTIFICATIONS__DESTINATIONS='[{"name": "ops", "kind": "discord", "url": "https://discord.com/api/webhooks/..."}]'
```

### The guided launcher

`python3 launcher.py` asks whether to use the platform or legacy discovery. The platform path shows the banner once and opens a persistent Home menu. Select a project by number or create one with a separate owner token; project/profile/token-file selections are remembered. Publish authorized scope through **Manage targets and scope**. **Start scan** opens a separate processing/progress terminal while Home remains available for browsing. The dashboard also opens separately, or reuses a running server. See the [terminal guide](terminal.md) for navigation, cancellation and platform support. Use `python3 launcher.py --platform` to skip the mode question.

## 6. Dashboard and API

```bash
watchtower serve            # http://127.0.0.1:8080, sign in with your token
```

The server listens on loopback only unless you pass `--host` with `--allow-remote`. Put TLS in front of it before exposing it. The API is described in [api.md](api.md), and its OpenAPI document is at `/api/v1/openapi.json`.

## Settings and profiles

Settings come from `config/profiles/<profile>.toml`, overridden by `WATCHTOWER__SECTION__KEY` environment variables. The profile is chosen with `WATCHTOWER_PROFILE` or `--profile`.

| Profile | Use |
| --- | --- |
| `development` | your own machine |
| `production` | deployments; secrets come only from the environment |
| `test` | the automated tests |
| `lab` | the isolated demonstration lab (private networks allowed, offline discovery) |

## Detection rules

Rules in `rules/` run only after a human maintainer approves them in `rules/manifest.json` ([rules/README.md](../rules/README.md)). Until then, runs report each rule as not run, and nothing they would detect can open or resolve a finding. `python -m watchtower.adapters.checks` lists the pending rules.

## Running the tests

```bash
python -m pip install -e '.[dev]' -r requirements.txt
docker run -d --name wt-test-pg -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:55432:5432 postgres:17-alpine
WATCHTOWER_TEST_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres python -m pytest
```

The URL must be able to create roles and databases. Each test session creates its own non-superuser role and database and drops them afterwards. Without the URL, database tests are skipped. CI runs every test and fails if any is skipped.

## Updating an existing installation

Stop old worker/API processes, update the checkout, and install the package
extras you use (`python -m pip install -e '.[dev]'` for development). Load the
same database configuration as before, then run `watchtower-db upgrade` before
restarting. Revision 0003 adds finding workflow support, immutable scope
execution policies and durable request counters; existing scope rows inherit
compatible execution defaults. Back up PostgreSQL and the private evidence
store before an upgrade. The launcher uses this same database and does not
require another project token. Start it with `python launcher.py --platform`.
