# Deployment

## PostgreSQL

```bash
cp deploy/.env.example deploy/.env        # set both passwords; the file is ignored by Git
docker compose -f deploy/compose.yaml --env-file deploy/.env up -d --wait postgres
```

PostgreSQL listens on `127.0.0.1` only. On first start, `postgres/init/01-watchtower.sh` creates:

- the `watchtower` role: login, not a superuser, no `BYPASSRLS`;
- the `watchtower` database, owned by that role.

The application and `watchtower-db upgrade` both connect as `watchtower`. Because the tables use `FORCE ROW LEVEL SECURITY`, the project isolation policy applies to that role even though it owns them. Use the `postgres` superuser for administration only. A superuser bypasses row-level security.

## Configuration

Settings come from `config/profiles/<profile>.toml`, selected by `WATCHTOWER_PROFILE` (default `development`), with environment overrides named `WATCHTOWER__<SECTION>__<KEY>`:

```bash
export WATCHTOWER_PROFILE=production
export WATCHTOWER__DATABASE__URL='postgresql+psycopg://watchtower:<password>@127.0.0.1:5432/watchtower'
watchtower-db upgrade
```

Keep credentials in the environment or a secret manager, never in a profile. Run commands from the repository root, or set `WATCHTOWER_PROFILE_DIR`.

Scope enforcement settings (`[scope]`):

| Key | Default | Meaning |
| --- | --- | --- |
| `default_permitted_ports` | `80,443` | Ports used when a revision does not specify them |
| `max_redirects` | `0` | Redirects a single request chain may follow |
| `allow_https_downgrade` | `false` | Follow HTTPS→HTTP redirects |
| `allow_private_networks` | `false` | Permit RFC 1918, CGNAT, ULA and `.internal`-style names for internal assessments. Loopback, link-local and cloud metadata stay prohibited. |
| `extra_prohibited_networks` / `extra_prohibited_hostnames` | `[]` | Deployment-specific never-contact lists (JSON arrays in the environment) |
| `policy_cache_seconds` | `5` | UI decision cache only; running pipeline decisions reload revision validity |

Worker settings (`[runtime]`):

| Key | Default | Meaning |
| --- | --- | --- |
| `broker_url` | unset | Job broker URL; a secret, so set `WATCHTOWER__RUNTIME__BROKER_URL` |
| `concurrency` | `4` | Jobs one worker process runs at once |
| `lease_seconds` / `heartbeat_seconds` | `300` / `60` | Job lease length and renewal interval; the heartbeat must be at most half the lease |
| `limits` | `{}` | Maximum running jobs per `concurrency_key` across all workers, for example `WATCHTOWER__RUNTIME__LIMITS='{"dns": 4}'` |

Notification destinations (`[notifications]`) embed credentials in their URLs, so set them in the environment:

```bash
export WATCHTOWER__NOTIFICATIONS__DESTINATIONS='[{"name": "discord", "kind": "discord", "url": "https://discord.com/api/webhooks/..."}]'
```

Each destination has a `name` (matched against a notification's `channel`), a `kind` (`discord`, `slack`, `telegram` or `webhook`), an `https://` `url`, optional `events` (event types to deliver; empty delivers all) and `enabled`.

## MongoDB (legacy)

The root `docker-compose.yml` still runs the legacy MongoDB for the existing scripts and for the one-time import (see `migrations/README.md`). It is published on `127.0.0.1` only because it has no authentication.

## Worker egress and request budgets

Layer `compose.workers.yaml` over the base Compose file. The worker and notifier
share a namespace with the egress guard. Only that bootstrap container holds
`NET_ADMIN`; runtime processes drop all capabilities. The firewall allows exact
PostgreSQL/broker IP:port exceptions, configured resolvers on TCP/UDP 53 and
public TCP 80/443. Private, loopback, metadata/reserved ranges and other ports
are denied; IPv6 egress is disabled. No Docker socket or host network is used.
The guard is an address/port boundary, not a hostname scope enforcer; application
checks are still necessary. Optional tool binaries must still be reviewed.

Recreate the guard **and its dependent workers** if infrastructure IPs or DNS
settings change. Review required exceptions before deploying. Custom public
ports permitted in scope also need an explicit firewall policy change and tests.
Laptops and the private demonstration lab do not use this production namespace.

`scope.per_host_requests_per_minute` defaults to 120, project to 1200, global to
12000 and `max_requests_per_run` to 10000. PostgreSQL counters share these caps
across workers/retries; a scope revision can impose a lower per-run cap. Passive
Subfinder provider calls use tool/provider controls. See [operations](../docs/operations.md)
for idempotency, feed refresh and retention procedures.
