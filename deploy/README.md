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
| `max_redirects` | `5` | Redirects a single request chain may follow |
| `allow_https_downgrade` | `false` | Follow HTTPS→HTTP redirects |
| `allow_private_networks` | `false` | Permit RFC 1918, CGNAT, ULA and `.internal`-style names for internal assessments. Loopback, link-local and cloud metadata stay prohibited. |
| `extra_prohibited_networks` / `extra_prohibited_hostnames` | `[]` | Deployment-specific never-contact lists (JSON arrays in the environment) |
| `policy_cache_seconds` | `5` | Upper bound on how long a revocation takes to reach other processes |

## MongoDB (legacy)

The root `docker-compose.yml` still runs the legacy MongoDB for the existing scripts and for the one-time import (see `migrations/README.md`). It is published on `127.0.0.1` only because it has no authentication.
