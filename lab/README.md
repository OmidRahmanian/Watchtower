# Demonstration lab

The lab runs the whole WatchTower journey on your machine against targets it creates itself:

**authorize a target → establish a baseline → introduce a change → receive an alert → inspect a finding → fix it → retest.**

It needs Docker with Compose and nothing else. Nothing in it can reach the internet.

```bash
lab/lab.sh demo     # every step in order, with commentary
lab/lab.sh down     # remove the containers, volumes and generated passwords
```

## What runs

| Container | Role | Networks |
| --- | --- | --- |
| `web` | nginx answering as `www.acme-lab.test`, `api.acme-lab.test` and `shop.acme-lab.test` | `lab` |
| `watchtower` | the API, dashboard and CLI; scan jobs run here with `--work` | `lab` |
| `postgres` | the platform database, with the same non-superuser application role as production | `lab` |
| `gateway` | a reverse proxy that publishes the dashboard on `127.0.0.1:8080` | `lab`, `edge` |

Docker creates the `lab` network with `internal: true`, so it has no route out. Only the lab's containers resolve on it. The scanner is attached to `lab` alone. `.test` is a reserved top-level domain (RFC 2606), so `*.acme-lab.test` cannot name a real host.

The lab uses the `lab` settings profile, [`config/profiles/lab.toml`](../config/profiles/lab.toml). That profile is the only one that turns on `scope.allow_private_networks`, because the targets have Docker's private addresses. Loopback, link-local and cloud metadata addresses remain prohibited whatever the scope says. Discovery reads a seed file (`discovery_sources = ["manual"]`), so no third-party source is ever asked. Probes and checks use plain HTTP on port 80.

Change the dashboard port with `LAB_DASHBOARD_PORT=18080 lab/lab.sh up`. Set the owner name recorded on the authorization with `LAB_OWNER="Your Name"`.

## Step by step

| Step | Command | What you should see |
| --- | --- | --- |
| Start | `lab/lab.sh up` | Builds the images, migrates the database, creates the `acme-lab` project and saves the owner's token inside the container. `lab/lab.sh token` prints it for the dashboard. |
| Authorize | `lab/lab.sh authorize` | Asks you to confirm, then publishes scope revision 1 (`*.acme-lab.test`) with its authorization record. Before this, every run is refused. |
| Baseline | `lab/lab.sh scan baseline` | Discovers `www` and `api`, resolves them and probes them. Every phase reads `baseline`. A baseline never alerts. |
| Change | `lab/lab.sh change` | `www` gets a new title and starts serving `/.env`. `shop.acme-lab.test` appears and serves `/.git/config`. |
| Alert | `lab/lab.sh scan "after change"` | The run follows to completion and prints `ALERT monitor.changes` with `asset.discovered shop.acme-lab.test`, `http.changed … title`, and a `finding.opened` line for each exposure. `lab/lab.sh alerts` lists them again. |
| Inspect | `lab/lab.sh findings`, then `lab/lab.sh finding <id>` | The finding's check, endpoint, history and evidence. `.env` values are redacted in the evidence. The dashboard shows the same, with evidence download. |
| Failed scan | `lab/lab.sh outage`, `lab/lab.sh scan`, `lab/lab.sh restore` | With all targets unreachable, the run reads `FAILED` and a `monitor.run_failed` alert identifies failed phases. Existing findings stay open; failure never proves removal or remediation. |
| Fix | `lab/lab.sh fix` | Removes `/.env` and `/.git/config`. |
| Retest | `lab/lab.sh retest <id>` or `lab/lab.sh retest-open` | Each finding's own check runs again against its own endpoint. A conclusive negative marks it `resolved` and prints `FIXED (verified by retest)`. A retest that fails or is inconclusive prints `RETEST FAILED - not verified`, and the finding stays open. |

## Detection rules need a maintainer's approval

The five shipped detection rules are **pending maintainer approval**. Until a maintainer approves a rule, it is listed but never runs, and nothing approves one automatically. With the rules as shipped, the demo shows that state honestly:

- Every scan reads `PARTIAL`, and `watchtower run show` lists each rule as `did not run: … pending maintainer approval`.
- No finding is opened, so the inspect, fix and retest steps have nothing to act on. The dashboard's overview lists the pending rules.

To see detection, remediation and retest in the lab, a maintainer must review and approve the rules the demo exercises (`exposed-env-file` and `exposed-git-config`) by following [rules/README.md](../rules/README.md#approving-a-rule-maintainers). Then run `lab/lab.sh down` and `lab/lab.sh demo` again; the image is rebuilt from your checkout. The approval names the maintainer and the exact rule hash, and it is your decision: the lab never writes one.

The automated end-to-end tests (`tests/e2e/`) cover the whole journey, including detection and verified remediation. They use a temporary, test-only approved copy of the manifest (`tests/checks_support.py`) that never touches `rules/manifest.json`.

## Troubleshooting

- **`unknown shorthand flag: 'f'`**: your Docker has no `compose` plugin. `lab.sh` falls back to `docker-compose` when it is installed.
- **Bind mount or "not a directory" errors**: the lab builds its files into images and uses no bind mounts, so it also works with Colima and remote Docker contexts.
- **Port 8080 in use**: `LAB_DASHBOARD_PORT=18080 lab/lab.sh up`.
- **Start again from nothing**: `lab/lab.sh down` removes the database, evidence and token volumes and the generated `lab/.env`.
