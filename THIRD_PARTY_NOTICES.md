# Third-party components

WatchTower uses independently licensed libraries and optionally invokes external
tools. Their authors retain their rights. This file identifies dependencies; it
does not replace the license files shipped with the actual installed packages.
Invoking a tool is different from redistributing its binary, templates or data.

Metadata observed in the development environment for this build:

| Component | Declared license |
| --- | --- |
| Alembic | MIT |
| dnspython | ISC |
| idna | BSD-3-Clause |
| psycopg | LGPL-3.0-only |
| Pydantic | MIT |
| SQLAlchemy | MIT |
| FastAPI | MIT |
| Celery | BSD-3-Clause |
| Uvicorn | BSD-3-Clause |
| pytest (test dependency) | MIT |

Transitive dependencies, optional legacy requirements, Docker base images,
PostgreSQL, RabbitMQ, nginx and firewall packages carry their own notices.
Preserve those notices when redistributing a deployment. Subfinder, the Go
httpx tool, Nuclei and any Nuclei templates are not bundled by the platform
worker image; install and review them separately if using legacy integrations.

KEV, EPSS and vendor advisories are external datasets. Cache them for your
installation under their source terms and record provenance. This repository
ships only synthetic advisory fixtures, not a redistributed live feed mirror.

WatchTower's own code and native rule definitions use the [MIT license](LICENSE).
This grant does not relicense third-party packages, binaries, templates or
external data. Review the notices for the specific versions you distribute.
