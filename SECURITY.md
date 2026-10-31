# Reporting a security issue

Do not post credentials, private evidence, target inventories, or exploit details
in a public issue or pull request. If this repository's Security tab offers
**Report a vulnerability**, use that private reporting channel. If it is not
enabled, open a public issue asking the maintainer for a private contact method
without describing the vulnerability or identifying affected targets.

Include the WatchTower commit/version, deployment profile, relevant component,
expected and actual behavior, and a minimal reproduction using owned fixtures.
Redact tokens, webhook URLs, database passwords and captured secrets. Do not
test third-party systems as part of a WatchTower vulnerability report.

This project is an early self-hosted monitor. Review [the threat model](docs/threat-model.md),
[coverage](docs/coverage.md), and [deployment notes](deploy/README.md) before
sharing remote access. No response-time or support-lifetime guarantee is made.
