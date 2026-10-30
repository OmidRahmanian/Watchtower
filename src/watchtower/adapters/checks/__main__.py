"""Verify pinned rules: ``python -m watchtower.adapters.checks [--hashes]``."""

import sys

from watchtower.adapters.checks.manifest import main

sys.exit(main(sys.argv[1:]))
