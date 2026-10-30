#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
if [ -x .venv/bin/python ]; then
    exec .venv/bin/python -u watch.py
fi
exec python3 -u watch.py
