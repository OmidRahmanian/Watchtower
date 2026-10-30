#!/bin/sh
# Drive the WatchTower demonstration lab. See lab/README.md.
#
#   lab/lab.sh demo            the whole journey, step by step
#   lab/lab.sh up | authorize | scan | change | alerts | findings | finding ID
#              fix | retest ID | retest-open | outage | restore | runs | token | down
set -eu

LAB=$(cd "$(dirname "$0")" && pwd)
ENV_FILE="$LAB/.env"
TOKEN=/var/lib/watchtower/.config/watchtower/token
OWNER=${LAB_OWNER:-Lab Owner}

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "Install Docker with Compose, start Docker, and try again." >&2
    exit 1
fi
compose() { $COMPOSE -f "$LAB/compose.yaml" --env-file "$ENV_FILE" "$@"; }
# A TTY keeps colour in the CLI's output when you run the lab interactively.
tty_flag() { if [ -t 1 ]; then echo ""; else echo "-T"; fi; }
wt() { compose exec $(tty_flag) watchtower watchtower "$@"; }
in_web() { compose exec -T web sh -c "$1"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
secret() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }

up() {
    if [ ! -f "$ENV_FILE" ]; then
        umask 077
        printf 'LAB_POSTGRES_PASSWORD=%s\nLAB_DB_PASSWORD=%s\n' "$(secret)" "$(secret)" > "$ENV_FILE"
    fi
    compose up -d --build --wait
    compose exec -T watchtower sh -c 'test -f /var/lib/watchtower/seeds.txt || cp /app/lab/seeds.txt /var/lib/watchtower/seeds.txt'
    if ! compose exec -T watchtower test -f "$TOKEN"; then
        wt bootstrap acme-lab --name "Acme Lab" --owner "$OWNER" --save-token "$TOKEN"
    fi
    echo "Dashboard: http://127.0.0.1:${LAB_DASHBOARD_PORT:-8080}  (sign in with: lab/lab.sh token)"
}

authorize() {
    if [ "${1:-}" != "--yes" ]; then
        echo "The lab's targets are containers this lab created on a network with no internet access."
        printf 'Publish scope *.acme-lab.test, authorized by %s? [y/N] ' "$OWNER"
        read -r answer
        case "$answer" in y|Y|yes) ;; *) echo "Scope not published."; return 1 ;; esac
    fi
    wt scope publish --include '*.acme-lab.test' --authorization-kind asset_owner \
        --reference "lab/README.md: containers created by this lab on an isolated network" \
        --granted-by "$OWNER" --i-am-authorized
    wt scope check www.acme-lab.test
}

change() {
    in_web 'cp /lab/changes/index.html /srv/www/index.html
            cp /lab/changes/env /srv/www/.env
            mkdir -p /srv/shop/.git && cp /lab/changes/git-config /srv/shop/.git/config'
    compose exec -T watchtower sh -c \
        'grep -qx shop.acme-lab.test /var/lib/watchtower/seeds.txt || echo shop.acme-lab.test >> /var/lib/watchtower/seeds.txt'
    echo "Changed: www has a new title and serves /.env; shop.acme-lab.test is new and serves /.git/config."
}

fix() {
    in_web 'rm -f /srv/www/.env && rm -rf /srv/shop/.git'
    echo "Fixed: /.env and /.git/config are gone."
}

open_findings() {
    compose exec -T watchtower sh -c \
        "watchtower findings --json | python -c 'import json,sys; [print(f[\"id\"]) for f in json.load(sys.stdin)]'"
}

retest_open() {
    ids=$(open_findings)
    if [ -z "$ids" ]; then
        echo "No open findings to retest."
        return 0
    fi
    for id in $ids; do
        wt finding retest "$id" --reason "fixed in lab" --watch --work --interval 1 || true
    done
}

pending_note() {
    if ! compose exec -T watchtower python -m watchtower.adapters.checks >/dev/null 2>&1; then
        echo
        echo "Note: detection rules are pending maintainer approval, so checks report 'did not run' and no"
        echo "finding is opened. lab/README.md explains how a maintainer approves a rule for this demo."
    fi
}

demo() {
    step "1. Start the lab"; up
    step "2. Authorize the target"; authorize
    step "3. Baseline scan (records the current state; never alerts)"
    wt run start --reason "baseline" --watch --work --interval 1
    step "4. Introduce a change"; change
    step "5. Scan again and receive the alert"
    wt run start --reason "after change" --watch --work --interval 1 || true
    step "6. Inspect findings"; wt findings --all
    for id in $(open_findings); do wt finding show "$id"; done
    pending_note
    step "7. A failed scan looks like a failure, not a fix"; outage
    wt run start --reason "during outage" --watch --work --interval 1 || true
    restore
    step "8. Fix the exposure"; fix
    step "9. Retest each open finding"; retest_open
    step "10. Where things stand"; wt findings --all; wt run list
    echo
    echo "Explore the same data in the dashboard: http://127.0.0.1:${LAB_DASHBOARD_PORT:-8080}"
}

outage() { compose stop web; echo "The targets are down."; }
restore() { compose start web; compose exec -T web sh -c 'true'; echo "The targets are back."; }

command=${1:-help}
[ $# -gt 0 ] && shift
case "$command" in
    up) up ;;
    authorize) authorize "$@" ;;
    scan) wt run start --reason "${1:-lab scan}" --watch --work --interval 1 ;;
    change) change ;;
    fix) fix ;;
    alerts) wt alerts ;;
    findings) wt findings --all ;;
    finding) wt finding show "$1" ;;
    retest) wt finding retest "$1" --watch --work --interval 1 ;;
    retest-open) retest_open ;;
    outage) outage ;;
    restore) restore ;;
    runs) wt run list ;;
    status) wt status ;;
    token) compose exec -T watchtower cat "$TOKEN" ;;
    demo) demo ;;
    down) compose down -v --remove-orphans; rm -f "$ENV_FILE" ;;
    *) sed -n '2,7p' "$0"; exit 2 ;;
esac
