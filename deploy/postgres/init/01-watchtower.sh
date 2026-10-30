#!/bin/sh
# Runs once, when the PostgreSQL data directory is first initialized.
# Creates the non-superuser application role and its database.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v app_password="$WATCHTOWER_DB_PASSWORD" <<'SQL'
CREATE ROLE watchtower LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'app_password';
CREATE DATABASE watchtower OWNER watchtower;
REVOKE ALL ON DATABASE watchtower FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE watchtower TO watchtower;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname watchtower <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO watchtower;
SQL
