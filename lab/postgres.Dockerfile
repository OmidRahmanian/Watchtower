# PostgreSQL with the platform's init script (a non-superuser application role).
FROM postgres:17-alpine
COPY deploy/postgres/init/ /docker-entrypoint-initdb.d/
