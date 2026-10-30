# WatchTower worker image: the platform package with Celery, run as an unprivileged user.
# External tools (subfinder) are optional; add them in a derived image if discovery uses them.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY rules ./rules
COPY config ./config
RUN pip install ".[workers]" \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin watchtower \
    && mkdir -p /app/data/evidence && chown 10001:10001 /app/data/evidence
USER 10001:10001
CMD ["watchtower-worker", "serve"]
