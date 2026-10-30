# The WatchTower platform for the demonstration lab.
FROM python:3.12.7-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY rules ./rules
COPY frontend ./frontend
COPY config ./config
COPY lab/targets/seeds.txt ./lab/seeds.txt
RUN pip install ".[api]" \
    && useradd --system --uid 10001 --home-dir /var/lib/watchtower watchtower \
    && install -d -o watchtower -g watchtower -m 0700 /var/lib/watchtower

USER watchtower
EXPOSE 8080
