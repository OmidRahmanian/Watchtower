FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/egress_guard.py /opt/watchtower/egress_guard.py
CMD ["python", "/opt/watchtower/egress_guard.py"]
