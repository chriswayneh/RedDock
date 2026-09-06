FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REDDOCK_DATABASE_URL=sqlite:////var/lib/reddock/reddock.db \
    REDDOCK_EVIDENCE_DIR=/var/lib/reddock/evidence
WORKDIR /app/backend
# Nmap is RedDock's Phase 1 discovery adapter and ships inside this image so no
# host installation is required. It is taken from the base image's Debian
# repository rather than pinned, so security updates reach it; the exact version
# used by a run is recorded in that run's evidence metadata.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system reddock && useradd --system --gid reddock --home-dir /app reddock \
    && mkdir -p /var/lib/reddock/evidence /app/static \
    && chown -R reddock:reddock /var/lib/reddock /app
COPY backend/pyproject.toml backend/README.md ./
COPY backend/app ./app
RUN pip install --no-cache-dir ".[postgres]"
COPY --from=frontend-build /build/frontend/dist /app/static
RUN chown -R reddock:reddock /app
USER reddock
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/ready')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
