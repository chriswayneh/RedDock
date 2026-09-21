FROM node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85 AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REDDOCK_API_DOCS_ENABLED=false \
    REDDOCK_DATABASE_URL=sqlite:////var/lib/reddock/reddock.db \
    REDDOCK_EVIDENCE_DIR=/var/lib/reddock/evidence \
    REDDOCK_OPERATOR_TOKEN_FILE=/var/lib/reddock/operator-token
WORKDIR /app/backend
# Nmap is RedDock's Phase 1 discovery adapter. The exact Debian package and its
# corresponding source archives are installed together so every distributed
# image carries the source used for its Nmap binary.
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && mkdir -p /usr/share/reddock-source/nmap \
    && chmod 1777 /usr/share/reddock-source/nmap \
    && cd /usr/share/reddock-source/nmap \
    && source_package="$(dpkg-query -W -f='${source:Package}' nmap)" \
    && source_version="$(dpkg-query -W -f='${source:Version}' nmap)" \
    && apt-get source --download-only "$source_package=$source_version" \
    && test "$(sed -n 's/^Version: //p' ./*.dsc | head -n 1)" = "$source_version" \
    && dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' nmap nmap-common > PACKAGE.txt \
    && sha256sum ./*.dsc ./*.tar.* > SHA256SUMS \
    && chmod -R a=rX /usr/share/reddock-source/nmap \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 999 reddock \
    && useradd --system --uid 999 --gid 999 --home-dir /app reddock \
    && mkdir -p /var/lib/reddock/evidence /run/reddock-api /app/static \
    && chown -R reddock:reddock /var/lib/reddock /run/reddock-api /app
COPY backend/pyproject.toml backend/README.md ./
COPY backend/app ./app
COPY LICENSE THIRD_PARTY_NOTICES.md docs/NMAP_SOURCE_OFFER.md /usr/share/doc/reddock/
RUN pip install --no-cache-dir ".[postgres]"
COPY --from=frontend-build /build/frontend/dist /app/static
RUN chown -R reddock:reddock /app
USER reddock
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/ready')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]
