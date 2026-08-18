FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REDDOCK_DATABASE_URL=sqlite:////var/lib/reddock/reddock.db
WORKDIR /app/backend
RUN groupadd --system reddock && useradd --system --gid reddock --home-dir /app reddock \
    && mkdir -p /var/lib/reddock /app/static \
    && chown -R reddock:reddock /var/lib/reddock /app
COPY backend/pyproject.toml backend/README.md ./
COPY backend/app ./app
RUN pip install --no-cache-dir .
COPY --from=frontend-build /build/frontend/dist /app/static
RUN chown -R reddock:reddock /app
USER reddock
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
