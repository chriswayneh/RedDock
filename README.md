# RedDock

## Discover. Validate. Prove.

RedDock is a container-native security assessment and validation platform designed for authorized environments. Its design centers on a simple control model: **AI proposes. Policy authorizes. Tools execute. Evidence proves.**

- **Current release:** `v0.1.0`
- **Current phase:** Phase 0 — Foundation
- **Status:** Active development

> Phase 0 is a working foundation. It intentionally includes no scanning, vulnerability detection, exploitation, credential attacks, payloads, AI integration, or autonomous offensive actions.

![RedDock Phase 0 dashboard](docs/screenshots/dashboard.png)

*RedDock Phase 0 dashboard running locally with an empty Dockyard state. See [screenshot guidance](docs/screenshots/README.md).*

## Why I built RedDock

RedDock began as a hands-on project to explore how modern security tooling can be packaged as a portable, policy-controlled platform instead of a collection of host-specific scripts. It brings together container engineering, API design, frontend development, automation, and evidence-driven validation through small, testable releases.

## Current capabilities

- A containerized FastAPI application with SQLite persistence
- A browser-based RedDock dashboard and Dockyard workspace UI
- Create, list, and inspect Dockyards (engagement workspaces)
- Health, version, and generated OpenAPI endpoints
- Safety, architecture, and contributor documentation

## Technology

| Area | Phase 0 technologies |
| --- | --- |
| Backend | Python, FastAPI, Pydantic, SQLAlchemy, SQLite |
| Frontend | React, TypeScript, Vite |
| Platform | Docker, Docker Compose |
| Engineering | pytest, Vitest, ESLint, Ruff, TypeScript checks, GitHub Actions |

## Architecture at a glance

```text
Browser
  ↓
React UI (production build)
  ↓
FastAPI API
  ↓
Application service and domain model
  ↓
SQLite named volume
```

One Linux container serves the Vite-built React UI and FastAPI API on the same origin. The supported Phase 0 Docker configuration binds only to `localhost`; SQLite persists in a named Docker volume. Detailed boundaries and future seams are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

```bash
git clone https://github.com/chriswayneh/RedDock.git
cd RedDock
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080). The health endpoint is [http://localhost:8080/api/health](http://localhost:8080/api/health), and interactive API documentation is at [http://localhost:8080/docs](http://localhost:8080/docs).

Stop RedDock with `docker compose down`. The `reddock-data` Docker volume survives normal container recreation. To deliberately erase local data, run `docker compose down -v`.

## Development

Docker is the supported run path. For local feedback:

```bash
cd backend
pip install -e ".[dev]"
ruff check app tests
pytest

cd ../frontend
npm ci
npm run lint
npm run check
npm run test
npm run build
```

## Security and authorized use

Use RedDock only on systems you own or are explicitly authorized to assess, including labs, cyber ranges, CTFs, and training environments. Future execution requires explicit scope and policy authorization. Read [SECURITY.md](SECURITY.md) before contributing or deploying.

## Roadmap

Phase 0 is complete. Phase 1 will introduce DockGuard scope definitions and foundational asset modeling; it does not exist in the current product. Later discovery, detection, RedPath, RedLedger, AI, and reporting capabilities remain planned. See [ROADMAP.md](ROADMAP.md).

## Contributing and license

Contributions are welcome—start with [CONTRIBUTING.md](CONTRIBUTING.md). RedDock is available under the [MIT License](LICENSE).
