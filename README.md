<div align="center">

# RedDock

**Discover. Validate. Prove.**

Container-native security assessment and validation platform with controlled execution and evidence-backed findings.

[![Release](https://img.shields.io/github/v/tag/chriswayneh/RedDock?label=release&color=C1121F)](https://github.com/chriswayneh/RedDock/tags)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-supported-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/chriswayneh/RedDock/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/chriswayneh/RedDock/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/chriswayneh/RedDock)](LICENSE)
[![Phase](https://img.shields.io/badge/phase-1%20Discovery-C1121F)](ROADMAP.md)

**Current release:** [v0.2.1](https://github.com/chriswayneh/RedDock/tags) — Phase 1 Discovery · Active development

[Quick Start](#quick-start) · [Current Capabilities](#what-you-get) · [Architecture](#architecture) · [Security](#security-by-design) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## What This Is

RedDock explores how security tooling can become portable, container-native, policy-controlled, reproducible, and evidence-driven instead of a collection of host-specific scripts. It is designed for authorized environments and intentionally grows through small, verified phases.

Its operating model is simple: **AI proposes. Policy authorizes. Tools execute. Evidence proves.** Phase 1 implements the middle two: an explicit authorized scope, a policy boundary called DockGuard that every target must pass, and non-invasive discovery adapters that produce hashed evidence. There is still no AI integration, vulnerability detection, exploitation, credential attack, or payload of any kind.

## What You Get

| Capability | Phase 1 implementation |
| --- | --- |
| Runtime | One Dockerized application that serves the UI and API on the same origin |
| Workspaces | Dockyards that own an explicit authorized scope |
| Scope policy | DockGuard evaluates every target deterministically and fails closed |
| Discovery | Nmap host and TCP service discovery, plus a single-request HTTP origin probe |
| Inventory | Normalized assets and services that reconcile across repeat discovery |
| Observations | Dated, adapter-attributed records of what was seen — never findings |
| Evidence | Raw output, normalized result, and metadata per run, each SHA-256 hashed |
| Persistence | SQLite and evidence stored in a named Docker volume |
| Safety | Non-invasive profiles only; no scripting, brute force, evasion, or exploitation |

## Screenshots

<div align="center">

<img src="docs/screenshots/dashboard.png" alt="RedDock dashboard showing workspace metrics and a discovery run audit trail" width="900">

<sub>The dashboard: workspace metrics and the discovery audit trail, including a run DockGuard denied.</sub>

<br><br>

<img src="docs/screenshots/workspace.png" alt="RedDock Dockyard workspace showing the discovery launch flow beside a DockGuard ALLOWED decision" width="900">

<sub>The Dockyard workspace: a target must pass DockGuard before discovery can be launched.</sub>

</div>

## Quick Start

Docker Engine or Docker Desktop with Docker Compose is the supported way to run RedDock. Nmap ships inside the image; nothing is installed on your host.

```bash
git clone https://github.com/chriswayneh/RedDock.git
cd RedDock
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080). The health endpoint is [http://localhost:8080/api/health](http://localhost:8080/api/health), and interactive API documentation is at [http://localhost:8080/docs](http://localhost:8080/docs).

Stop the application with `docker compose down`. The `reddock-data` volume holds both the database and retained evidence and survives normal container recreation; use `docker compose down -v` only when you deliberately want to erase local data.

## How It Works

1. Create a Dockyard to represent an authorized engagement workspace.
2. Define its authorized scope: included targets, and exclusions that always win.
3. Enter a target and ask DockGuard for a decision. It answers `ALLOWED` or a specific denial with the reason and the scope entry that decided it.
4. Run a safe discovery profile. The server re-evaluates DockGuard immediately before the adapter is invoked, so an out-of-scope target is never reached.
5. Results normalize into assets, services, and observations, and the run's raw output, normalized result, and metadata are retained and hashed.

Run the same discovery again and RedDock updates what it already knows rather than duplicating it, while every observation is kept as history.

## Architecture

```mermaid
flowchart TB
  Browser[Browser] --> UI[React UI]
  UI --> API[FastAPI API]
  API --> Guard{DockGuard}
  Guard -->|denied| Audit[Recorded denial]
  Guard -->|allowed| Adapter[Discovery adapter]
  Adapter --> Normalize[Assets · Services · Observations]
  Normalize --> Database[(SQLite named Docker volume)]
  Adapter --> Evidence[(Hashed evidence)]
```

The production image builds the React application and serves it from the same FastAPI process that exposes `/api`. There is deliberately no reverse proxy, separate frontend service, queue, or remote dependency; discovery runs on a small bounded thread pool inside the application. See [ARCHITECTURE.md](ARCHITECTURE.md) for the scope model, adapter boundary, and trust boundaries.

## Security by Design

> **AI proposes. Policy authorizes. Tools execute. Evidence proves.**

- **Scope is explicit and server-enforced.** DockGuard evaluates every target twice — when the run is requested and again immediately before the tool is invoked. The UI cannot bypass it.
- **Denials are specific.** `denied_out_of_scope`, `denied_excluded`, `invalid_target`, and `unresolved` each carry the reason and the matching scope entry.
- **Fail closed.** Anything DockGuard cannot positively place inside the authorized scope is denied, including a scope it cannot parse.
- **Names and addresses stay separate.** A hostname is never authorized because it resolves into an authorized network, and there is no wildcard or subdomain expansion.
- **Tools never receive operator flags.** Argument vectors are generated internally from a fixed table of safe options, executed without a shell, bounded by timeouts, and built only from targets normalized to a character set that cannot form an option.
- **Dangerously broad scope is rejected.** A scope entry may not cover more than 256 addresses, and a default route is never valid.
- **Observations are not findings.** RedDock records what an adapter saw and assigns no severity, score, or verdict.

Read [SECURITY.md](SECURITY.md) for the authorized-use policy and the full Phase 1 control list.

## Repository Structure

```text
backend/       FastAPI API, DockGuard, discovery adapters, evidence, and SQLite persistence
frontend/      React and TypeScript dashboard
scripts/       Local end-to-end smoke test
docs/          Architecture decisions and project documentation
.github/       Continuous-integration workflow
```

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Current system boundaries and future design seams |
| [Security](SECURITY.md) | Authorized-use policy and product safety model |
| [Roadmap](ROADMAP.md) | Phased delivery plan and clear separation of planned work |
| [Contributing](CONTRIBUTING.md) | Local checks and contribution guidelines |
| [Changelog](CHANGELOG.md) | Release history |

## Project Status

**v0.2.1 is the current release:** it finalizes Phase 1 with consistent version metadata across the application, API, and packages.

**v0.2.0 delivered Phase 1 — Discovery:** DockGuard scope enforcement, asset/service/observation models, the Nmap and HTTP discovery adapters, discovery-run auditing, and the RedLedger evidence foundation.

**v0.1.0 delivered Phase 0 — Foundation:** a containerized React/FastAPI application, local Dockyard persistence, a dashboard, documentation, tests, and CI.

**Next: Phase 2 — Detection.** Normalized findings, detection adapter contracts, CVE enrichment, and deduplication are planned, not implemented. See the [roadmap](ROADMAP.md) for the complete phased plan.

## Contributing and Security

Contributions are welcome when they preserve the safety model and keep changes small and tested. Start with [CONTRIBUTING.md](CONTRIBUTING.md), and report potential vulnerabilities through [SECURITY.md](SECURITY.md) or GitHub Private Vulnerability Reporting.

## License

[MIT](LICENSE).

## Built With

[Python](https://www.python.org/) · [FastAPI](https://fastapi.tiangolo.com/) · [Pydantic](https://docs.pydantic.dev/) · [SQLAlchemy](https://www.sqlalchemy.org/) · [SQLite](https://www.sqlite.org/) · [Nmap](https://nmap.org/) · [React](https://react.dev/) · [TypeScript](https://www.typescriptlang.org/) · [Vite](https://vite.dev/) · [Docker](https://www.docker.com/) · [GitHub Actions](https://github.com/features/actions)

<br>

<p align="center">
  <strong>Discover. Validate. Prove.</strong><br>
  <sub>Controlled security validation, built one verified phase at a time.</sub>
</p>
