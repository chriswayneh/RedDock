# Changelog

All notable changes to RedDock are documented here.

## [0.2.1] — Phase 1 Discovery, finalized

Phase 1 remains as released in 0.2.0; this is a corrective patch release.

### Changed

- The application, API, and backend/frontend package metadata now all report the current release version
- The HTTP probe User-Agent identifies the current RedDock version
- README and screenshots present Phase 1 as released rather than pending

### Notes

- No change to DockGuard, discovery, inventory, or evidence behaviour

## [0.2.0] — Phase 1 Discovery

### Added

- DockGuard: deterministic, fail-closed scope evaluation enforced server-side on every discovery request and again immediately before a tool runs
- Dockyard scope entries with inclusions, exclusions, and a target-evaluation endpoint
- Target normalization for IPv4, IPv6, networks, hostnames, and HTTP origins, rejecting ambiguous and unsafe forms
- Asset, Service, Observation, DiscoveryRun, and EvidenceRecord models with deterministic asset and service identity
- Discovery adapter boundary with an explicit registry
- Nmap adapter with non-invasive host-discovery and service-discovery profiles
- HTTP probe adapter for a single request against a scoped origin
- RedLedger evidence foundation: raw output, normalized result, and run metadata, each SHA-256 hashed
- Dockyard workspace UI with scope management, a DockGuard preview, discovery launch, and inventory views
- Functional Assets navigation and a minimal RedLedger evidence view
- End-to-end Phase 1 smoke test against loopback

### Security

- Tool argument vectors generated from a fixed table of approved options and executed without a shell
- Scope entries limited to 256 addresses; default routes rejected
- Bounded run duration, concurrency, and evidence size; runs interrupted by a restart are marked failed
- Evidence writes confined to the run directory; cookies and session material never retained

### Containerization

- Nmap installed in the RedDock image so no host installation is required
- Evidence stored alongside the database in the existing named volume

### Testing

- DockGuard, target normalization, inventory, evidence, adapter, and discovery-orchestration test suites
- Schema-upgrade test proving Phase 0 data survives the Phase 1 schema
- Frontend tests covering scope, DockGuard decisions, and discovery gating

## [0.1.0] — Phase 0 Foundation

### Added

- Phase 0 containerized application foundation
- Dockyard persistence and API
- RedDock dashboard and Dockyard UI shell

### Architecture

- Single-container FastAPI and production-built React application
- SQLite persistence through a named Docker volume
- Documented DockGuard, tool-adapter, RedLedger, and AI safety boundaries

### Containerization

- Non-root Linux runtime image and Docker Compose launch workflow
- Container health checks and local browser access on port 8080

### Testing

- Backend endpoint and persistence tests
- Frontend interaction tests, linting, type checking, and production build checks

### Documentation

- Architecture, roadmap, security, contribution, and ADR documentation
