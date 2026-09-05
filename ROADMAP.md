# RedDock roadmap

## Completed — Phase 0: Foundation

Containerized application, React UI shell, FastAPI API, OpenAPI 3.1 schema and Swagger UI explorer, SQLite Dockyards, safety model, documentation, tests, and CI. Completion means a clean checkout can build and launch RedDock locally; Phase 0 contains no assessment tools.

## Completed — Phase 1: Discovery

DockGuard scope definitions, asset/service/observation models, the Nmap and HTTP discovery adapters, discovery-run auditing, and the RedLedger evidence foundation. Scoped discovery now produces auditable asset observations with hashed evidence. Released as v0.2.0 and finalized in v0.2.1.

## Completed — Phase 2: Detection

Normalized findings, the detector contract and registry, detection runs, deduplication by stable fingerprint, a finding lifecycle that resolves rather than deletes, and the CVE enrichment boundary. Observations now become traceable findings without fabricating data: a finding names the detector and rule that produced it, cites the observations it was drawn from, and carries the hashes that verify them. Released as v0.3.0.

RedDock ships no CVE data. Enrichment is a boundary with a local, operator-supplied catalogue behind it, and a catalogue match is an association rather than a conclusion. See [ADR 0007](docs/adr/0007-cve-enrichment-is-an-association.md).

## Completed — Phase 3: Validation

Controlled non-destructive validation is now limited to one fixed HTTP-origin recheck for an eligible open `http.security_headers` finding. Creating a request makes no network contact; a separate local approval note is required, DockGuard re-evaluates the recorded origin immediately before the probe, and a raw/normalized/metadata/manifest evidence package is SHA-256 hashed. Outcomes are `confirmed`, `not_reproduced`, or `indeterminate`, with confidence stated separately. There are no payloads, credentials, arbitrary URLs, redirects, response bodies, or commands. Released as v0.4.0.

## Completed — Phase 4: Correlation

Finding correlation, exact-address asset relationships, fixed CWE mappings, and the RedPath visualization are implemented. Correlation reads stored state only, accepts no target or tuning parameters, and retains a hashed snapshot. Every displayed relationship states its basis and carries the discovery evidence hash or hashes that support it; it does not infer exploitability, reachability, or aggregate risk. Released as v0.5.0.

## Completed — Phase 5: Intelligence

Optional local or cloud OpenAI-compatible analysis now produces remediation and prioritization advice from stored, evidence-linked findings. Creating a run freezes and hashes the exact packet without contacting a provider; a separate approval note is required after review, and provider identity is bound to that approval. Output is schema-checked against the packet's finding IDs and evidence hashes, retained as hashed advice, and cannot change findings, targets, scope, tools, or commands. RedDock remains fully functional with intelligence disabled. Released as v0.6.0.

## Completed — Phase 6: Reporting

Technical and executive reports, evidence manifests, and portable DockPack exports are implemented. A report freezes one bounded Dockyard snapshot, re-verifies every database-referenced source artifact against its retained SHA-256, and produces deterministic Markdown, JSON, a manifest, and a byte-reproducible ZIP without contacting a target or model. Downloads are hash-checked again before delivery. Released as v0.7.0.

## Completed — Phase 7: Advanced / Lab

The first capability is a fixed, single-host extended
TCP service-discovery profile guarded by both deployment opt-in and a separate,
short-lived per-Dockyard authorization. Authorization, requests, execution,
denials, and revocation have their own audit ledger. The extension boundary is
also implemented as content-addressed, data-only detector manifests rather than
arbitrary code plugins.

Portable lab-audit provenance is included in reporting and DockPacks, and real
Phase 7 screenshots are published. The final security review and complete
CI/Docker test matrix passed. Released as v0.8.0.

## Phase 8 — Production polish

RBAC, optional PostgreSQL, scaling work, release automation, ARM64 support, and production hardening. The persistence checkpoint now includes a validated Alembic baseline, packaged driver, a private pinned [PostgreSQL Compose profile](docs/POSTGRESQL.md), mounted database/provider secrets, and real-server migration/CRUD CI. The identity checkpoint creates organizations, OIDC-keyed user profiles, memberships, hash-only session storage, non-null organization ownership, a centralized deny-by-default role contract, exhaustive API permission enforcement, and organization-scoped Dockyard list/create/load operations while preserving the account-free workflow. Unsupported deployment modes are rejected; this does not yet enable authentication or shared use. The default no-LLM package and optional AMD64/ARM64 Ollama + Qwen3.5 4B bundle are explicit. The source-backed [threat model](docs/THREAT_MODEL.md) and [identity/tenancy ADR](docs/adr/0013-production-identity-and-tenancy.md) define the non-negotiable boundary between backward-compatible loopback local mode and a future fail-closed authenticated server mode. Complete when session resolution, child-resource tenancy review, OIDC, administration, deployment, backup/restore, scaling, and operational requirements are implemented, documented, and validated end to end.
