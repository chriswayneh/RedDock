# RedDock roadmap

## Completed — Phase 0: Foundation

Containerized application, React UI shell, FastAPI API, SQLite Dockyards, safety model, documentation, tests, and CI. Completion means a clean checkout can build and launch RedDock locally; Phase 0 contains no assessment tools.

## Completed — Phase 1: Discovery

DockGuard scope definitions, asset/service/observation models, the Nmap and HTTP discovery adapters, discovery-run auditing, and the RedLedger evidence foundation. Scoped discovery now produces auditable asset observations with hashed evidence. Released as v0.2.0 and finalized in v0.2.1.

## Completed — Phase 2: Detection

Normalized findings, the detector contract and registry, detection runs, deduplication by stable fingerprint, a finding lifecycle that resolves rather than deletes, and the CVE enrichment boundary. Observations now become traceable findings without fabricating data: a finding names the detector and rule that produced it, cites the observations it was drawn from, and carries the hashes that verify them. Released as v0.3.0.

RedDock ships no CVE data. Enrichment is a boundary with a local, operator-supplied catalogue behind it, and a catalogue match is an association rather than a conclusion. See [ADR 0007](docs/adr/0007-cve-enrichment-is-an-association.md).

## Next — Phase 3: Validation

Controlled non-destructive validation, confidence scoring, approval gates, and evidence packages. Complete when validation actions require scope and policy decisions.

## Phase 4 — Correlation

Finding correlation, asset relationships, framework mappings, and RedPath visualization. Complete when relationships are explainable and evidence-linked.

## Phase 5 — Intelligence

Optional local or cloud LLM analysis for remediation and prioritization. Complete when AI output is structured, reviewable, and never bypasses DockGuard.

## Phase 6 — Reporting

Technical and executive reports, evidence manifests, and portable DockPack exports. Complete when reports are reproducible from retained evidence.

## Phase 7 — Advanced / Lab

Explicitly authorized lab-mode capabilities and a broader plugin ecosystem. Complete when lab-only controls are clear and separately guarded.

## Phase 8 — Production polish

RBAC, optional PostgreSQL, scaling work, release automation, ARM64 support, and production hardening. Complete when operational requirements are documented and validated.
