# RedDock backend

This package contains RedDock Core's FastAPI application: the API, DockGuard scope enforcement, the discovery adapters, the detectors, and SQLAlchemy persistence with SQLite by default and packaged PostgreSQL support. Run it via the repository's Docker Compose workflow, or install it locally for development with Python 3.13.

```text
app/targets.py      target parsing and normalization
app/dockguard.py    scope evaluation and decisions
app/services.py     Dockyard and scope operations
app/inventory.py    asset, service, and observation persistence rules
app/discovery/      adapter contract, adapters, registry, and run orchestration
app/detection/      detector contract, detectors, registry, enrichment, and run orchestration
app/findings.py     finding persistence, deduplication, and lifecycle rules
app/validation/     approval-gated, fixed HTTP-origin validation orchestration
app/correlation/    stored-state relationships, fixed CWE mappings, and RedPath assembly
app/intelligence/   approval-gated, provider-neutral advice over reviewed evidence packets
app/reporting/      deterministic reports, evidence manifests, and DockPack exports
app/authorization.py reviewed role/permission contract for the future authenticated mode
app/session_auth.py  hash-only browser-session issuance and resolution primitive
app/evidence.py     hashed evidence storage
```

A discovery adapter may contact a target after DockGuard allows it. A detector
may not contact anything: it is handed a frozen snapshot of one Dockyard and
returns value objects, with no session, socket, subprocess or operator input in
reach. `tests/test_detection_contract.py` reads the detection package and fails
if that stops being true.

Validation is not a general-purpose testing interface. It can recheck only an
eligible open HTTP security-header finding at its recorded origin. Requesting
one records intent without contacting a target; a separate approval note
re-evaluates DockGuard and then reuses the fixed, bodyless HTTP probe. The
raw result, normalized conclusion, metadata, and manifest are retained with
SHA-256 hashes.

Correlation is passive too. It accepts no target or options and relates only
stored records with exact identifiers and retained evidence hashes. RedPath
renders those relationships and their explanations; it does not infer an attack
path, exploitability, causation, or aggregate risk.

Intelligence is optional and advice-only. Creating a run stores the exact
evidence-linked packet without contacting a provider. A separate approval note
sends that reviewed packet to the process-configured OpenAI-compatible endpoint;
the provider response must match a strict schema and may cite only findings and
hashes in the packet. It receives no tools and cannot change RedDock state.
The default `compose.yaml` package contains no LLM. The optional
`compose.ollama.yaml` bundle provisions a private Ollama sidecar and Qwen3.5 4B
model volume; an operator can replace that model or use any compatible endpoint
without changing this backend package.

The optional `compose.postgres.yaml` profile replaces SQLite with a private,
pinned PostgreSQL 17 service. RedDock and PostgreSQL receive the password as a
mounted Compose secret, PostgreSQL has no host port, and CI proves the migration
head and CRUD behavior against a real server. This remains a loopback-only
validation profile, not the future authenticated server mode. See
[Optional PostgreSQL](../docs/POSTGRESQL.md).

Phase 8 also defines the deny-by-default owner, admin, operator, auditor, and
viewer permission sets. Every API method/path is classified as public or bound
to one named permission, a test rejects unclassified routes, and the API router
enforces the manifest against an explicit local owner. Negative tests prove a
viewer cannot mutate state, read raw evidence, approve model disclosure, or
export a DockPack. These controls are not authentication: the only supported
runtime mode remains the account-free loopback `local` mode, and requesting
`server` mode fails startup until OIDC sessions and tenant-scoped context
resolution are complete.

The dormant session primitive issues independent 256-bit browser and CSRF
tokens, masks them from object representations, stores only their hashes, and
resolves a context only while the session, membership, user, and role remain
valid. No route issues or accepts these tokens yet.

Reporting is passive and deterministic. It accepts an empty request, refuses a
snapshot while source work is active, and reads only database-referenced
artifacts beneath RedLedger. Every source hash is re-verified before RedDock
renders technical and executive Markdown, creates the evidence manifest, and
packages a portable DockPack. Fixed archive metadata makes unchanged retained
state byte-reproducible; the package hash is checked again before download.
