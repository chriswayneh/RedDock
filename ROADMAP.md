# RedDock roadmap

## The short version

You can already run RedDock locally, define allowed targets, collect observations, review findings, explore their connections, and export reports with evidence. AI advice is optional. [Try it step by step](docs/GETTING_STARTED.md).

The latest release is **v0.8.0 (Phase 7)**. **Phase 8 is in progress, not a finished production release.** Its purpose is to make the tool more reliable and prepare for future controlled multi-user deployments. Sign-in, SSO, and usable role-based accounts are not available today; supporting code is not a shipped feature.

Current work focuses on connecting the dormant identity and session foundations into a complete sign-in flow, adding administration, and proving the PostgreSQL, proxy, recovery, scaling, and deployment paths end to end. The checkpoints below separate what works now from what still needs to be finished.

## Phase 0: Foundation (complete)

Containerized application, React UI shell, FastAPI API, OpenAPI 3.1 schema and Swagger UI explorer, SQLite Dockyards, safety model, documentation, tests, and CI. Completion means a clean checkout can build and launch RedDock locally; Phase 0 contains no assessment tools.

## Phase 1: Discovery (complete)

DockGuard scope definitions, asset/service/observation models, the Nmap and HTTP discovery adapters, discovery-run auditing, and the RedLedger evidence foundation. Scoped discovery now produces auditable asset observations with hashed evidence. Released as v0.2.0 and finalized in v0.2.1.

## Phase 2: Detection (complete)

Normalized findings, the detector contract and registry, detection runs, deduplication by stable fingerprint, a finding lifecycle that resolves rather than deletes, and the CVE enrichment boundary. Observations now become traceable findings without fabricating data: a finding names the detector and rule that produced it, cites the observations it was drawn from, and carries the hashes that verify them. Released as v0.3.0.

RedDock ships no CVE data. Enrichment is a boundary with a local, operator-supplied catalogue behind it, and a catalogue match is an association rather than a conclusion. See [ADR 0007](docs/adr/0007-cve-enrichment-is-an-association.md).

## Phase 3: Validation (complete)

Controlled non-destructive validation is now limited to one fixed HTTP-origin recheck for an eligible open `http.security_headers` finding. Creating a request makes no network contact; a separate local approval note is required, DockGuard re-evaluates the recorded origin immediately before the probe, and a raw/normalized/metadata/manifest evidence package is SHA-256 hashed. Outcomes are `confirmed`, `not_reproduced`, or `indeterminate`, with confidence stated separately. There are no payloads, credentials, arbitrary URLs, redirects, response bodies, or commands. Released as v0.4.0.

## Phase 4: Correlation (complete)

Finding correlation, exact-address asset relationships, fixed CWE mappings, and the RedPath visualization are implemented. Correlation reads stored state only, accepts no target or tuning parameters, and retains a hashed snapshot. Every displayed relationship states its basis and carries the discovery evidence hash or hashes that support it; it does not infer exploitability, reachability, or aggregate risk. Released as v0.5.0.

## Phase 5: Intelligence (complete)

Optional local or cloud OpenAI-compatible analysis now produces remediation and prioritization advice from stored, evidence-linked findings. Creating a run freezes and hashes the exact packet without contacting a provider; a separate approval note is required after review, and provider identity is bound to that approval. Output is schema-checked against the packet's finding IDs and evidence hashes, retained as hashed advice, and cannot change findings, targets, scope, tools, or commands. RedDock remains fully functional with intelligence disabled. Released as v0.6.0.

## Phase 6: Reporting (complete)

Technical and executive reports, evidence manifests, and portable DockPack exports are implemented. A report freezes one bounded Dockyard snapshot, re-verifies every database-referenced source artifact against its retained SHA-256, and produces deterministic Markdown, JSON, a manifest, and a byte-reproducible ZIP without contacting a target or model. Downloads are hash-checked again before delivery. Released as v0.7.0.

## Phase 7: Advanced / Lab (complete)

The first capability is a fixed, single-host extended
TCP service-discovery profile guarded by both deployment opt-in and a separate,
short-lived per-Dockyard authorization. Authorization, requests, execution,
denials, and revocation have their own audit ledger. The extension boundary is
also implemented as content-addressed, data-only detector manifests rather than
arbitrary code plugins.

Portable lab-audit provenance is included in reporting and DockPacks, and real
Phase 7 screenshots are published. The final security review and complete
CI/Docker test matrix passed. Released as v0.8.0.

## Phase 8: Production polish

**Status: in progress, not released.**

The goal is to make RedDock more reliable to operate and prepare it for future
team use. Today it remains a **local, single-operator application**. Working
sign-in, SSO, and shared-user access are not available yet.

### Available now

- **A more usable workspace:** bookmarkable page, tab, and finding addresses;
  browser Back and Forward; full dashboard counts; complete paginated
  inventories and run histories; readable dates; and read-only Settings. Every
  bounded list reports its total and keeps the 100-row page size. Tabs load
  their own data and poll only while visible discovery or validation work is
  running.
- **An opt-in API explorer:** Swagger and the schema are off by default, with
  an explicit local developer switch and the same loopback-only boundary.
- **A database choice:** keep the simple default setup or use the private
  [PostgreSQL package](docs/POSTGRESQL.md). A readiness check confirms the app
  can reach its database, not just that its process is running.
- **AI is optional:** the normal package needs no model. The optional Ollama
  bundle supplies a local AI runtime and downloads Qwen3.5 4B separately.
- **More security checks:** automated code analysis and weekly dependency
  checks help identify problems. The frontend test suite now uses Jest, and CI
  prevents the retired Vitest packages from returning. Dependency updates are
  not merged automatically.
- **Safer releases:** an annotated version tag must match the application,
  packages, README, roadmap, and changelog before automation can publish an
  attested AMD64/ARM64 container image and GitHub Release.
- **Native platform checks:** both AMD64 and ARM64 GitHub runners now build the
  production image and complete the same discovery-through-reporting smoke test.
- **Recoverable local data:** the default SQLite package has an offline,
  integrity-checked backup format, a networkless least-privilege maintenance
  overlay, rollback-safe staged restore, and POSIX-ordered interrupted-restore
  recovery that blocks application startup until an operator resolves it.
- **Reliability and safety fixes:** current protections strengthen
  target exclusions, limits slow web checks, prevents duplicate validation
  approvals, and improves interrupted-run recovery and report consistency. It
  also stops another website from starting a validation through your browser,
  tightens what the RedDock page is allowed to load, and removes container
  privileges the application never uses.
- **Accurate repeat discovery:** an explicitly closed or filtered Nmap port
  updates the matching known service while an unscanned port remains unchanged.
  Exact compact port lists are retained as evidence; count-only summaries never
  become guessed inventory, and newly closed ports do not fill the service list.

### Foundations built but not enabled

Supporting code exists for organizations, user profiles, role-based permissions,
and secure browser sessions. These pieces still need to be connected into a
complete, tested sign-in and administration experience.

**This groundwork does not make RedDock a supported multi-user or internet-facing
service.** Unsupported deployment modes remain blocked.

### Still needed before release

- **Working team access:** integrate sign-in, SSO, permissions, and administration.
- **Operational readiness:** complete PostgreSQL disaster recovery, production
  deployment, and scaling validation. Continue recovery drills for the shipped
  SQLite procedure.
- **End-to-end and independent review:** test the complete experience and
  address review findings. Passing automated checks is not a security certification.

### Technical details

<details>
<summary>Expand implementation checkpoints and security boundaries</summary>

#### Database and packaging

- Validated Alembic baseline, packaged PostgreSQL driver, and a private,
  pinned PostgreSQL Compose profile.
- Mounted database/provider secrets, real-server migration/CRUD CI, and a
  database-backed readiness probe separate from process liveness.
- Explicit no-LLM default and optional AMD64/ARM64 Ollama + Qwen3.5 4B bundle;
  this does not mark all Phase 8 platform work complete.
- Offline SQLite archives bind the database and retained evidence with strict
  portable manifests and SHA-256 hashes. Verification checks SQLite integrity,
  known migration state, and database-backed evidence references. Restore uses
  staged same-volume replacements plus an ordered recovery marker. POSIX paths
  receive file and directory durability flushes; native Windows host operation
  does not claim sudden-power-loss ordering. Because the database and evidence
  are separate paths, neither mode claims one crash-atomic filesystem
  transaction.

#### Identity and session groundwork

These primitives are not an enabled authentication system:

- Organizations, OIDC-keyed profiles, memberships, non-null organization
  ownership, least-privilege API enforcement, and request-scoped tenancy guards.
- Hash-only session storage, high-entropy session issuance, expiry, targeted
  and membership-wide revocation, and active-membership checks.
- CSRF-hash checks, active-session limits, retention-cutoff cleanup, and
  tenant-scoped structured security events without free-form metadata.

#### Browser boundary

- Dormant exact-HTTPS-origin checks and host-bound secure session-cookie policy.
- A request verifier requiring both exact Origin and CSRF proof for mutations,
  with ambiguous duplicate credentials rejected.
- Local mode rejects public-origin configuration. Central response hardening
  denies framing and browser capabilities, blocks content sniffing and referrer
  disclosure, and marks every API response `no-store`.
- A dormant, unregistered OIDC client validates deployment-owned endpoint
  origins, bounded discovery/JWKS/token responses, authorization-code PKCE,
  one-use browser-bound login state, and asymmetric issuer/audience/nonce/time
  claims. It retains no provider tokens or profile claims and does not enable
  sign-in or `server` mode.
- The next enablement checkpoint still needs application-scoped provider/JWKS
  caching, cross-worker database rate limits, session idle/touch/rotation,
  callback and administration routes, TLS proxy trust, and end-to-end tests.

#### Automated review

- Immutable GitHub Action pins for the CI matrix and `security-extended`
  CodeQL analysis across workflows, frontend, and backend.
- Grouped weekly Dependabot checks for Actions, Docker, npm, and pip,
  without automatic merging.
- Fail-closed release metadata verification and full-SHA-pinned automation for
  attested AMD64/ARM64 images and generated GitHub Releases.
- Native AMD64 and ARM64 container jobs run the complete production smoke path,
  including the gated lab profile and packaged detector provenance.

#### Reliability fixes

- Mapped-IPv6 exclusion bypass and slow-response HTTP worker exhaustion fixed.
- Overlapping validation approvals prevented; interrupted validation recovered.
- Discovery observations and their evidence published atomically.
- PostgreSQL reports captured with consistent snapshot isolation.
- Regression coverage includes real PostgreSQL concurrent writes and
  loopback-only trickling HTTP responses.
- Re-detection repairs missing evidence IDs only when the original discovery
  evidence record still exists. Lost evidence cannot be reconstructed by
  inventing hashes.

#### Release boundary

The [threat model](docs/THREAT_MODEL.md) and
[identity/tenancy design decision](docs/adr/0013-production-identity-and-tenancy.md)
separate the current local workflow from a future authenticated server mode
that refuses requests unless its security requirements are satisfied.

Phase 8 is complete only when identity and browser controls are integrated
with OIDC and route authentication, and administration, deployment,
PostgreSQL recovery, scaling, and remaining operational requirements are documented and
validated end to end.

</details>
