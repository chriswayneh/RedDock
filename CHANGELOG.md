# Changelog

All notable changes to RedDock are documented here.

## [0.6.0] — Phase 5 Intelligence

### Added

- An opt-in OpenAI-compatible provider boundary for local or cloud remediation and prioritization advice
- A two-step workflow that freezes, displays, retains, and hashes the exact stored-data packet before any provider request
- Separate local approval notes bound to the configured provider, model, destination, and local/external classification
- Strict structured response validation whose finding IDs and evidence hashes must be present in the approved packet
- Atomic one-shot approval, retained-packet integrity verification, prompt-version binding, and a true total provider deadline
- An Intelligence workspace for provider status, packet review, approvals, results, hashes, and limitations
- Additive `IntelligenceRun` persistence, restart recovery, API and UI coverage, and ADR 0010

### Security

- Intelligence is disabled by default and accepts no API-supplied provider credentials, destinations, prompts, targets, commands, tools, or actions
- API keys remain process-only; they are never stored, returned to the browser, retained in evidence, or logged
- External destinations require HTTPS; redirects are refused; total time, raw wire bytes, decoded bytes, response fragments, packet size, findings, and retained runs are independently bounded
- FastAPI and the development test stack are updated to current compatible release lines so Starlette and pytest include their published security fixes
- Model output is advice only and cannot modify finding state, trigger validation, widen scope, invoke a tool, or perform remediation
- Stored strings are treated as untrusted data, and output that cites an unknown finding or evidence hash fails closed

## [0.5.0] — Phase 4 Correlation

### Added

- `CorrelationRun` snapshots with counts and hashed normalized/metadata evidence
- Exact-address web-to-host asset relationships backed by the observation and discovery artifact that recorded the address
- Same-asset and related-asset finding correlations carrying both findings' evidence hashes
- A fixed, versioned CWE mapping table for RedDock's detector rules; classification never changes a finding
- `/correlations` and `/redpath` APIs whose correlation request body is deliberately empty
- RedPath, an evidence-linked asset/finding graph with relationship explanations and framework mappings
- Structural, API, isolation, schema-upgrade, frontend, and end-to-end smoke coverage
- ADR 0009 documenting why correlation asserts only evidence-linked facts

### Security

- Correlation has no network or process capability and accepts no target, selector, weight, script, or plugin
- Every edge requires retained evidence; records lacking the necessary hash are omitted instead of inferred
- Exact identifier equality is the only asset-linking rule, and correlation does not claim attack reachability, exploitability, causation, or risk
- Snapshot edge count is capped at 5,000 per Dockyard

## [0.4.0] — Phase 3 Validation

Phase 3 adds a deliberately narrow path to recheck a conclusion without turning
RedDock into a general-purpose scanner.

### Added

- `ValidationRun`, an auditable request/approval/result record linked to one finding
- A fixed `http.origin_recheck` validator for eligible open `http.security_headers` findings only
- Separate request and approval API endpoints; the request contacts nothing, while approval requires a 3–500 character note
- A second DockGuard decision immediately before contact, with denied validation attempts retained in the audit trail
- `confirmed`, `not_reproduced`, and `indeterminate` outcomes with confidence kept separate from the original finding's severity and confidence
- A validation evidence package containing `raw/http-recheck.json`, `normalized/result.json`, `metadata.json`, and `raw/manifest.json`, with SHA-256 hashes recorded on the run
- A Validation workspace tab for requests, approvals, outcomes, DockGuard decisions, and evidence hashes
- Tests for the approval boundary, successful evidence package, scope revocation, unsupported findings, and additive schema upgrade
- ADR 0008 documenting why validation is approval-gated and bounded

### Security

- Validation accepts no operator-selected URL, payload, credential, cookie, command, or tool option; it uses a finding's recorded origin and the existing fixed HTTP probe
- It follows no redirects, reads no response body, performs no crawling or browser automation, and is limited to one/two safe HTTP requests (a `HEAD` and only a standards-required `GET` fallback)
- Only an open eligible finding may be requested, requests are bounded per Dockyard, and scope removal between request and approval denies the attempt before any contact
- An approval is a local audit assertion, not proof of external authorization; DockGuard remains the technical scope boundary

## [0.3.0] — Phase 2 Detection

Observations can now become findings. They remain separate concepts: an observation states what an adapter saw, a finding states what one named detector concluded from one or more of them, and a finding that cites no observation is refused rather than stored.

### Added

- Detector contract: a detector receives an immutable snapshot of one Dockyard and returns value objects, with no database session, socket, subprocess, target, or operator-supplied option in reach
- Detector registry with an explicit, fixed set; nothing is discovered, imported by name, or loaded from a plugin directory at runtime
- DetectionRun: an auditable record of which detectors ran, what each did or failed to do, how much state was read, what was produced and resolved, and which enrichment source was in effect
- Finding model with separate severity and confidence, a stable SHA-256 fingerprint, and links to the observations that support it
- Finding lifecycle: `open`, `resolved`, `suppressed`, and `accepted`, where resolution is RedDock's answer about the data and suppression and acceptance are the operator's
- FindingEvidence linking each finding to its observations, their discovery run, and the hashed RedLedger artifact behind them
- `http.security_headers` detector: plaintext transport and absent response-level protections, for the headers the probe recorded that it examined
- `service.rules` detector: a fixed table of protocol rules over services RedDock identified, plus disclosed product versions
- `tls.certificates` detector: what certificate verification objected to, using the code and message OpenSSL gave
- CVE enrichment boundary with an optional local catalogue behind `REDDOCK_CVE_CATALOG`
- API for detectors, detection runs, findings, finding detail with evidence, and operator status decisions
- Findings and Detection sections in the workspace, and a Dockyard-scoped Findings page
- ADR 0006 (detection boundary) and ADR 0007 (CVE enrichment is an association)

### Changed

- The HTTP probe records the header set it examined alongside the headers that were present, so a detector can tell an absent header from one RedDock never looked for
- The HTTP probe records the code and message OpenSSL gave when certificate verification failed, because an unverified handshake returns an empty peer certificate
- The HTTP probe retains `x-content-type-options`, `content-security-policy`, and `x-frame-options` in addition to the previous allowlist
- The HTTP probe User-Agent is derived from the application version rather than repeated as a literal
- The evidence store writes detection documents under a `detection` scope, so a detection run and a discovery run that share an identifier cannot share a directory
- The dashboard reports open findings; the observations view states that a detector, not the observation, produces interpretation

### Security

- Detection contacts nothing and takes no operator parameters: the request body is empty by design, so no operator string reaches a detector
- A detector that raises, returns malformed output, or names data outside its Dockyard is failed as a whole; its results are discarded and it resolves nothing
- Findings are never deleted, and an operator cannot declare one resolved
- Severity is stated conservatively and separately from confidence; RedDock produces no risk score, CVSS vector, or aggregate rating
- No CVE data is downloaded, matching is exact-version only, and an association never changes a severity, confidence, or status
- Detection snapshots, per-detector output, per-finding evidence references, and an operator-supplied catalogue are all bounded

### Testing

- Structural tests that parse the detection package and fail the build if a detector could reach a network, a process, the filesystem, or the database
- Detection orchestration tests for deduplication, resolution, reopening, operator decisions, detector failure isolation, malformed output, Dockyard isolation, and deterministic evidence
- A fingerprint test that runs in separate processes under different `PYTHONHASHSEED` values
- Detector tests covering false-positive avoidance: unexamined headers, redirects, server errors, scheme handling, and port numbers without an identification
- Schema-upgrade test proving a 0.2.1-shaped database upgrades in place and runs a full detection on data the previous release wrote
- A version test asserting the application, the API, and both packages report one version
- The end-to-end smoke test now covers detection, findings, evidence traceability, and deduplication

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
