# Security

## Responsible use

RedDock is for systems owned by the operator or assessed with explicit authorization. It is appropriate for authorized engagements, labs, cyber ranges, CTFs, and training environments. Do not use it to access systems outside approved scope.

RedDock can contact a network target. Scoping a target in RedDock is a statement that you are authorized to assess it. The product enforces the scope you declare; it cannot verify that you were entitled to declare it.

## Product safety model

Every target action passes DockGuard before a tool runs, and DockGuard fails closed: anything it cannot positively place inside the Dockyard's authorized scope is denied. Optional intelligence receives no tool access at all and cannot expand target scope or change RedDock state. Reporting has no active capability and packages only retained artifacts whose hashes it has re-verified.

## Zero trust and least privilege status

RedDock treats every boundary crossing as untrusted and gives each component
only the authority needed for its current job. These terms describe concrete
controls, not a certification or a claim that server mode is ready.

| Boundary | Implemented control | Current limit or pending gate |
| --- | --- | --- |
| Network ingress | The supported Compose application listens on a Unix socket. Only the unprivileged ingress proxy receives that socket, and only the proxy publishes `127.0.0.1:8080` on the host. Optional sidecars use separate backend networks and receive no API socket. | This boundary depends on the provided Compose files. Raw container publication or adding another service to the socket volume is not supported. Do not publish RedDock to a LAN, proxy, or the internet. |
| Local change protection | First start generates a high-entropy operator token in the data volume. Unsafe requests require the token, browser requests require one exact local Origin, and a fixed process-local throttle bounds mutation and unlock attempts. | This is an accident boundary for local changes, not user identity. Safe reads remain available through the host-loopback ingress, and the throttle is not shared across processes. |
| Identity | Server mode fails startup. Dormant OIDC primitives constrain provider origins, redirects, response sizes, algorithms, claims, state, nonce, and PKCE. | No authentication route is registered. Login, callback, logout, browser session resolution, proxy trust, and administration remain release gates. |
| Authorization | Routes have a deny-by-default permission manifest. Unknown roles and inactive memberships receive no authority. Resource loaders constrain data by organization. | Current local requests use the reserved local owner. The operator token does not create a user identity, tenant, or role. |
| Target and model access | DockGuard authorizes target contact. Detectors and reports have no network capability. Model advice receives only a separately approved packet and no tools. | RedDock enforces declared scope but cannot establish the operator's legal or contractual authority. |
| Process and secrets | Compose services use fixed unprivileged users, read-only root filesystems, bounded writable mounts, fixed resource limits, dropped capabilities, and `no-new-privileges`. Database credentials use mounted secret files. The dormant limiter uses a separately credentialed PostgreSQL role whose narrow privileges are checked at startup. | PostgreSQL support does not enable authenticated shared use. The main role still runs migrations, and both future server database secrets exist in one process. |
| Retained data | Path confinement, bounded reads, SHA-256 evidence checks, and owner-only backup file modes where supported protect application workflows. | Backups and DockPacks are not encrypted. Operators still control host access, export custody, secret rotation, and disaster-recovery policy. |

For operators, the safe rule is simple: use the default loopback Compose
deployment, keep assessment scope authorized and narrow, and treat exported
evidence as sensitive. A green CI run is supporting evidence, not proof that a
deployment is secure.

## Safety controls

### Scope enforcement

- DockGuard is evaluated on the server for every discovery request, and again immediately before the adapter is invoked. A validation request is also re-evaluated at approval time, immediately before its fixed recheck. Frontend checks are convenience only.
- Exclusions always override inclusions, and a Dockyard with no scope denies everything.
- Denials are specific and explained: `denied_out_of_scope`, `denied_excluded`, `invalid_target`, `unresolved`.
- Denied requests are persisted as discovery runs so refused attempts remain auditable.
- A scope entry may not cover more than 256 addresses (IPv4 /24, IPv6 /120), and a default route such as `0.0.0.0/0` is rejected. There is no internet-wide scanning mode.

### Target handling

- Targets are normalized to a single canonical form before comparison or execution. Integer, packed, zero-padded, and hexadecimal IP forms are rejected as ambiguous, including a name built only from numeric components such as `0x7f000001`, which a C resolver would read as `127.0.0.1`.
- A canonical target may contain only `[A-Za-z0-9._:/-]` and can never begin with `-`.
- URLs are reduced to an origin; embedded credentials are rejected and paths, queries, and fragments are dropped.
- Hostnames match exactly. There is no wildcard or subdomain expansion, and a hostname is never authorized because it resolves into an authorized network.
- Resolution is opt-in, records the resolved addresses as evidence, and refuses when a resolved address is explicitly excluded. Adapters contact the recorded address rather than the name.
- IPv4-mapped IPv6 DNS answers are rejected before execution so alternate address representations cannot bypass IPv4 exclusions.
- Metadata and link-local destinations are non-overridable policy denials. This includes `169.254.0.0/16`, `100.100.100.200`, `fe80::/10`, `fd00:ec2::254`, and known metadata-service hostnames. A name that resolves to one of these addresses is denied before contact.

### Tool execution

- Argument vectors are generated internally from a fixed table of approved options. No operator-supplied flag reaches a tool, and adapters re-check every variable value before building the vector.
- Processes are started with `shell=False`; no command string is ever concatenated.
- Every run has a timeout, stderr is captured and truncated, and a non-zero exit fails the run rather than producing partial results.
- Only non-invasive profiles exist. Nmap runs without NSE scripts, brute force, credential guessing, exploit scripts, OS detection, UDP scanning, fragmentation, decoys, spoofing, source-port manipulation, or `-A`.
- The HTTP probe issues one request per origin, follows no redirects, reads no response body, and does not crawl, fuzz, submit forms, or test for vulnerabilities.
- One absolute HTTP deadline spans connection, TLS, every underlying response read, and HEAD-to-GET fallback; a continuously trickling peer cannot reset the total budget.
- HTTPS probes require TLS 1.2 or newer for both verified and certificate-observation handshakes. RedDock does not weaken its client policy to enumerate obsolete protocol support.
- Each Dockyard retains at most 500 discovery requests, including denied attempts. Admission is serialized inside the process so concurrent requests cannot step past the cap.

### Local HTTP changes

- On first initialization, RedDock creates a 256-bit URL-safe operator token in the data volume with owner-only permissions and prints it to the service log. It stores only a token digest in process memory.
- The browser exchanges the token for an HttpOnly, host-only, `SameSite=Strict` session cookie. Because the supported local UI uses HTTP, the cookie is not marked `Secure`; host loopback and the Compose ingress remain required boundaries.
- Every unsafe local request requires exactly one operator credential. A browser Origin must be exactly `http://localhost:8080` or `http://127.0.0.1:8080`. Command-line requests may omit Origin but still need the token. CORS remains closed and mutations remain JSON-only.
- Mutation admission is limited to 120 requests per minute per process. Token unlock attempts are limited to 10 per minute per process. These availability controls are not a database-wide or multi-process rate limit.
- The token does not protect safe reads, identify a person, or make the service safe to publish. If its file disappears after initialization, unsafe requests return a generic failure until the original file is restored and RedDock restarts.

### Validation

- Phase 3 validation is not a target-entry or tool-selection feature. It can only recheck an eligible, open `http.security_headers` finding at the HTTP origin already recorded on that finding.
- Requesting validation stores intent and makes no network contact. A separate local operator approval note is required before RedDock makes the recheck, and that approval does not itself prove authorization to assess a system. Like every other state-changing route, the request is JSON, so a page the operator merely has open cannot submit it as a plain cross-origin form and spend this Dockyard's fixed validation budget.
- At approval time RedDock evaluates DockGuard again. If scope was removed or now denies the origin, the denied attempt remains in the audit trail and no connection is attempted.
- Approval uses an atomic pending-state claim; a concurrent loser cannot probe or replace approval metadata. Startup marks interrupted running validations failed while preserving pending approvals.
- The validator reuses the fixed HTTP probe: a bodyless `HEAD`, with one standards-required `GET` fallback for `405` or `501`; it accepts no URL, payload, credential, cookie, command, flag, redirect, response body, crawler, or browser automation.
- A result is `confirmed`, `not_reproduced`, or `indeterminate`, with confidence stated separately. It never changes the original finding's severity, confidence, or operator status.

### Lab mode

- Lab capability requires two independent gates: the deployment owner must enable a process-level switch that the API cannot change, and an operator must create a 5–120 minute authorization for one capability and Dockyard using the exact acknowledgement shown in the Lab console.
- The current lab profile accepts exactly one effective host only, including after hostname resolution, and uses a fixed TCP connect scan of Nmap's top 1,000 ports with bounded version detection. It still has no scripts, UDP, OS detection, evasion, credential testing, brute force, payload, exploit, or operator-supplied flag.
- RedDock rechecks the deployment switch, active authorization, single-host constraint, and DockGuard immediately before execution. A network target is refused even when it is in ordinary DockGuard scope.
- Authorization, request, execute, deny, and revoke decisions are append-only audit events. Expiration, supersession, revocation, and denial do not erase history.

### Detection

- Detection reads only what RedDock already recorded. A detector receives an immutable snapshot of one Dockyard and is given no database session, socket, subprocess, target, or operator-supplied option. `tests/test_detection_contract.py` rejects the defined imports and capabilities that could cross this boundary.
- A detection request carries no parameters at all. There is no target field, no detector selection, and no options, so no operator string reaches a detector.
- Built-in detectors are registered explicitly in code. Optional Phase 7 extensions are bounded, deployment-owned JSON rules loaded outside the detection package; they cannot name a module, command, URL, template, target, or tool, and there is no dynamic import, `eval`, or `exec` anywhere in the detection package.
- The complete plugin set is schema-checked and frozen at startup. Symlinks, path escapes, duplicate JSON keys or IDs, unknown fields, excessive sizes, and IDs outside the `plugin.` namespace fail startup closed. The API and detection evidence expose each manifest's SHA-256; a manifest still requires human review because data can author a misleading claim without executing code.
- Every finding must cite at least one observation from the snapshot it was drawn from. A finding that cites none, names another Dockyard's data, or carries an unknown severity, confidence, or category is refused, and the detector that produced it is failed as a whole rather than partially trusted.
- Detection snapshots fail before detector execution if any asset, service, or observation bound would omit stored state. A detector that fails or exceeds its fixed output bound resolves nothing. Not running is never treated as evidence that an issue went away.
- Findings are never deleted. An issue that a later run no longer reproduces is marked resolved; an operator may suppress, accept, or reopen one but may not declare it resolved.
- Ratings are stated conservatively and separately. Severity and confidence are distinct fields, missing hardening headers are reported as `low`, and RedDock produces no risk score, CVSS vector, or aggregate rating because it does not compute one.
- RedDock downloads no CVE data. Enrichment is off unless an operator supplies a local catalogue, matches only an exact product and version, and never changes a finding's severity, confidence, or status.

### Correlation

- Correlation reads one Dockyard's stored state and accepts an empty request body. It has no target, network or process capability, selector, weighting, dynamic rule, or operator-supplied option.
- Asset relationships require exact equality between a web asset's recorded address and a host asset's normalized identity, plus the observation and retained discovery hash that support it.
- Finding correlations require evidence hashes for both findings. A candidate missing required evidence is omitted rather than guessed.
- Fixed CWE mappings classify existing detector rules only; they never create a finding or alter severity, confidence, status, or validation outcome.
- RedPath is not attack-path analysis. It does not claim reachability, exploitability, causation, likelihood, or aggregate risk, and correlation output is capped at 5,000 edges per snapshot.

### Intelligence

- Intelligence is disabled unless an operator supplies a provider base URL and model through deployment configuration. Provider credentials may come from a mounted secret file or the backward-compatible process variable; they are masked in settings and are never accepted by the API, stored, returned to the browser, retained as evidence, or logged.
- Creating a run makes no provider request. It freezes and hashes the exact versioned packet from active, evidence-linked findings in the latest completed correlation; the browser displays that JSON and the destination before a separate approval note can send it.
- Approval is bound to the provider, model, destination, local/external classification, and prompt version recorded at creation. A configuration or prompt-version change blocks the send. Only loopback addresses and the fixed internal `ollama` service are classified as local. Host gateways such as `host.docker.internal` cross the container boundary, are classified as external, and require HTTPS. Redirects are refused, and requests have total-time and response-size bounds.
- The API accepts no arbitrary prompt, destination, target, command, tool, credential, action, or finding selection. Stored strings are explicitly treated as untrusted data in the fixed prompt.
- Provider output must match a strict schema and may cite only finding IDs and evidence hashes in the reviewed packet. Unknown or duplicate references fail the run as a whole.
- Output is retained, hashed advice only. It cannot alter a finding, trigger validation or discovery, invoke a tool, modify scope, or apply remediation. An operator remains responsible for reviewing both the advice and a provider's data-handling terms.

### Reporting and DockPack exports

- Reporting reads one Dockyard's stored state and accepts an empty request body. It has no target, provider, prompt, output path, filename, selector, command, network, or process capability.
- A snapshot is refused while source discovery, detection, validation, or correlation work is active. Pending intelligence packets may be included as retained input, while only completed, hash-verified advice is included as output.
- The runner enumerates database-referenced artifacts only. Each portable path is fixed by source type and integer run ID, resolved beneath RedLedger, and rejected if it is absolute, escaping, duplicated, missing, not a regular file, or no longer matches its retained SHA-256.
- Assets, services, findings, finding-evidence links, validation rows, lab authorizations, lab audit events, evidence files, retained report runs, and total DockPack bytes have independent fixed bounds applied before unbounded materialization. A limit violation fails closed rather than silently omitting part of the snapshot.
- Members use sorted names, fixed timestamps, fixed modes, canonical JSON, and uncompressed ZIP storage. The same retained state therefore produces byte-identical reports and DockPacks. A download re-hashes its retained artifact before serving it.
- Stored text remains untrusted and is placed in delimiter-safe literal code spans before Markdown rendering, including in portable exports. Reports are evidence summaries, not HTML, executable content, vulnerability verdicts, or aggregate risk scores.
- A DockPack can contain targets, service banners, finding details, validation and lab authorization notes, lab policy decisions, model advice, and other assessment evidence. It is not encrypted. Treat it as engagement-confidential: review it before sharing, store or transmit it through an approved encrypted channel, and verify its manifest before extraction.

### Evidence and data

- Evidence paths are built from integer identifiers and a validated artifact name, and each resolved destination is confirmed to be inside its run directory before a write.
- Raw artifacts are capped at 2 MiB and marked when truncated.
- Only a small allowlist of response headers is retained; cookies and other session material are never written to evidence.
- Every stored artifact is SHA-256 hashed and recorded, for detection, correlation, intelligence, and reporting runs as well as discovery runs. A completed validation also retains raw recheck output, a normalized result, approval/policy metadata, and a hash manifest.
- Discovery commits inventory, observations, evidence references, and completion together after successful file writes. A write failure rolls back partial inventory, preventing detection from consuming an observation before its evidence reference exists.
- Every finding is traceable to the observations it was drawn from, the discovery run that recorded them, and the hash of the retained artifact they came from.

### Runtime

- The Compose application runs as the unprivileged `reddock` user, drops every Linux capability, uses a read-only root filesystem, and has fixed process and memory limits. Nmap uses TCP connect scanning and receives no raw-socket capability. The ingress proxy, PostgreSQL, Ollama, and the model provisioner use explicit unprivileged users, drop every capability, use read-only root filesystems with narrow writable mounts, set `no-new-privileges`, and have fixed process and memory limits.
- The rootless Ollama wrapper uses the new `reddock-ollama-v2` model volume. Its first start downloads the selected model again. An older root-owned model cache is not mounted or deleted automatically; removing it is an explicit operator decision after its volume has been identified.
- The application listens on `/run/reddock-api/reddock.sock`, not a container TCP port. Only the unprivileged ingress proxy receives that socket volume and publishes `127.0.0.1:8080` on the host. Ollama and PostgreSQL use separate internal backend networks and receive no socket volume, so they cannot initiate API requests. The application retains outbound networks because authorized discovery, PostgreSQL, and optional model access require them.
- This isolation belongs to the supported Compose package. Publishing the raw image, changing its command, sharing the socket volume, or attaching extra services to the ingress boundary requires a separate security review.
- SQLite data, evidence, and the local operator token are held in a named volume by default. The optional PostgreSQL profile uses a separate named volume and internal network with no host port; its password is mounted as a Compose secret. None of this state is baked into the image.
- The runtime image includes the exact Debian Nmap corresponding-source archives used for its installed Nmap package under `/usr/share/reddock-source/nmap`, together with package metadata and SHA-256 checksums. See [Nmap corresponding source](docs/NMAP_SOURCE_OFFER.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
- Inputs use Pydantic validation; unknown or malformed requests are rejected.
- CORS is intentionally not opened because UI and API share one origin.
- Requests are accepted only for the documented `localhost` and `127.0.0.1` Host values, preventing an arbitrary Host from using browser DNS rebinding to reach the loopback API.
- Every response, including a rejected Host, carries centralized anti-framing, no-sniff, referrer, browser-capability, opener, and resource-policy headers. Every `/api/` response is `Cache-Control: no-store` so sensitive JSON and evidence downloads are not retained by browser caches.
- The content security policy is stated positively: `default-src 'self'` with same-origin script, style, image, font, and connection sources, and no `unsafe-inline` of any kind. The build emits no inline script or style, so an injected reference has nowhere to resolve to. The interactive API documentation keeps the narrower framing and object policy because its bundles load from a CDN.
- Liveness discloses only that the process can answer. The separate readiness route performs one database query and returns a generic 503 without connection details; container orchestration uses readiness rather than treating a database-blind process check as healthy.
- The only accepted deployment mode is `local`. `REDDOCK_DEPLOYMENT_MODE=server` and unknown values fail startup until authenticated server mode is implemented; enabling PostgreSQL does not widen the trust boundary.
- Future server-browser primitives already require one exact HTTPS origin and a host-bound `Secure`, `HttpOnly`, `SameSite=Lax` session cookie. Their request verifier rejects ambiguous duplicate credentials and requires both exact Origin and session-bound CSRF proof for unsafe methods. They are deliberately disconnected from routes, and setting `REDDOCK_PUBLIC_ORIGIN` in local mode fails startup rather than implying authentication that is not present.
- Dormant OIDC primitives accept provider endpoints only from deployment-owned
  HTTPS origins, reject redirects and oversized responses, use authorization
  code with PKCE, bind one-use state to a host-only transaction cookie, and
  validate asymmetric ID-token signatures plus issuer, audience, time, and
  nonce claims. One provider and its thread-safe metadata and signing-key cache
  belong to one future application lifespan, so concurrent request threads
  cannot stampede initial loads or key refreshes. They retain no provider token
  or profile claim and resolve only a pre-provisioned issuer/subject identity.
  No authentication route is registered, and server mode still fails startup.
- A dormant authentication coordinator composes these controls in fail-closed
  order. A future HTTP adapter must supply the canonical client address from
  trusted ingress. Login limiting precedes provider discovery and state
  creation. Callback limiting precedes one-use state consumption, and the state
  is burned before provider token exchange, preventing callback replay from
  repeating that exchange. The matching user and membership rows are locked
  through session issuance. Only a pre-provisioned active identity can receive
  an audited hash-only session. Post-burn provider exchange and ID-token
  validation failures make a best-effort attempt to record bounded denial
  events, and expected failures reveal no provider, database, identity, or
  session detail. No auth route or UI calls this code, and server mode
  remains disabled. The configured dormant lifespan builds an owned primary
  database runtime from the same validated server configuration and gives its
  engine to the coordinator. Startup verifies the effective login, database,
  search path, and timeout policy. Connection, checkout, statement, lock,
  idle-transaction, and transaction waits are bounded, and shutdown disposes
  the owned engine. This does not narrow the main role, which still runs
  migrations and accesses application data. It does not enable a route, UI, or
  server mode.
- One immutable lifespan binding selects the database session factory for each
  request. Local requests use global `SessionLocal` only through an explicit
  local binding. Configured requests use `PrimaryDatabaseRuntime.session`; a
  missing or malformed binding makes the database dependency produce a generic
  `503` rather than an ambient fallback, and every yielded session is closed.
  Configured protected routes receive no local-owner context and return `401`
  until browser identity resolution is connected. Discovery carries the exact
  request factory into its worker instead of importing `SessionLocal`. Executor
  drain or cancellation before primary-runtime shutdown remains unfinished.
  None of this enables an auth route, UI, or server mode.
- Future authentication throttling uses atomic database updates shared across
  workers. A global bucket is checked before any client bucket, counters stop at
  their fixed limit, client and identity values are protected by a
  deployment-keyed HMAC, IPv6 clients share a `/64` bucket, and expired-state
  cleanup is bounded. Each decision owns its database transaction. PostgreSQL
  concurrency tests verify global and same-client admission, exact reset, and
  cleanup-versus-refresh behavior. These dormant primitives do not expose a
  login route or make server mode available. A future server process loads one
  canonical mounted key containing exactly 64 lowercase hexadecimal characters
  and keeps it paired with a process-owned limiter capability. The capability
  owns two isolated, prewarmed PostgreSQL connections with bounded checkout,
  connect, statement, and lock waits; uncertainty or database failure denies
  the request. The main pool is capped at 15 connections, so each process needs
  17 connections plus operational headroom. PostgreSQL tests fill each pool in
  turn and verify that the other remains usable. Local mode and the current
  Compose profiles load no limiter key. Every worker must use the same key, and
  rotation requires a full stop rather than a rolling restart. The server
  contract requires a distinct `REDDOCK_RATE_LIMIT_DATABASE_USER` and mounted
  `REDDOCK_RATE_LIMIT_DATABASE_PASSWORD_FILE`; reuse of either application
  credential is rejected. Startup accepts only a direct `LOGIN NOINHERIT` role
  with a connection limit exactly twice `REDDOCK_SERVER_WORKERS`, no
  memberships or elevated flags, database `CONNECT`, `public` schema `USAGE`,
  bucket `SELECT`/`INSERT`/`UPDATE`/`DELETE`, and sequence `USAGE`. It rejects
  ownership, grant options, column-level grants, object creation, temporary
  access, other database access, large-object access, database parameter
  grants, role-level settings, user-defined routine execution, standalone type
  ownership, bucket policies or triggers, foreign keys, rewrite rules,
  inheritance, and unrelated object access. The
  connection fixes its search path to `pg_catalog,public`. Operators provision
  the role outside
  migrations and rotate its password with a coordinated stop and restart. This
  is a startup-time check, not continuous database policy monitoring. The main
  role still runs migrations, both secrets exist in one process, and
  database-wide capacity and shared HMAC-key enforcement remain separate gates.
- Dormant browser sessions use stable families of hash-only token generations.
  A session becomes idle after 30 minutes, activity writes are limited to once
  every five minutes, and the bearer token and CSRF proof rotate together after
  one hour without extending the original eight-hour expiry. Logout and
  membership revocation cover the whole family, including a retained
  predecessor that races with rotation. Request-facing lifecycle entry points
  own short isolated transactions, lower-level revocation can participate in a
  wider identity-change transaction, and inactive rows are cleaned in bounded
  batches. PostgreSQL tests cover concurrent issuance, touch, rotation, logout,
  membership revocation, and cleanup. No session route is registered, and
  server mode remains disabled.
- Concurrent discovery runs and run duration are bounded; a run interrupted by a restart is marked failed rather than left active. Validation and intelligence requests are bounded per Dockyard and run synchronously only after approval. Reporting runs synchronously under a single-process lock, captures database state under an explicit consistent transaction, and removes a partial reporting directory when startup marks its interrupted run failed.
- Detection is bounded too: the snapshot it reads, the findings a detector may return, and the evidence references a finding may carry all have limits, and an operator-supplied CVE catalogue is size- and entry-capped.
- Secrets must not be committed. GitHub secret scanning and push protection check the public repository for likely credentials.
- GitHub push protection and secret scanning are enabled, while a pinned CodeQL `security-extended` matrix analyzes workflow, frontend, and backend languages on changes and weekly. CodeQL receives read-only contents plus only the `security-events: write` permission required to publish results. PyPA `pip-audit` and npm audit also fail CI for known Python-runtime or high-severity frontend dependency vulnerabilities. Dependabot checks GitHub Actions, Docker, npm, and pip weekly; minor and patch updates are grouped, major updates stay isolated, and no update is auto-merged.

## What RedDock does not do

Supported RedDock workflows contain no exploitation, credential testing, brute force, injection testing, payload execution, evasion, persistence, lateral movement, post-exploitation, attack-path analysis, autonomous AI action, automated remediation, or automated external report delivery. They do not execute operator-supplied scripts or shell commands.

It performs no exploitation or broad active vulnerability testing. Detection, correlation, and reporting reason over data an earlier, non-invasive discovery already recorded; they send nothing. RedPath visualizes evidence-linked relationships, not attack reachability. Phase 3 can only recheck the limited HTTP transport/header conditions it owns through an approval-gated, fixed, bodyless HTTP-origin probe. Phase 5 can send a separately approved evidence packet to a configured model for advice, but provides no action channel. Phase 6 can export the retained record for operator-controlled handling but cannot upload, email, publish, or transmit it. A finding therefore remains a conclusion from evidence, not a claim that RedDock exploited a system: a version banner is a disclosure rather than a vulnerability, and a CVE association or CWE classification is never a statement that a service is exploitable.

## Reporting a vulnerability

Do not open a public issue for a suspected security flaw. Use [GitHub Private Vulnerability Reporting](https://github.com/chriswayneh/RedDock/security/advisories/new) for a concise report with reproduction steps, affected versions, and impact. Private reporting is enabled for this repository; do not post sensitive details in an issue, discussion, or pull request.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.8.x | Yes, current published release |
| 0.7.x | No, superseded by 0.8.0 |
| 0.6.x | No, superseded by 0.7.0 |
| 0.5.x | No, superseded by 0.6.0 |
| 0.4.x | No, superseded by 0.5.0 |
| 0.3.x | No, superseded by 0.4.0 |
| 0.2.x | No, superseded by 0.3.0 |
| 0.1.x | No, superseded by 0.2.0 |

Security fixes are evaluated for the latest published release. RedDock is a local, single-operator application in this phase; do not expose it to untrusted networks.

The source-backed [threat model](docs/THREAT_MODEL.md) documents the current
trust boundaries and the separate fail-closed identity and tenancy design
required before a supported networked deployment exists.
