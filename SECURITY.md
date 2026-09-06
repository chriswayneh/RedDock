# Security

## Responsible use

RedDock is for systems owned by the operator or assessed with explicit authorization. It is appropriate for authorized engagements, labs, cyber ranges, CTFs, and training environments. Do not use it to access systems outside approved scope.

RedDock can contact a network target. Scoping a target in RedDock is a statement that you are authorized to assess it. The product enforces the scope you declare; it cannot verify that you were entitled to declare it.

## Product safety model

Every target action passes DockGuard before a tool runs, and DockGuard fails closed: anything it cannot positively place inside the Dockyard's authorized scope is denied. Optional intelligence receives no tool access at all and cannot expand target scope or change RedDock state. Reporting has no active capability and packages only retained artifacts whose hashes it has re-verified.

## Safety controls

**Scope enforcement**

- DockGuard is evaluated on the server for every discovery request, and again immediately before the adapter is invoked. A validation request is also re-evaluated at approval time, immediately before its fixed recheck. Frontend checks are convenience only.
- Exclusions always override inclusions, and a Dockyard with no scope denies everything.
- Denials are specific and explained: `denied_out_of_scope`, `denied_excluded`, `invalid_target`, `unresolved`.
- Denied requests are persisted as discovery runs so refused attempts remain auditable.
- A scope entry may not cover more than 256 addresses (IPv4 /24, IPv6 /120), and a default route such as `0.0.0.0/0` is rejected. There is no internet-wide scanning mode.

**Target handling**

- Targets are normalized to a single canonical form before comparison or execution. Integer, packed, and zero-padded IP forms are rejected as ambiguous.
- A canonical target may contain only `[A-Za-z0-9._:/-]` and can never begin with `-`.
- URLs are reduced to an origin; embedded credentials are rejected and paths, queries, and fragments are dropped.
- Hostnames match exactly. There is no wildcard or subdomain expansion, and a hostname is never authorized because it resolves into an authorized network.
- Resolution is opt-in, records the resolved addresses as evidence, and refuses when a resolved address is explicitly excluded. Adapters contact the recorded address rather than the name.

**Tool execution**

- Argument vectors are generated internally from a fixed table of approved options. No operator-supplied flag reaches a tool, and adapters re-check every variable value before building the vector.
- Processes are started with `shell=False`; no command string is ever concatenated.
- Every run has a timeout, stderr is captured and truncated, and a non-zero exit fails the run rather than producing partial results.
- Only non-invasive profiles exist. Nmap runs without NSE scripts, brute force, credential guessing, exploit scripts, OS detection, UDP scanning, fragmentation, decoys, spoofing, source-port manipulation, or `-A`.
- The HTTP probe issues one request per origin, follows no redirects, reads no response body, and does not crawl, fuzz, submit forms, or test for vulnerabilities.

**Validation**

- Phase 3 validation is not a target-entry or tool-selection feature. It can only recheck an eligible, open `http.security_headers` finding at the HTTP origin already recorded on that finding.
- Requesting validation stores intent and makes no network contact. A separate local operator approval note is required before RedDock makes the recheck, and that approval does not itself prove authorization to assess a system.
- At approval time RedDock evaluates DockGuard again. If scope was removed or now denies the origin, the denied attempt remains in the audit trail and no connection is attempted.
- The validator reuses the fixed HTTP probe: a bodyless `HEAD`, with one standards-required `GET` fallback for `405` or `501`; it accepts no URL, payload, credential, cookie, command, flag, redirect, response body, crawler, or browser automation.
- A result is `confirmed`, `not_reproduced`, or `indeterminate`, with confidence stated separately. It never changes the original finding's severity, confidence, or operator status.

**Lab mode**

- Lab capability requires two independent gates: the deployment owner must enable a process-level switch that the API cannot change, and an operator must create a 5–120 minute authorization for one capability and Dockyard using the exact acknowledgement shown in the Lab console.
- The current lab profile accepts exactly one effective host only, including after hostname resolution, and uses a fixed TCP connect scan of Nmap's top 1,000 ports with bounded version detection. It still has no scripts, UDP, OS detection, evasion, credential testing, brute force, payload, exploit, or operator-supplied flag.
- RedDock rechecks the deployment switch, active authorization, single-host constraint, and DockGuard immediately before execution. A network target is refused even when it is in ordinary DockGuard scope.
- Authorization, request, execute, deny, and revoke decisions are append-only audit events. Expiration, supersession, revocation, and denial do not erase history.

**Detection**

- Detection reads only what RedDock already recorded. A detector receives an immutable snapshot of one Dockyard and is given no database session, no socket, no subprocess, no target, and no operator-supplied option, so there is nothing for it to reach, execute, or widen. `tests/test_detection_contract.py` parses the detection package and fails the build if a detector imports anything that could.
- A detection request carries no parameters at all. There is no target field, no detector selection, and no options, so no operator string reaches a detector.
- Built-in detectors are registered explicitly in code. Optional Phase 7 extensions are bounded, deployment-owned JSON rules loaded outside the detection package; they cannot name a module, command, URL, template, target, or tool, and there is no dynamic import, `eval`, or `exec` anywhere in the detection package.
- The complete plugin set is schema-checked and frozen at startup. Symlinks, path escapes, duplicate JSON keys or IDs, unknown fields, excessive sizes, and IDs outside the `plugin.` namespace fail startup closed. The API and detection evidence expose each manifest's SHA-256; a manifest still requires human review because data can author a misleading claim without executing code.
- Every finding must cite at least one observation from the snapshot it was drawn from. A finding that cites none, names another Dockyard's data, or carries an unknown severity, confidence, or category is refused, and the detector that produced it is failed as a whole rather than partially trusted.
- Detection snapshots fail before detector execution if any asset, service, or observation bound would omit stored state. A detector that fails or exceeds its fixed output bound resolves nothing. Not running is never treated as evidence that an issue went away.
- Findings are never deleted. An issue that a later run no longer reproduces is marked resolved; an operator may suppress, accept, or reopen one but may not declare it resolved.
- Ratings are stated conservatively and separately. Severity and confidence are distinct fields, missing hardening headers are reported as `low`, and RedDock produces no risk score, CVSS vector, or aggregate rating because it does not compute one.
- RedDock downloads no CVE data. Enrichment is off unless an operator supplies a local catalogue, matches only an exact product and version, and never changes a finding's severity, confidence, or status.

**Correlation**

- Correlation reads one Dockyard's stored state and accepts an empty request body. It has no target, network or process capability, selector, weighting, dynamic rule, or operator-supplied option.
- Asset relationships require exact equality between a web asset's recorded address and a host asset's normalized identity, plus the observation and retained discovery hash that support it.
- Finding correlations require evidence hashes for both findings. A candidate missing required evidence is omitted rather than guessed.
- Fixed CWE mappings classify existing detector rules only; they never create a finding or alter severity, confidence, status, or validation outcome.
- RedPath is not attack-path analysis. It does not claim reachability, exploitability, causation, likelihood, or aggregate risk, and correlation output is capped at 5,000 edges per snapshot.

**Intelligence**

- Intelligence is disabled unless an operator supplies a provider base URL and model through deployment configuration. Provider credentials may come from a mounted secret file or the backward-compatible process variable; they are masked in settings and are never accepted by the API, stored, returned to the browser, retained as evidence, or logged.
- Creating a run makes no provider request. It freezes and hashes the exact versioned packet from active, evidence-linked findings in the latest completed correlation; the browser displays that JSON and the destination before a separate approval note can send it.
- Approval is bound to the provider, model, destination, local/external classification, and prompt version recorded at creation. A configuration or prompt-version change blocks the send. External endpoints require HTTPS; loopback endpoints may use HTTP only without a credential. Redirects are refused, and requests have total-time and response-size bounds.
- The API accepts no arbitrary prompt, destination, target, command, tool, credential, action, or finding selection. Stored strings are explicitly treated as untrusted data in the fixed prompt.
- Provider output must match a strict schema and may cite only finding IDs and evidence hashes in the reviewed packet. Unknown or duplicate references fail the run as a whole.
- Output is retained, hashed advice only. It cannot alter a finding, trigger validation or discovery, invoke a tool, modify scope, or apply remediation. An operator remains responsible for reviewing both the advice and a provider's data-handling terms.

**Reporting and DockPack exports**

- Reporting reads one Dockyard's stored state and accepts an empty request body. It has no target, provider, prompt, output path, filename, selector, command, network, or process capability.
- A snapshot is refused while source discovery, detection, validation, or correlation work is active. Pending intelligence packets may be included as retained input, while only completed, hash-verified advice is included as output.
- The runner enumerates database-referenced artifacts only. Each portable path is fixed by source type and integer run ID, resolved beneath RedLedger, and rejected if it is absolute, escaping, duplicated, missing, not a regular file, or no longer matches its retained SHA-256.
- Assets, services, findings, finding-evidence links, validation rows, lab authorizations, lab audit events, evidence files, retained report runs, and total DockPack bytes have independent fixed bounds applied before unbounded materialization. A limit violation fails closed rather than silently omitting part of the snapshot.
- Members use sorted names, fixed timestamps, fixed modes, canonical JSON, and uncompressed ZIP storage. The same retained state therefore produces byte-identical reports and DockPacks. A download re-hashes its retained artifact before serving it.
- Stored text remains untrusted and is placed in delimiter-safe literal code spans before Markdown rendering, including in portable exports. Reports are evidence summaries, not HTML, executable content, vulnerability verdicts, or aggregate risk scores.
- A DockPack can contain targets, service banners, finding details, validation and lab authorization notes, lab policy decisions, model advice, and other assessment evidence. Treat it as potentially sensitive engagement data: review it before sharing, store it with access controls, and verify its manifest before extraction.

**Evidence and data**

- Evidence paths are built from integer identifiers and a validated artifact name, and each resolved destination is confirmed to be inside its run directory before a write.
- Raw artifacts are capped at 2 MiB and marked when truncated.
- Only a small allowlist of response headers is retained; cookies and other session material are never written to evidence.
- Every stored artifact is SHA-256 hashed and recorded, for detection, correlation, intelligence, and reporting runs as well as discovery runs. A completed validation also retains raw recheck output, a normalized result, approval/policy metadata, and a hash manifest.
- Every finding is traceable to the observations it was drawn from, the discovery run that recorded them, and the hash of the retained artifact they came from.

**Runtime**

- The production container runs as an unprivileged `reddock` user, with no `privileged: true`, no added capabilities, and no `network_mode: host`. Nmap therefore runs unprivileged and uses TCP connect scanning; RedDock does not request raw-socket capabilities to enable features it does not need.
- SQLite data and evidence are held in a named volume by default. The optional PostgreSQL profile uses a separate named volume and a private service with no host port; its password is mounted as a Compose secret. None of this state is baked into the image.
- Inputs use Pydantic validation; unknown or malformed requests are rejected.
- CORS is intentionally not opened because UI and API share one origin.
- Requests are accepted only for the documented `localhost` and `127.0.0.1` Host values, preventing an arbitrary Host from using browser DNS rebinding to reach the loopback API.
- Every response, including a rejected Host, carries centralized anti-framing, no-sniff, referrer, browser-capability, opener, and resource-policy headers. Every `/api/` response is `Cache-Control: no-store` so sensitive JSON and evidence downloads are not retained by browser caches.
- Liveness discloses only that the process can answer. The separate readiness route performs one database query and returns a generic 503 without connection details; container orchestration uses readiness rather than treating a database-blind process check as healthy.
- The only accepted deployment mode is `local`. `REDDOCK_DEPLOYMENT_MODE=server` and unknown values fail startup until authenticated server mode is implemented; enabling PostgreSQL does not widen the trust boundary.
- Future server-browser primitives already require one exact HTTPS origin and a host-bound `Secure`, `HttpOnly`, `SameSite=Lax` session cookie. Their request verifier rejects ambiguous duplicate credentials and requires both exact Origin and session-bound CSRF proof for unsafe methods. They are deliberately disconnected from routes, and setting `REDDOCK_PUBLIC_ORIGIN` in local mode fails startup rather than implying authentication that is not present.
- Concurrent discovery runs and run duration are bounded; a run interrupted by a restart is marked failed rather than left active. Validation and intelligence requests are bounded per Dockyard and run synchronously only after approval. Reporting runs synchronously under a single-process lock, captures database state under an explicit consistent transaction, and removes a partial reporting directory when startup marks its interrupted run failed.
- Detection is bounded too: the snapshot it reads, the findings a detector may return, and the evidence references a finding may carry all have limits, and an operator-supplied CVE catalogue is size- and entry-capped.
- No secrets are checked into this repository.
- GitHub push protection and secret scanning are enabled, while a pinned CodeQL `security-extended` matrix analyzes workflow, frontend, and backend languages on changes and weekly. CodeQL receives read-only contents plus only the `security-events: write` permission required to publish results.

## What RedDock does not do

RedDock contains no exploitation, credential testing, brute force, injection testing, payload execution, evasion, persistence, lateral movement, post-exploitation, attack-path analysis, autonomous AI action, automated remediation, or automated external report delivery. No operator-supplied script or shell command is executed anywhere in the product.

It performs no exploitation or broad active vulnerability testing. Detection, correlation, and reporting reason over data an earlier, non-invasive discovery already recorded; they send nothing. RedPath visualizes evidence-linked relationships, not attack reachability. Phase 3 can only recheck the limited HTTP transport/header conditions it owns through an approval-gated, fixed, bodyless HTTP-origin probe. Phase 5 can send a separately approved evidence packet to a configured model for advice, but provides no action channel. Phase 6 can export the retained record for operator-controlled handling but cannot upload, email, publish, or transmit it. A finding therefore remains a conclusion from evidence, not a claim that RedDock exploited a system: a version banner is a disclosure rather than a vulnerability, and a CVE association or CWE classification is never a statement that a service is exploitable.

## Reporting a vulnerability

Do not open a public issue for a suspected security flaw. Use [GitHub Private Vulnerability Reporting](https://github.com/chriswayneh/RedDock/security/advisories/new) for a concise report with reproduction steps, affected versions, and impact. Private reporting is enabled for this repository; do not post sensitive details in an issue, discussion, or pull request.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.8.x | Yes — current published release |
| 0.7.x | No — superseded by 0.8.0 |
| 0.6.x | No — superseded by 0.7.0 |
| 0.5.x | No — superseded by 0.6.0 |
| 0.4.x | No — superseded by 0.5.0 |
| 0.3.x | No — superseded by 0.4.0 |
| 0.2.x | No — superseded by 0.3.0 |
| 0.1.x | No — superseded by 0.2.0 |

Security fixes are evaluated for the latest published release. RedDock is a local, single-operator application in this phase; do not expose it to untrusted networks.

The source-backed [threat model](docs/THREAT_MODEL.md) documents the current
trust boundaries and the separate fail-closed identity and tenancy design
required before a supported networked deployment exists.
