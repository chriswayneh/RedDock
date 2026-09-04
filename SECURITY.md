# Security

## Responsible use

RedDock is for systems owned by the operator or assessed with explicit authorization. It is appropriate for authorized engagements, labs, cyber ranges, CTFs, and training environments. Do not use it to access systems outside approved scope.

RedDock can contact a network target. Scoping a target in RedDock is a statement that you are authorized to assess it. The product enforces the scope you declare; it cannot verify that you were entitled to declare it.

## Product safety model

Every action passes DockGuard before a tool runs, and DockGuard fails closed: anything it cannot positively place inside the Dockyard's authorized scope is denied. AI will never receive unrestricted shell access or the ability to expand target scope.

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

**Detection**

- Detection reads only what RedDock already recorded. A detector receives an immutable snapshot of one Dockyard and is given no database session, no socket, no subprocess, no target, and no operator-supplied option, so there is nothing for it to reach, execute, or widen. `tests/test_detection_contract.py` parses the detection package and fails the build if a detector imports anything that could.
- A detection request carries no parameters at all. There is no target field, no detector selection, and no options, so no operator string reaches a detector.
- Detectors are registered explicitly in code. Nothing is loaded from a path, a plugin directory, or configuration, and there is no dynamic import, `eval`, or `exec` anywhere in the detection package.
- Every finding must cite at least one observation from the snapshot it was drawn from. A finding that cites none, names another Dockyard's data, or carries an unknown severity, confidence, or category is refused, and the detector that produced it is failed as a whole rather than partially trusted.
- A detector that fails resolves nothing. Not running is never treated as evidence that an issue went away.
- Findings are never deleted. An issue that a later run no longer reproduces is marked resolved; an operator may suppress, accept, or reopen one but may not declare it resolved.
- Ratings are stated conservatively and separately. Severity and confidence are distinct fields, missing hardening headers are reported as `low`, and RedDock produces no risk score, CVSS vector, or aggregate rating because it does not compute one.
- RedDock downloads no CVE data. Enrichment is off unless an operator supplies a local catalogue, matches only an exact product and version, and never changes a finding's severity, confidence, or status.

**Evidence and data**

- Evidence paths are built from integer identifiers and a validated artifact name, and each resolved destination is confirmed to be inside its run directory before a write.
- Raw artifacts are capped at 2 MiB and marked when truncated.
- Only a small allowlist of response headers is retained; cookies and other session material are never written to evidence.
- Every stored artifact is SHA-256 hashed and recorded, for detection runs as well as discovery runs. A completed validation also retains raw recheck output, a normalized result, approval/policy metadata, and a hash manifest.
- Every finding is traceable to the observations it was drawn from, the discovery run that recorded them, and the hash of the retained artifact they came from.

**Runtime**

- The production container runs as an unprivileged `reddock` user, with no `privileged: true`, no added capabilities, and no `network_mode: host`. Nmap therefore runs unprivileged and uses TCP connect scanning; RedDock does not request raw-socket capabilities to enable features it does not need.
- SQLite data and evidence are held in a named volume, not baked into the image.
- Inputs use Pydantic validation; unknown or malformed requests are rejected.
- CORS is intentionally not opened because UI and API share one origin.
- Concurrent discovery runs and run duration are bounded; a run interrupted by a restart is marked failed rather than left active. Validation requests are bounded per Dockyard and run synchronously only after approval.
- Detection is bounded too: the snapshot it reads, the findings a detector may return, and the evidence references a finding may carry all have limits, and an operator-supplied CVE catalogue is size- and entry-capped.
- No secrets are checked into this repository.

## What RedDock does not do

RedDock contains no exploitation, credential testing, brute force, injection testing, payload execution, evasion, persistence, lateral movement, post-exploitation, attack-path analysis, AI reasoning, automated remediation, or report generation. No operator-supplied script or shell command is executed anywhere in the product.

It performs no exploitation or broad active vulnerability testing. Detection reasons over data an earlier, non-invasive discovery already recorded; it sends nothing. Phase 3 can only recheck the limited HTTP transport/header conditions it owns through an approval-gated, fixed, bodyless HTTP-origin probe. A finding therefore remains a conclusion from evidence, not a claim that RedDock exploited a system: a version banner is a disclosure rather than a vulnerability, and a CVE association from a local catalogue is never a statement that a service is exploitable.

## Reporting a vulnerability

Do not open a public issue for a suspected security flaw. When GitHub Private Vulnerability Reporting is enabled, use it for a concise report with reproduction steps, affected versions, and impact. Until then, avoid posting sensitive details publicly and ask the maintainers for a private reporting channel.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.4.x | Yes — current published release |
| 0.3.x | No — superseded by 0.4.0 |
| 0.2.x | No — superseded by 0.3.0 |
| 0.1.x | No — superseded by 0.2.0 |

Security fixes are evaluated for the latest published release. RedDock is a local, single-operator application in this phase; do not expose it to untrusted networks.
