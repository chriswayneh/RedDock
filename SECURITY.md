# Security

## Responsible use

RedDock is for systems owned by the operator or assessed with explicit authorization. It is appropriate for authorized engagements, labs, cyber ranges, CTFs, and training environments. Do not use it to access systems outside approved scope.

From Phase 1 onward RedDock can contact a network target. Scoping a target in RedDock is a statement that you are authorized to assess it. The product enforces the scope you declare; it cannot verify that you were entitled to declare it.

## Product safety model

Every action passes DockGuard before a tool runs, and DockGuard fails closed: anything it cannot positively place inside the Dockyard's authorized scope is denied. AI will never receive unrestricted shell access or the ability to expand target scope.

## Phase 1 safety controls

**Scope enforcement**

- DockGuard is evaluated on the server for every discovery request, and again immediately before the adapter is invoked. Frontend checks are convenience only.
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

**Evidence and data**

- Evidence paths are built from integer identifiers and a validated artifact name, and each resolved destination is confirmed to be inside its run directory before a write.
- Raw artifacts are capped at 2 MiB and marked when truncated.
- Only a small allowlist of response headers is retained; cookies and other session material are never written to evidence.
- Every stored artifact is SHA-256 hashed and recorded.

**Runtime**

- The production container runs as an unprivileged `reddock` user, with no `privileged: true`, no added capabilities, and no `network_mode: host`. Nmap therefore runs unprivileged and uses TCP connect scanning; RedDock does not request raw-socket capabilities to enable features it does not need.
- SQLite data and evidence are held in a named volume, not baked into the image.
- Inputs use Pydantic validation; unknown or malformed requests are rejected.
- CORS is intentionally not opened because UI and API share one origin.
- Concurrent runs and run duration are bounded; a run interrupted by a restart is marked failed rather than left active.
- No secrets are checked into this repository.

## What RedDock does not do

Phase 1 contains no vulnerability scanning, CVE matching, findings, severity scoring, exploitation, credential testing, injection testing, post-exploitation, attack-path analysis, AI reasoning, automated remediation, or report generation. Observations record what was seen and assign no verdict.

## Reporting a vulnerability

Do not open a public issue for a suspected security flaw. When GitHub Private Vulnerability Reporting is enabled, use it for a concise report with reproduction steps, affected versions, and impact. Until then, avoid posting sensitive details publicly and ask the maintainers for a private reporting channel.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes — current published release |

Security fixes are evaluated for the latest published release. RedDock is a local, single-operator application in this phase; do not expose it to untrusted networks.
