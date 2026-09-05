# Architecture

## Shape

```text
Browser → React UI (static files) → FastAPI → DockGuard → discovery adapter
                                        │                        ↓
                                        │            SQLite ← evidence files
                                        ↓               ↓
                                    detector ←── snapshot of stored state
                                        ↓
                                    findings → correlation → RedPath
                                        ↓
                                    validation request → approval → DockGuard → fixed HTTP recheck
                                        ↓
                                    intelligence packet → approval → configured model → advice
                                        ↓
                                    reporting snapshot → reports + manifest + DockPack
```

Discovery goes through DockGuard to a target and records what it saw. Detection, correlation, and reporting go the other way: they read stored state and write findings, relationship snapshots, or portable reports without ever reaching a target. Validation begins with a request that records intent only; a separately noted approval rechecks DockGuard and may send one fixed HTTP-origin probe. Optional intelligence creates an exact stored-data packet first, then a separate approval may send only that packet to the configured model provider. The provider receives no target or tool capability. Reporting re-verifies retained artifacts and packages them locally without contacting a target or model.

The production image builds the React/Vite application and serves it as static content from the same FastAPI process that exposes `/api`. A named Docker volume holds SQLite at `/var/lib/reddock` and retained evidence at `/var/lib/reddock/evidence`. There is deliberately no reverse proxy, separate frontend service, queue, or remote dependency.

## Boundaries

- `backend/app/api.py`: HTTP validation and response mapping.
- `backend/app/targets.py`: target parsing and normalization.
- `backend/app/dockguard.py`: scope evaluation and decisions.
- `backend/app/services.py`: Dockyard and scope operations.
- `backend/app/inventory.py`: asset, service, and observation persistence rules.
- `backend/app/discovery/`: the adapter contract, adapters, registry, and run orchestration.
- `backend/app/detection/`: the detector contract, detectors, registry, fingerprints, CVE enrichment, and run orchestration.
- `backend/app/detector_plugins.py`: bounded JSON manifest loading outside the no-I/O detector boundary.
- `backend/app/findings.py`: finding persistence, deduplication, and lifecycle rules.
- `backend/app/validation/`: approval-gated validation orchestration and the fixed HTTP-origin profile.
- `backend/app/correlation/`: stored-state correlation, fixed CWE mappings, and RedPath assembly.
- `backend/app/intelligence/`: reviewed evidence packets, provider boundary, structured advice, and run orchestration.
- `backend/app/reporting/`: deterministic snapshot assembly, report rendering, evidence verification, and DockPack packaging.
- `backend/app/evidence.py`: the evidence store.
- `backend/app/models.py` and `schemas.py`: persistence mappings and input/output contracts.
- `frontend/src`: presentation and API client only.

## Target normalization

Every operator-supplied target passes through `normalize_target` before anything else sees it. Normalization produces one canonical form per target and rejects anything ambiguous:

- IPv4 and IPv6 addresses in strict textual form only — integer, packed, and zero-padded forms are refused so `3232235777` can never quietly become `192.168.1.1`.
- Networks canonicalized to their network address (`192.168.1.37/24` → `192.168.1.0/24`).
- Hostnames lowercased, stripped of a trailing dot, IDNA-encoded per label, and validated.
- URLs reduced to an origin: scheme, host, and port. Paths, queries, fragments, and embedded credentials are rejected or dropped, because RedDock probes an origin and not a location.

A canonical target may contain only `[A-Za-z0-9._:/-]` and can never begin with `-`. This is what makes argument injection through a target string impossible rather than merely unlikely.

## DockGuard

DockGuard answers one question: may this Dockyard act on this target? It is evaluated on the server, twice — when a run is requested, and again immediately before the adapter is invoked, because scope can change in between.

```text
requested target → normalization → exclusions → inclusions → resolution → decision
```

Decisions are `allowed`, `denied_out_of_scope`, `denied_excluded`, `invalid_target`, or `unresolved`. Each carries the reason, the normalized target, and the scope entry that decided it.

Matching rules, all deterministic:

- An address matches an address entry that equals it, or a network entry that contains it.
- A network request must be a subnet of an authorized network entry. Overlapping exclusions are passed to the adapter as excluded addresses; if they cover the network entirely, the request is denied.
- A hostname matches a hostname entry exactly. **There is no wildcard or subdomain expansion.**
- A URL matches an identical origin entry, or an address/network entry covering its host.
- Address space and names are separate universes: a hostname is never authorized because it resolves into an authorized network, and an address is never authorized because some name points at it.
- Exclusions are checked first and always win.

DockGuard fails closed. A scope entry that no longer normalizes is skipped rather than trusted, an empty scope denies everything, and any state it cannot positively resolve into "inside the authorized scope" is a denial.

### DNS policy

Resolution is opt-in and never authorizes anything. When a run targets a name, DockGuard resolves it, refuses if any resolved address is explicitly excluded, records the addresses as evidence, and hands those addresses to the adapter. The adapter contacts the recorded address, not the name, so the host that was authorized is the host that is contacted.

## Scope limits

| Limit | Value | Why |
| --- | --- | --- |
| Addresses per scope entry | 256 (IPv4 /24, IPv6 /120) | Makes accidental large-network scanning impossible |
| Scope entries per Dockyard | 64 | Keeps evaluation bounded and reviewable |
| Concurrent discovery runs | 2 | Bounds load without a task queue |
| Discovery run duration | 600 s | No run can hang indefinitely |
| Raw evidence per artifact | 2 MiB | Bounds disk use; oversized output is truncated and marked |

A default route such as `0.0.0.0/0` is rejected outright, as are multicast and unspecified addresses.

## Discovery adapter boundary

An adapter is the only component allowed to talk to a target, and it is reached only after DockGuard allows the request. The contract is intentionally small — `supports(target)` and `run(request)` — and every adapter follows the same internal stages:

```text
prepare → execute → parse → normalize → artifacts
```

`prepare` builds the invocation from approved options only, `execute` runs it without a shell and under a timeout, `parse` reads the output, `normalize` produces the value objects below, and the artifacts returned on the result are what the run orchestrator hands to the evidence store. Adapters are registered explicitly in `discovery/registry.py`; nothing is discovered at runtime.

| Adapter | Profiles | Behaviour |
| --- | --- | --- |
| `nmap` | `host_discovery`, `service_discovery`, lab-gated `lab_extended_service_discovery` | `-sn` host discovery, a TCP connect scan of the top 100 ports with light version detection, or a separately authorized single-host lab profile covering the top 1,000 TCP ports with bounded version detection. No NSE scripts, UDP, OS detection, evasion, or `-A`. |
| `http` | `http_probe` | One HEAD (GET only if HEAD is refused) against a scoped origin. No redirects, no body read, no crawling, no path guessing. |

## Domain model

- **Asset** — something observed inside a Dockyard. Identity is deterministic: within one Dockyard an asset is `(asset_type, identity)`, where identity is a normalized IP for a `host` and an origin for a `web` asset. Repeat discovery updates `last_seen` and adds newly learned facts; it never erases what an earlier run established.
- **Service** — a transport endpoint on an asset, unique on `(asset, transport, port)`. `service_name`, `product`, and `version` stay null until an adapter actually identified them. A conventional port number is not evidence: nmap's port-table guess is discarded, so TCP/22 open is recorded as TCP/22 open and nothing more.
- **Observation** — a dated, adapter-attributed statement of what was seen, with a confidence of `observed` (RedDock saw it) or `reported` (the target said so). Observations accumulate as history and are never reconciled.
- **DiscoveryRun** — one auditable request: adapter, profile, requested and normalized target, DockGuard decision and reason, status, counts, and evidence path. Denied requests are stored too, because an audit trail that only records successes is not an audit trail.
- **DetectionRun** — one auditable detection: which detectors ran, what each of them did or failed to do, how much state was read, how many findings were produced, created and resolved, which enrichment source was in effect, and the hashes of the two documents it retained. It has no target and no DockGuard decision, because it contacts nothing.
- **Finding** — a normalized security-relevant conclusion one named detector drew. Identity is a SHA-256 `fingerprint` over the detector, the rule, and the asset and service concerned, unique within a Dockyard, so repeated detection updates one row instead of accumulating duplicates. Severity and confidence are separate fields: how much this would matter, and how sure RedDock is that it is true, are different questions and blending them loses both.
- **FindingEvidence** — one row per observation that supported a finding, carrying the discovery run and the hashed `EvidenceRecord` that observation came from.
- **ValidationRun** — one request to recheck one eligible finding. It records target, validator version, both the request-time and approval-time policy outcome, the approval note, a bounded result, and hashes for its evidence package. Denied requests are complete audit records because no target was contacted.
- **CorrelationRun** — one immutable stored-state snapshot with input/relationship/mapping counts and hashes for its normalized result and metadata. It has no target or policy decision because it contacts nothing.
- **AssetRelationship** — an exact-address link from a web asset to a host asset, citing the observation, discovery run, evidence record, explanation, confidence, and SHA-256 that support it.
- **FindingCorrelation** — a symmetric same-asset or related-asset link whose explanation carries both findings' supporting hashes.
- **FrameworkMapping** — a fixed, versioned detector-rule classification under CWE. It is linked to a finding and its evidence hash but never changes that finding.
- **IntelligenceRun** — one immutable reviewed packet and, after separate approval, one structured advice result. It binds provider identity, prompt version, approval note, timestamps, packet and result hashes, and failure state to the latest completed correlation snapshot.
- **ReportRun** — one immutable, bounded snapshot of completed retained state, including lab authorization and policy history. It records source counts and the SHA-256 values of the technical JSON, technical Markdown, executive Markdown, evidence manifest, and DockPack, plus failure and restart state.
- **EvidenceRecord** — a hashed pointer to one retained discovery artifact.

**Observation ≠ Finding.** An observation says what happened; a finding says what it means. They remain separate rows, separate lifecycles and separate concepts: discovery alone never produces a finding, detection never edits an observation, and a finding that cites no observation is refused rather than stored. What Phase 2 adds is the arrow between them, not a merge.

### Finding lifecycle

```text
                  detector reproduces it
        (new) ──────────────► open ◄──────────── operator reopens
                               │  ▲
   detector no longer          │  │  detector reproduces it again
   reproduces it               ▼  │
                            resolved
                               │
        operator decides ──────┴──────► suppressed / accepted
```

Four states, and only three of them are an operator's to set. `resolved` is RedDock's answer to a question about the data — is this still reproduced? — so the API refuses to let an operator declare it, and nothing here ever deletes a finding: an issue that stopped being reproduced is more useful recorded as resolved than erased. `suppressed` and `accepted` are decisions a person took responsibility for, so a later run leaves them alone even when it sees the issue again.

Resolution is scoped to the detector that just ran successfully. A detector that raised, or that returned output RedDock refused, resolves nothing, because not running is not evidence that an issue went away.

## Detection boundary

A detector is deliberately weaker than a discovery adapter. An adapter may contact a target; a detector may not contact anything. It receives an immutable snapshot of one Dockyard's assets, services and observations and returns value objects — no session, no socket, no subprocess, no target string, no operator-supplied option. `tests/test_detection_contract.py` parses the detection package and fails the build if a detector imports anything that could reach outside the process or touch the database, so the boundary is checked rather than asserted.

```text
snapshot → detect → validate → normalize → findings
```

Everything except `detect` belongs to the runner. It builds the snapshot, validates what came back, computes identity, reconciles against what is known, resolves what is absent and writes evidence. A detector that returns something malformed — an unknown severity, a rule id that is not a rule id, a finding about another Dockyard's asset, a finding citing no observation — is failed as a whole and its results are discarded, and the other detectors still run.

| Detector | Reads | Reports |
| --- | --- | --- |
| `http.security_headers` | `http_response`, `http_header` | Plaintext transport, and response-level protections the response did not carry, for the headers the probe examined |
| `service.rules` | `service_identified` and the service inventory | A fixed table of protocol rules over services RedDock identified, and disclosed product versions |
| `tls.certificates` | `tls_session` | What certificate verification objected to |
| `plugin.*` | One declared observation type | An exact scalar match from a reviewed, content-addressed JSON manifest |

Three things keep this from producing the usual noise. A header is only reported when the probe recorded that it looked for it, so "RedDock did not look" is never rendered as "the server did not send it". Content-level headers are only judged on a response that represents how an endpoint normally answers, so a 301 to HTTPS carrying no Content-Security-Policy is not a finding. And a service rule needs an identification observation, so a port number alone still says nothing: TCP/23 open is TCP/23 open.

Phase 7 extensions preserve the same boundary by being data rather than code.
The loader sits outside `detection/`, validates one deployment-configured
directory before the API starts, and compiles exact comparisons into frozen
value objects. A manifest cannot import a module, execute a command, interpolate
a template, choose a target, or perform I/O. Its full SHA-256 appears in the
detector catalogue, while detection evidence records the content-addressed
detector version. See [ADR 0012](docs/adr/0012-detector-plugins-are-data-not-code.md).

The scope is also narrower than it could look. RedDock does not enumerate supported TLS versions or cipher suites — the HTTP probe negotiates with a default client, so it can only ever record a version a current client accepted — and a rule about obsolete protocol versions would therefore never be able to fire from RedDock's own data. It is left out rather than shipped as decoration.

## Validation boundary

Phase 3 does not make every finding executable. The only profile, `http.origin_recheck`, applies only to an open `http.security_headers` finding for `plaintext-http`, missing HSTS, missing `nosniff`, missing content security policy, or missing frame protection. The target comes from the linked web asset's normalized identity; neither the browser nor an API client supplies a target, URL path, header, payload, credential, cookie, command, tool flag, or parser.

```text
finding → request (no contact) → DockGuard decision → approval note → DockGuard decision → fixed HTTP probe → result + evidence package
```

The approval action must include a short note. It records the operator's decision but is not an authorization bypass: the second DockGuard decision happens immediately before the probe and wins if scope has changed. The runner reuses `HttpProbeAdapter`, so it makes a bodyless `HEAD` request and only falls back to one `GET` for `405` or `501`; it follows no redirects and reads no response body. Outcomes are `confirmed`, `not_reproduced`, or `indeterminate`; result confidence is separate from both the original finding's severity and its detection confidence. See [ADR 0008](docs/adr/0008-validation-is-approval-gated.md).

## CVE enrichment

RedDock fetches no CVE data and has no vulnerability feed. Phase 2 ships the boundary and a local catalogue reader behind it, enabled only when an operator sets `REDDOCK_CVE_CATALOG` to a JSON file. A match requires an exactly equal product and version; version ranges are not interpreted, because a range is an inference and an inference printed beside a CVE identifier reads as a result.

An association never creates a finding, never changes a severity, a confidence or a status, and is attached to the version-disclosure finding that already stood on its own evidence. A catalogue that is missing, oversized or malformed is recorded as a warning on the detection run rather than failing it, and each detection run states which enrichment source was in effect so a finding with no CVE reference can be told apart from one RedDock could not enrich. See [ADR 0007](docs/adr/0007-cve-enrichment-is-an-association.md).

## Correlation boundary

Correlation accepts an empty request body and reads assets, observations,
findings, and evidence hashes already stored for one Dockyard. The package has
no networking, subprocess, dynamic import, target, selector, weight, or plugin
surface. Its only asset rule is exact equality between a web asset's recorded
address and a host asset's normalized identity, supported by that web
observation's retained artifact. Findings correlate when they share one asset
or sit on the two sides of that exact relationship, and only when both have
evidence hashes.

RedPath is a view of this snapshot. Each edge states its basis, confidence, and
supporting SHA-256 value or values. Fixed CWE mappings classify detector rules;
they are not additional evidence. Neither the runner nor the graph claims
reachability, exploitability, causation, likelihood, or risk. See [ADR 0009](docs/adr/0009-correlation-asserts-only-evidence-linked-facts.md).

## Intelligence boundary

Intelligence is disabled by default and keeps packet construction separate from
transmission:

```text
latest correlation + active evidence-linked findings
  → freeze exact versioned packet
  → retain + hash
  → operator review
  → separate approval note
  → provider identity recheck
  → configured OpenAI-compatible endpoint
  → strict schema + reference validation
  → retained, hashed advice
```

There is no arbitrary prompt or finding selector in the API. The packet contains
only stored finding facts and evidence hashes under fixed instructions that mark
all evidence strings as untrusted data. The provider gets no shell, tools,
credentials, target-selection surface, DockGuard access, or state-changing API.
Its output may refer only to IDs and hashes in that packet and cannot update the
source findings. External destinations and every credentialed connection require
HTTPS; redirects are refused and the packet, response, total duration, finding
count, and retained run count are bounded. Approval atomically claims one packet,
and re-verifies its prompt version and retained packet hash before transmission.
See [ADR 0010](docs/adr/0010-intelligence-is-reviewable-advice.md).

## Reporting boundary

Reporting accepts an empty request and has no target, source selector, model,
prompt, network, subprocess, output path, or archive-name surface:

```text
completed Dockyard state + database-referenced evidence
  → refuse active source runs
  → enumerate bounded source artifacts
  → resolve beneath RedLedger + re-verify every SHA-256
  → freeze canonical snapshot
  → render technical + executive reports
  → build complete evidence manifest
  → package deterministic DockPack
  → retain + hash every output
```

Discovery artifacts come from `EvidenceRecord`; later-phase artifacts come from
the hashes on their completed run records. Validation manifests must describe
the exact fixed raw artifact, and only completed intelligence advice joins the
always-retained reviewed packet. No directory is scanned to discover extra
files. Missing, changed, duplicated, unsafe, or oversized input fails the whole
run rather than creating a partial export.

Reporting schema `reddock.reporting/2` adds bounded, Dockyard-isolated lab
authorization and policy-ledger rows to the canonical technical snapshot. They
are ordered by immutable identifiers and therefore remain reproducible; stored
authorization status is reported alongside its timestamps without a clock-based
reinterpretation. The snapshot and DockPack hashes bind this policy history to
the portable report.

The snapshot excludes reporting history, so creating a report does not change
the next report's source state. Source queries and evidence verification run
inside one explicit SQLite transaction, so concurrent mutations wait until the
snapshot is frozen. JSON is canonical, ZIP members are sorted, and
timestamps, modes, and compression are fixed. Unchanged retained state produces
byte-identical output. See [ADR 0011](docs/adr/0011-reporting-is-a-deterministic-snapshot.md)
and the [DockPack format](docs/DOCKPACK.md).

## Evidence flow (RedLedger)

Every completed run writes through the same store:

```text
evidence/<dockyard-id>/<discovery-run-id>/
  metadata.json          adapter, tool version, profile, targets, DockGuard decision,
                         invocation, timestamps, counts, artifact hashes
  raw/                   unmodified tool output
  normalized/result.json the normalized assets and observations

evidence/<dockyard-id>/detection/<detection-run-id>/
  metadata.json          detectors and their outcomes, enrichment source, inputs read,
                         counts, timestamps, artifact hashes
  normalized/result.json the findings produced and the fingerprints resolved

evidence/<dockyard-id>/validation/<validation-run-id>/
  raw/http-recheck.json  fixed HTTP probe's bounded, filtered response record
  normalized/result.json finding, rule, outcome, confidence, and response summary
  metadata.json          request/approval timestamps, approval note, DockGuard decision,
                         target, validator version, and artifact hashes
  raw/manifest.json      package membership and SHA-256 for the other artifacts

evidence/<dockyard-id>/correlation/<correlation-run-id>/
  metadata.json          input and output counts, method, and artifact hash
  normalized/result.json assets, findings, relationships, mappings, explanations,
                         observation identifiers, and supporting evidence hashes

evidence/<dockyard-id>/intelligence/<intelligence-run-id>/
  normalized/result.json exact versioned packet reviewed before approval
  raw/advice.json         schema-validated provider advice
  metadata.json           provider identity, prompt version, approval, timestamps,
                          packet and advice hashes

evidence/<dockyard-id>/reporting/<report-run-id>/
  normalized/result.json canonical technical snapshot used by every report
  technical.md            evidence-oriented technical report
  executive.md            bounded summary without an aggregate risk score
  raw/manifest.json       complete source-artifact membership and SHA-256 values
  raw/dockpack.zip        deterministic portable package containing all of the above
```

Paths are built from integer identifiers, a fixed scope name and a validated artifact name, and the resolved destination is checked to be inside its run directory, so no operator input can direct a write elsewhere. Every artifact is SHA-256 hashed. Session material such as cookies is deliberately never retained, and detection has nothing raw to retain because it contacts nothing.

A finding is therefore checkable end to end. `FindingEvidence` names the observations it was drawn from; each of those names its discovery run and that run's hashed `EvidenceRecord`; the detection run records the hash of the normalized result the finding appears in. Which detector produced it, from what observation, during which run, and which hash verifies it are all answerable without leaving the database.

Detection, validation, correlation, intelligence, and reporting artifact hashes are recorded as columns on their runs rather than as `evidence_records` rows, because that table's `discovery_run_id` is NOT NULL and keeping the evolution additive avoids relaxing it in place. Unifying them behind one table is the first job of a future versioned migration.

A DockPack is the Phase 6 portable export. It includes the snapshot, both rendered reports, the evidence manifest, and exactly the verified artifacts referenced by the database. The validation package remains one source inside it rather than a competing export format.

## Trust boundaries

| Boundary | Treatment |
| --- | --- |
| Browser → API | Untrusted input. Pydantic validation, `extra="forbid"`, bounded lengths. UI checks are convenience; the server decides. |
| API → DockGuard | Every target, always, server-side. |
| DockGuard → adapter | Only normalized targets and internally generated options cross. Operator strings never become flags. |
| Adapter → target | Non-invasive profiles only, without a shell, under a timeout, with output bounds. |
| Target → RedDock | Tool output and HTTP headers are untrusted data. They are stored and displayed as text, never executed, and self-reported values are marked `reported`. A detector reads that same data and may draw a conclusion from it; it still cannot act on it. |
| API → detector | Only an immutable snapshot of one Dockyard crosses. No session, socket, subprocess, target or operator option is reachable from a detector, and its output is validated before any of it is stored. |
| API → correlation runner | One Dockyard identifier and an empty body. The runner reads stored state, requires evidence hashes, and has no active capability or operator option. |
| API → validation runner | One finding identifier and an approval note only; the runner derives the origin from persisted state and has no arbitrary target or tool option. |
| Validation runner → target | DockGuard must allow the recorded origin at approval time; the only contact is the fixed bounded HTTP probe. |
| API → intelligence runner | One Dockyard identifier and an empty create body; approval adds only a bounded note. Provider credentials and destinations never come from the API. |
| Intelligence runner → model provider | Only the exact retained packet after approval and provider-identity recheck. The request has no tools or action channel; external endpoints require HTTPS and redirects are refused. |
| Model provider → RedDock | Untrusted, size-bounded JSON. Schema, finding IDs, evidence hashes, and duplicates are validated before the advice is retained. |
| API → reporting runner | One Dockyard identifier and an empty body. The runner reads retained state only and accepts no operator-selected path, source, target, or option. |
| RedLedger → DockPack | Only database-referenced regular files whose resolved paths stay under the evidence root and whose bytes match retained SHA-256 values. Portable member names and total size are bounded. |
| DockPack → operator | Potentially sensitive engagement data. The archive and its member manifest must be verified and handled under the engagement's access controls. |
| RedDock → disk | Writes confined to the database file and the evidence root. |

## Concurrency and restart

Discovery runs on a `ThreadPoolExecutor` bounded to the concurrent-run limit; there is no Redis, queue, or worker service. If the process stops while a run is in flight, startup marks that run failed with "Interrupted by a RedDock restart" rather than leaving it looking active or pretending it completed.

Detection is synchronous. It reads stored state and contacts nothing, so there is nothing to wait on: the run completes inside the request, the response describes a finished run, and there is no in-flight detection state for a restart to recover. A second detection run on the same Dockyard while one is in flight is refused rather than interleaved.

Correlation is synchronous for the same reason and is capped at 5,000 derived
edges per snapshot. Startup marks a correlation run left active by a process
restart as failed instead of leaving its audit state ambiguous.

Validation is synchronous only after approval. It is bounded to 500 retained requests per Dockyard, makes at most the two requests owned by the HTTP probe, and records a failed outcome if the process-level probe cannot complete. There is no background retry or task queue.

Intelligence is synchronous only after approval. A Dockyard may retain 200 runs,
one may be active at a time, a packet may contain 200 findings and 512 KiB, and a
provider response is capped at 1 MiB under a fixed 60-second timeout. Startup
marks an interrupted send failed; there is no retry or background queue.

Reporting is synchronous under a single-process creation lock and captures its
database inputs under one explicit transaction. It refuses a snapshot while
discovery, detection, validation, or correlation is active, may retain at most
200 report runs per Dockyard, includes at most 2,000 assets, 20,000 services,
5,000 findings, 20,000 finding-evidence links, 500 validation rows, and 2,000
evidence files, and caps a DockPack at 64 MiB. Query and streaming-read bounds
apply before oversized inputs can be fully materialized. Startup marks an
interrupted report failed and removes its partial reporting directory.

| Detection limit | Value | Why |
| --- | --- | --- |
| Assets per snapshot | 2 000 | A snapshot cannot grow without bound |
| Observations per snapshot | 20 000 | The newest are read, so a long history stays bounded |
| Findings per detector per run | 500 | A detector that exceeds it fails rather than being silently truncated |
| Evidence references per finding per run | 20 | A finding cannot drag an unbounded citation list behind it |
| CVE catalogue | 5 MiB, 20 000 entries | An operator-supplied file is still input |

## Persistence evolution

Database setup is isolated in `backend/app/database.py` and each domain model owns its table definition. Phase 8 introduced a frozen v0.8.0 schema contract and versioned Alembic baseline before any ownership or tenancy column changed. A legacy database is completed additively, validated table by table and column by column, and only then stamped; an unknown shape fails startup without being stamped. Fresh installs are created at the current model and stamped at the current migration head. `tests/test_schema_upgrade.py` and `tests/test_migrations.py` verify old data survival, idempotency, and the fail-closed path.

That constraint has already shaped a decision rather than merely being stated: detection artifact hashes live on the detection run because `evidence_records.discovery_run_id` cannot be relaxed additively.

## Deterministic core

Nothing in discovery, detection, validation, correlation, or reporting is AI-driven.
Detectors remain deterministic rules over recorded data, and the same input
produces the same findings; the same unchanged retained state produces the same
report bytes. Phase 5 intelligence is an optional downstream
advice view: it cannot become evidence, change a conclusion, invoke a tool, or
widen scope. RedDock remains fully useful with no model provider configured.
