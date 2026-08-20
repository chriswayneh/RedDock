# Architecture

## Shape

```text
Browser → React UI (static files) → FastAPI → DockGuard → discovery adapter
                                        │                        ↓
                                        │            SQLite ← evidence files
                                        ↓               ↓
                                    detector ←── snapshot of stored state
                                        ↓
                                    findings → validation request → approval → DockGuard → fixed HTTP recheck
```

Three paths leave the API. Discovery goes through DockGuard to a target and records what it saw. Detection goes the other way: it reads stored state, concludes something about it, and writes findings back without ever reaching a target. The third begins with a validation request that records intent only; a separately noted approval rechecks DockGuard and may send one fixed HTTP-origin probe. The network boundary is therefore limited to discovery and the narrowly bounded recheck.

The production image builds the React/Vite application and serves it as static content from the same FastAPI process that exposes `/api`. A named Docker volume holds SQLite at `/var/lib/reddock` and retained evidence at `/var/lib/reddock/evidence`. There is deliberately no reverse proxy, separate frontend service, queue, or remote dependency.

## Boundaries

- `backend/app/api.py`: HTTP validation and response mapping.
- `backend/app/targets.py`: target parsing and normalization.
- `backend/app/dockguard.py`: scope evaluation and decisions.
- `backend/app/services.py`: Dockyard and scope operations.
- `backend/app/inventory.py`: asset, service, and observation persistence rules.
- `backend/app/discovery/`: the adapter contract, adapters, registry, and run orchestration.
- `backend/app/detection/`: the detector contract, detectors, registry, fingerprints, CVE enrichment, and run orchestration.
- `backend/app/findings.py`: finding persistence, deduplication, and lifecycle rules.
- `backend/app/validation/`: approval-gated validation orchestration and the fixed HTTP-origin profile.
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
| `nmap` | `host_discovery`, `service_discovery` | `-sn` host discovery, or a TCP connect scan of the top 100 ports with light version detection. No NSE scripts, no UDP, no OS detection, no evasion, no `-A`. |
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

Three things keep this from producing the usual noise. A header is only reported when the probe recorded that it looked for it, so "RedDock did not look" is never rendered as "the server did not send it". Content-level headers are only judged on a response that represents how an endpoint normally answers, so a 301 to HTTPS carrying no Content-Security-Policy is not a finding. And a service rule needs an identification observation, so a port number alone still says nothing: TCP/23 open is TCP/23 open.

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
```

Paths are built from integer identifiers, a fixed scope name and a validated artifact name, and the resolved destination is checked to be inside its run directory, so no operator input can direct a write elsewhere. Every artifact is SHA-256 hashed. Session material such as cookies is deliberately never retained, and detection has nothing raw to retain because it contacts nothing.

A finding is therefore checkable end to end. `FindingEvidence` names the observations it was drawn from; each of those names its discovery run and that run's hashed `EvidenceRecord`; the detection run records the hash of the normalized result the finding appears in. Which detector produced it, from what observation, during which run, and which hash verifies it are all answerable without leaving the database.

Detection and validation artifact hashes are recorded as columns on their runs rather than as `evidence_records` rows, because that table's `discovery_run_id` is NOT NULL and keeping the evolution additive avoids relaxing it in place. Unifying them behind one table is the first job of a future versioned migration.

Portable exports still belong to later phases; the Phase 3 package is retained locally and is not an export format.

## Trust boundaries

| Boundary | Treatment |
| --- | --- |
| Browser → API | Untrusted input. Pydantic validation, `extra="forbid"`, bounded lengths. UI checks are convenience; the server decides. |
| API → DockGuard | Every target, always, server-side. |
| DockGuard → adapter | Only normalized targets and internally generated options cross. Operator strings never become flags. |
| Adapter → target | Non-invasive profiles only, without a shell, under a timeout, with output bounds. |
| Target → RedDock | Tool output and HTTP headers are untrusted data. They are stored and displayed as text, never executed, and self-reported values are marked `reported`. A detector reads that same data and may draw a conclusion from it; it still cannot act on it. |
| API → detector | Only an immutable snapshot of one Dockyard crosses. No session, socket, subprocess, target or operator option is reachable from a detector, and its output is validated before any of it is stored. |
| API → validation runner | One finding identifier and an approval note only; the runner derives the origin from persisted state and has no arbitrary target or tool option. |
| Validation runner → target | DockGuard must allow the recorded origin at approval time; the only contact is the fixed bounded HTTP probe. |
| RedDock → disk | Writes confined to the database file and the evidence root. |

## Concurrency and restart

Discovery runs on a `ThreadPoolExecutor` bounded to the concurrent-run limit; there is no Redis, queue, or worker service. If the process stops while a run is in flight, startup marks that run failed with "Interrupted by a RedDock restart" rather than leaving it looking active or pretending it completed.

Detection is synchronous. It reads stored state and contacts nothing, so there is nothing to wait on: the run completes inside the request, the response describes a finished run, and there is no in-flight detection state for a restart to recover. A second detection run on the same Dockyard while one is in flight is refused rather than interleaved.

Validation is synchronous only after approval. It is bounded to 500 retained requests per Dockyard, makes at most the two requests owned by the HTTP probe, and records a failed outcome if the process-level probe cannot complete. There is no background retry or task queue.

| Detection limit | Value | Why |
| --- | --- | --- |
| Assets per snapshot | 2 000 | A snapshot cannot grow without bound |
| Observations per snapshot | 20 000 | The newest are read, so a long history stays bounded |
| Findings per detector per run | 500 | A detector that exceeds it fails rather than being silently truncated |
| Evidence references per finding per run | 20 | A finding cannot drag an unbounded citation list behind it |
| CVE catalogue | 5 MiB, 20 000 entries | An operator-supplied file is still input |

## Persistence evolution

Database setup is isolated in `backend/app/database.py` and each domain model owns its table definition. Every phase so far is purely additive — it adds tables and changes no existing column — so `create_all` upgrades a deployed database in place without data loss. `tests/test_schema_upgrade.py` verifies that against real 0.1.0-shaped and 0.2.1-shaped databases, including running a full detection over data written by the previous release. Before the first destructive schema change, introduce versioned Alembic migrations rather than altering deployed tables ad hoc.

That constraint has already shaped a decision rather than merely being stated: detection artifact hashes live on the detection run because `evidence_records.discovery_run_id` cannot be relaxed additively.

## AI boundary

AI is still not integrated, and remains optional whenever it arrives. It may propose structured actions, but DockGuard evaluates them exactly as it evaluates an operator's, and it never receives shell access or the ability to widen scope. Nothing in detection is AI-driven: every detector is a deterministic rule over recorded data, and the same input produces the same findings. RedDock must remain useful with no AI provider configured.
