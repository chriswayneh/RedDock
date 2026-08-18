# Architecture

## Shape

```text
Browser → React UI (static files) → FastAPI → DockGuard → discovery adapter
                                        ↓                        ↓
                                     SQLite                  evidence files
```

The production image builds the React/Vite application and serves it as static content from the same FastAPI process that exposes `/api`. A named Docker volume holds SQLite at `/var/lib/reddock` and retained evidence at `/var/lib/reddock/evidence`. There is deliberately no reverse proxy, separate frontend service, queue, or remote dependency.

## Boundaries

- `backend/app/api.py`: HTTP validation and response mapping.
- `backend/app/targets.py`: target parsing and normalization.
- `backend/app/dockguard.py`: scope evaluation and decisions.
- `backend/app/services.py`: Dockyard and scope operations.
- `backend/app/inventory.py`: asset, service, and observation persistence rules.
- `backend/app/discovery/`: the adapter contract, adapters, registry, and run orchestration.
- `backend/app/evidence.py`: the evidence store.
- `backend/app/models.py` and `schemas.py`: persistence mappings and input/output contracts.
- `frontend/src`: presentation and API client only.

## Target normalization

Every operator-supplied target passes through `normalize_target` before anything else sees it. Normalization produces one canonical form per target and rejects anything ambiguous:

- IPv4 and IPv6 addresses in strict textual form only — integer, packed, and zero-padded forms are refused so `3232235777` can never quietly become `192.168.1.1`.
- Networks canonicalized to their network address (`192.168.1.37/24` → `192.168.1.0/24`).
- Hostnames lowercased, stripped of a trailing dot, IDNA-encoded per label, and validated.
- URLs reduced to an origin: scheme, host, and port. Paths, queries, fragments, and embedded credentials are rejected or dropped, because Phase 1 probes an origin and not a location.

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
- **EvidenceRecord** — a hashed pointer to one retained artifact.

**Observation ≠ Finding.** An observation says what happened; a finding says what it means. RedDock records the former and, in Phase 1, deliberately refuses to imply the latter. Findings, severity, and scoring belong to Phase 2.

## Evidence flow (RedLedger foundation)

Every completed run writes:

```text
evidence/<dockyard-id>/<run-id>/
  metadata.json          adapter, tool version, profile, targets, DockGuard decision,
                         invocation, timestamps, counts, artifact hashes
  raw/                   unmodified tool output
  normalized/result.json the normalized assets and observations
```

Paths are built from integer identifiers and a validated artifact name, and the resolved destination is checked to be inside its run directory, so no operator input can direct a write elsewhere. Each artifact is SHA-256 hashed and recorded as an `EvidenceRecord`. Session material such as cookies is deliberately never retained.

This is the foundation only. Validation state, evidence packages, and portable exports belong to later phases.

## Trust boundaries

| Boundary | Treatment |
| --- | --- |
| Browser → API | Untrusted input. Pydantic validation, `extra="forbid"`, bounded lengths. UI checks are convenience; the server decides. |
| API → DockGuard | Every target, always, server-side. |
| DockGuard → adapter | Only normalized targets and internally generated options cross. Operator strings never become flags. |
| Adapter → target | Non-invasive profiles only, without a shell, under a timeout, with output bounds. |
| Target → RedDock | Tool output and HTTP headers are untrusted data. They are stored and displayed as text, never executed, and self-reported values are marked `reported`. |
| RedDock → disk | Writes confined to the database file and the evidence root. |

## Concurrency and restart

Discovery runs on a `ThreadPoolExecutor` bounded to the concurrent-run limit; Phase 1 introduces no Redis, queue, or worker service. If the process stops while a run is in flight, startup marks that run failed with "Interrupted by a RedDock restart" rather than leaving it looking active or pretending it completed.

## Persistence evolution

Database setup is isolated in `backend/app/database.py` and each domain model owns its table definition. Phase 1 is purely additive — it adds tables and changes no existing column — so `create_all` upgrades a Phase 0 database in place without data loss, which `tests/test_schema_upgrade.py` verifies against a real 0.1.0-shaped database. Before the first destructive schema change, introduce versioned Alembic migrations rather than altering deployed tables ad hoc.

## AI boundary

AI is not integrated in Phase 1 and is optional thereafter. It may propose structured actions, but DockGuard evaluates them exactly as it evaluates an operator's, and it never receives shell access or the ability to widen scope. RedDock must remain useful with no AI provider configured.
