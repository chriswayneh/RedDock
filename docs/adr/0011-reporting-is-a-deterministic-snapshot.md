# ADR 0011: Reporting is a deterministic retained-state snapshot

- Status: accepted
- Date: 2026-09-05

## Context

RedDock needs technical and executive reports that can travel with the evidence
behind them. A conventional report generator could accept arbitrary queries,
templates, filesystem destinations, live provider calls, or a best-effort set of
whatever files happen to exist. Those choices would weaken Dockyard isolation,
create active capability in a passive phase, and make a report impossible to
reproduce or audit.

The evidence store also evolved additively. Discovery artifacts have individual
`EvidenceRecord` rows, while later phases store known artifact hashes on their
run records. The export must cover both without changing previous schemas.

## Decision

Reporting accepts only a Dockyard identifier and an empty request body. It reads
completed retained state, never contacts a target or model, and accepts no
operator-selected source, template, output path, command, URL, or archive name.
It refuses to snapshot while discovery, detection, validation, or correlation
source work is active.

The runner enumerates artifacts from database references rather than scanning
directories. It resolves each reference beneath RedLedger and verifies the
retained SHA-256 before use. Unsafe paths, missing or changed files, conflicting
portable names, incomplete hashes, and count or size limit violations fail the
whole run.

One canonical technical JSON snapshot drives the technical and executive
Markdown reports. A separate evidence manifest binds the Dockyard, generator,
scope hash, cited runs, and finding claims to every included source artifact.
A DockPack contains those reports, the manifest, and the verified
source bytes. Canonical JSON, ordered records, fixed ZIP metadata, and exclusion
of report history make unchanged state byte-reproducible. Every output is
retained and hashed, and a package is re-hashed before download.

## Consequences

- A report is traceable to exact retained bytes, not merely to database claims.
- Re-running reporting without changing source state produces the same artifacts.
- Reporting cannot become a second discovery, intelligence, publishing, or file
  export interface.
- A changed or unavailable source fails closed; RedDock does not silently create
  a partial package.
- DockPacks can contain sensitive engagement data and require operator-controlled
  storage, review, sharing, and retention.
- Rich custom templates, selective exports, automatic delivery, signing, and
  server-side publication are intentionally outside this decision.
