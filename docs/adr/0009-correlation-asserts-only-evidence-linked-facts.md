# ADR 0009: Correlation asserts only evidence-linked facts

## Status

Accepted

## Context

Phase 4 needs to show useful relationships across assets and findings without
turning co-occurrence into a claim of causation or drawing an attack path that
RedDock did not test. A visually plausible graph can otherwise appear more
authoritative than the observations behind it.

## Decision

Correlation runs synchronously over one Dockyard's stored state and accepts an
empty request body. It has no socket, subprocess, target, selector, weighting,
dynamic plugin, or operator-supplied rule.

An asset relationship is stored only when a web asset's recorded address is
exactly equal to a host asset's normalized identity and a retained discovery
artifact supports the web observation. Findings correlate only when they share
that exact asset or belong to the two sides of such an asset relationship. Each
finding must already carry a retained evidence hash. A missing observation or
hash causes the candidate relationship to be omitted.

Framework mappings are a fixed, versioned table from RedDock detector rules to
CWE weakness classes. They classify an existing conclusion and do not add
evidence or change severity, confidence, status, or validation outcome.

Every run retains normalized output and metadata under the fixed `correlation`
evidence scope. RedPath renders the stored snapshot, explanation, confidence,
and evidence hashes. The graph does not claim network reachability,
exploitability, causation, likelihood, or aggregate risk.

## Consequences

- A reviewer can inspect why every edge exists and verify its evidence hash.
- Repeated snapshots preserve what RedDock knew at a point in time.
- Relationships remain conservative and may omit useful but unproven links.
- Richer inference may be added only with a separately documented evidence and
  confidence model; it cannot silently broaden these semantics.
