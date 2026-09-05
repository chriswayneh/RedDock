# ADR 0012: Detector plugins are data, not code

- Status: accepted
- Date: 2026-09-05

## Context

Phase 7 needs organizations to express narrow local detection policy without
turning RedDock into an arbitrary-code plugin host. Loading Python modules,
commands, templates, or remote packages would let an extension cross the
detector boundary, reach outside the retained snapshot, or compromise the
RedDock process. A plugin marketplace would also introduce an unresolved
supply-chain and trust problem.

## Decision

RedDock accepts only deployment-owned JSON manifests using the versioned
`reddock.detector-plugin/1` schema. Each rule compares one named scalar field on
one retained observation type with one exact scalar value and supplies fixed
finding text and classification. RedDock's code performs the match, constructs
the evidence link, validates the result, and owns persistence.

The loader lives outside the detection package. It reads only top-level JSON
files from one process-configured directory, rejects symlinks, path escapes,
duplicate keys and IDs, unknown fields, excessive sizes, and identifiers outside
the `plugin.` namespace. The registry validates and freezes the full set at
startup. It never dynamically imports or evaluates content, downloads a plugin,
interpolates a template, or accepts a plugin path through the API.

The API exposes the manifest SHA-256 and a detector version containing its hash
prefix. Detection-run evidence therefore records exactly which manifest content
produced a conclusion.

## Consequences

- A detector extension gains no filesystem, network, subprocess, database,
  import, target, or tool capability.
- A deployment owner can add conservative organization-specific rules without a
  RedDock source fork.
- A manifest can still make a poor or misleading claim, so it remains reviewed
  policy whose hash should be pinned and approved.
- Rich logic, remote registries, hot reload, executable SDKs, and third-party
  package installation are intentionally excluded.
