# Security

## Responsible use

RedDock is for systems owned by the operator or assessed with explicit authorization. It is appropriate for authorized engagements, labs, cyber ranges, CTFs, and training environments. Do not use it to access systems outside approved scope.

## Product safety model

Phase 0 cannot execute security tools. Future execution will require a requested action to pass DockGuard scope validation, policy validation, risk classification, and—where configured—human approval. AI will never receive unrestricted shell access or the ability to expand target scope.

## Baseline controls

- The production container runs as an unprivileged `reddock` user.
- SQLite data is held in a named volume, not baked into the image.
- Inputs use Pydantic validation; unknown or malformed Dockyard requests are rejected.
- CORS is intentionally not opened in Phase 0 because UI and API share one origin.
- No secrets are checked into this repository.
- Container health checks use the API health endpoint.

## Reporting a vulnerability

Do not open a public issue for a suspected security flaw. When GitHub Private Vulnerability Reporting is enabled, use it for a concise report with reproduction steps, affected versions, and impact. Until then, avoid posting sensitive details publicly and ask the maintainers for a private reporting channel.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes — current Phase 0 foundation |

Security fixes are evaluated for the latest published Phase 0 release. RedDock is a local, single-operator application in this phase; do not expose it to untrusted networks.
