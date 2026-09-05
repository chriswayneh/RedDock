# ADR 0013: Production identity and tenancy require a separate fail-closed mode

## Status

Accepted for Phase 8 implementation.

## Context

RedDock v0.8.x is intentionally local and single-operator. Its documented
Compose deployment publishes only `127.0.0.1:8080`, accepted Host names are
loopback names, and the API has no authentication. That is a coherent local
boundary, but changing a port mapping does not turn it into a secure shared
service.

Production use introduces distinct users, organizations, sensitive engagement
evidence, active target operations, external model disclosure, and privileged
exports. Optional authentication placed around existing ID-only data lookups
would create fail-open paths and make tenant isolation difficult to review.

## Decision

RedDock will support two explicit deployment modes.

### Local mode

- Remains the default and retains the current account-free workflow.
- May publish only on host loopback and accepts only loopback Host names.
- Must not be reverse proxied or exposed to an untrusted network.
- Supports SQLite and the optional private Ollama bundle.

### Server mode

Server mode will fail startup unless every mandatory control is configured:

- PostgreSQL rather than SQLite.
- One exact public origin and exact trusted Host names.
- OIDC authorization-code flow with PKCE, state, and nonce validation. RedDock
  will not store user passwords in the first server-mode release.
- A high-entropy session secret supplied through a mounted secret file.
- TLS termination at a trusted reverse proxy, strict proxy-header handling, and
  `Secure`, `HttpOnly`, same-site session cookies.
- Server-side sessions stored as hashes, with rotation, expiry, revocation, and
  logout. A stolen database must not contain reusable bearer sessions.
- Origin and CSRF enforcement for state-changing browser requests.
- No public self-signup. An owner/admin provisions membership and OIDC
  issuer/subject identity through an explicit bootstrap process.

Mixed or incomplete configurations are rejected. In particular, setting a
public origin cannot silently leave the local unauthenticated API enabled.

## Ownership model

Phase 8 adds:

- `Organization`: tenant and policy boundary.
- `User`: profile synchronized from a verified OIDC issuer/subject pair. Email
  is display/contact data, never the stable identity key.
- `Membership`: a user's role and status in an organization.
- `Dockyard.organization_id`: mandatory owner for engagement state.
- `Session`: expiring and revocable; only a token hash is retained server-side.
- `SecurityAuditEvent`: tenant-bound structured decisions with bounded opaque
  identifiers and no free-form detail field.

Every child resource is authorized through its Dockyard and organization. A
route must use a central organization-aware loader; `session.get(Resource, id)`
or an ID-only query is not authorization. Absent and cross-tenant objects should
use the same response where that prevents an identifier oracle.

Existing local data will migrate into one explicit local organization and
bootstrap owner. Migration must preserve IDs and hashes, require a documented
backup, and make organization ownership non-null before server mode is enabled.

## Roles

Permissions are named and deny by default.

| Role | Intended authority |
| --- | --- |
| `owner` | All organization actions, ownership transfer, membership and identity administration |
| `admin` | Membership and Dockyard administration plus operator actions, except ownership transfer |
| `operator` | Manage Dockyards/scope; run product workflows; update finding workflow state |
| `auditor` | Read normalized/raw evidence, audit history, reports, and DockPacks; no mutations or active operations |
| `viewer` | Read normalized inventory, findings, correlations, and report summaries; no raw evidence, approvals, exports, configuration, or mutation |

Approval-gated operations require both the operation permission and an
authenticated actor. Approval and append-only audit rows record user,
membership, organization, request metadata, and time. Role is rechecked at
execution; approval does not survive membership revocation or a permission-
removing role change.

## Enforcement and testing

- A central reviewed policy/dependency layer owns route permissions.
- Data-access helpers require authorization context and organization ID.
- UI visibility improves usability; the API is always the enforcement point.
- Tests cover every role/action pair, cross-organization ID swaps, disabled
  memberships, revoked/expired sessions, OIDC issuer/subject confusion,
  CSRF/origin failures, and approval-time role changes.
- Logs and errors exclude cookies, authorization codes, client secrets, session
  tokens, and model credentials.
- Server mode is not production-ready until PostgreSQL, migrations,
  backup/restore, proxy/TLS, and multi-process concurrency tests pass.

## Consequences

Local use stays simple and backward compatible. Shared deployments gain a
reviewable security boundary rather than relying on placement alone. Phase 8 is
therefore staged: PostgreSQL and secret-file configuration; identity and
sessions; centralized RBAC; UI administration and OIDC; operations validation;
then the v0.9.0 release.

Until those stages are complete, RedDock is not a supported shared or
internet-facing service.
