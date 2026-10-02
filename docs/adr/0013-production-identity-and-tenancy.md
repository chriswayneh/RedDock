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
- TLS termination at a trusted reverse proxy, strict proxy-header handling, and
  `Secure`, `HttpOnly`, same-site session cookies.
- Server-side sessions stored as hashes in stable families, with a 30-minute
  idle limit, throttled activity updates, paired bearer and CSRF rotation,
  expiry, revocation, and logout. A stolen database must not contain reusable
  bearer sessions.
- Origin and CSRF enforcement for state-changing browser requests.
- Database-serialized global and subject rate limits before authentication and
  protected mutations. Limiter decisions own separate transactions, and raw
  client and identity values are protected with a stable, mounted,
  deployment-owned HMAC key shared by every worker. Limiter transactions use a
  reserved connection pool so request work cannot starve the decision path. A
  separate database login and password restrict the limiter to its exact
  bucket operations.
- No public self-signup. An owner/admin provisions membership and OIDC
  issuer/subject identity through an explicit bootstrap process.

Mixed or incomplete configurations are rejected. In particular, setting a
public origin cannot silently leave the local unauthenticated API enabled.

The first ingress checkpoint keeps server mode blocked while defining the
proxy contract. The application server does not interpret forwarding headers
implicitly. A dedicated middleware accepts one canonical forwarded client,
Host, and HTTPS scheme only when the immediate peer is in the deployment-owned
proxy allowlist. Alternate `Forwarded` syntax, duplicate values, and multi-hop
lists are rejected.

Rate-limit buckets use finite code-owned action names and domain-separated,
deployment-keyed HMAC subject keys. PostgreSQL conflict updates serialize
concurrent workers. A global bucket is consumed first, so a globally denied
request cannot create an attacker-selected subject row. Each decision uses a
separate short transaction so it cannot commit or roll back protected caller
state. These counters are short-lived operational state, not tenant records,
and do not enable any route by themselves.

The dormant runtime accepts only a mounted key containing exactly 64 lowercase
hexadecimal characters. One process-owned capability keeps its decoded key
paired with an isolated, prewarmed two-connection pool. The main pool is capped
at 15 connections, producing a 17-connection application budget per process
plus operational headroom. Checkout, connection, statement, and lock waits are
bounded, and failure to make a durable decision denies the request. Real
PostgreSQL tests fill each pool in turn and confirm isolation.

All workers must share the same key. Rotation requires a full stop, one shared
secret replacement, and a coordinated restart because mixed keys would split
counters. Local mode and the current Compose profiles neither load the key nor
create the capability. No protected route uses it, and server mode remains
disabled.

The dormant server runtime requires `REDDOCK_RATE_LIMIT_DATABASE_USER` and a
mounted `REDDOCK_RATE_LIMIT_DATABASE_PASSWORD_FILE`. The username and password
must each differ from the application database credentials. Limiter
connections use the dedicated login and fix their search path to
`pg_catalog,public`.

Startup verifies a direct `LOGIN NOINHERIT` role with a connection limit exactly
twice `REDDOCK_SERVER_WORKERS`, no memberships or elevated flags, and only:

- database `CONNECT`;
- `public` schema `USAGE`;
- bucket `SELECT`/`INSERT`/`UPDATE`/`DELETE`; and
- bucket-sequence `USAGE`.

Ownership, grant options, column-level grants, database or schema creation,
temporary access, other databases, large objects, database parameter grants,
role-level settings, user-defined routines, standalone PostgreSQL type
ownership, bucket policies or triggers, foreign keys, rewrite rules,
inheritance, and unrelated application objects are rejected. Every process
must receive the same worker count, set to the actual
deployment-wide total; RedDock cannot discover the orchestrator's process count.

Deployment operators provision this role after the main application role runs
migrations. RedDock migrations do not create or manage PostgreSQL logins. Role
password rotation requires stopping all workers, changing the database role and
mounted secret together, and restarting every worker. The check runs at startup
rather than continuously. The main role retains migration authority, and both
database secrets exist in one process. Database-wide capacity and consistent
HMAC-key distribution remain separate operational gates.

The dormant configured application lifespan composes one authentication
coordinator from the process-owned provider, isolated limiter, and the engine
owned by an exact-config primary database runtime. Login admission occurs
before provider discovery and state creation. Callback admission occurs before
one-use state consumption; the state is then burned before token exchange. A
verified token must map to an
exact pre-provisioned issuer/subject membership, locked through session
issuance, before an audited hash-only session is created. Post-burn provider
exchange and ID-token validation failures make a best-effort attempt to record
bounded denial events. Expected failures are generic, with a retry interval
only for a durable rate-limit denial. A dormant HTTP router invokes this
coordinator in an isolated harness; the running app does not register it or
provide a sign-in UI, and server mode remains disabled. The primary runtime verifies its effective login, database,
fixed search path, and timeout policy; owns its engine and session factory for
the application lifespan; bounds connection, checkout, statement, lock,
idle-transaction, and transaction waits; and disposes the engine at shutdown.
Migration and interrupted-work recovery share one connection behind a fixed
PostgreSQL advisory lock before the runtime is ready. The main role still runs
migrations and retains application-data authority. This runtime is not a
substitute for the separately credentialed limiter role.

The lifespan installs one immutable database request binding after startup.
Local requests use the global `SessionLocal` factory only through an explicit
local binding. Configured request database dependencies use
`PrimaryDatabaseRuntime.session`, and each yielded session is closed. A missing
or malformed binding produces a generic database-dependency `503` without
falling back to ambient database state. Configured protected routes receive no
local-owner context. A separate immutable authentication binding must match the
exact database binding and process-owned coordinator. Through trusted HTTPS
ingress, each request resolves one hash-only session and rechecks active user,
membership, role, configured issuer, and configured organization. Invalid or
ambiguous credentials return `401`; dependency outages return generic `503`.
Mutations additionally require exact Origin and CSRF proof before database
resolution and a durable membership-scoped limiter decision afterward. Role
enforcement and tenant-scoped record lookups remain mandatory. Public health
checks do not require a browser session.

Discovery carries the exact request session factory from submission into its
worker. Each lifespan owns one executor bound to that exact factory; missing,
closed, or mismatched runtimes reject admission. Shutdown drains accepted work
before closing authentication, provider, limiter, and primary database resources.
Compose gives the bounded discovery work 12 minutes to finish. Forced termination
still requires interrupted-work recovery on restart. HTTP session renewal,
and sign-in/logout routes remain unregistered in the running application.
Server mode remains disabled until those integrations and the other deployment
gates are complete.

Discovery commits a requester audit receipt with admission and queues that exact
receipt alongside the run ID. Execution validates its action, successful outcome,
run, and organization, and re-reads current user and membership authority under
the lifespan's immutable issuer/organization policy. A conditional pending-to-running
update gives duplicate delivery one database-wide winner. Authority is checked
before scope resolution and again immediately before adapter contact; the final
decision and audit commit before contact. Revocation after that boundary does not
cancel an admitted external operation. Receipts are not replayed on restart, and
this claim does not make capacity admission database-wide.

Validation and intelligence carry a separate immutable workflow-policy binding
paired by identity with the request database capability. Requests record their
actor; approvals independently resolve the current approver and their required
permission both before verification and at the final claim. The claim and actor
audit commit together before target or provider contact. Another authorized
member can approve a retained request after its requester loses access. Historical
local pending requests remain usable, with no fabricated requester attribution.
PostgreSQL races verify one-winner approval and final revocation checks. This does
not complete administration or server acceptance.

Lab grant and revocation mutations use the same paired workflow policy, with
current `lab:authorize` permission held through the atomic policy/audit commit.
The workspace row serializes PostgreSQL mutations before identity locks; local
SQLite also uses a process mutex. Grant supersession and the lab history bound
therefore remain consistent across independent workers. A grant is workspace
policy until expiry, supersession, or explicit revocation. Revoking its author's
membership does not implicitly revoke that policy; discovery independently
checks its current execution actor and the lab gate before contact.

Stored-data detection, correlation, and report creation require the same exact
workflow policy and record requester attribution. They re-read current authority
before committing a publication event. Detection and correlation no longer
commit intermediate findings or relationships: result rows, artifact references,
and the publication event become visible together. A failed check or evidence
write rolls back unpublished results while retaining a failed run. Reporting
preserves its independent consistent snapshot transaction, then checks current
permission at publication and removes partial artifacts on failure. Team
administration integration, audit retention, and full deployment acceptance remain open.

The dormant team administration core requires a current configured owner/admin
and a fresh, operation-owned transaction. It provisions an exact issuer/subject
without signup or silently attaching existing identities, with at most 1,000
retained memberships and 100 entries per roster page. Ordinary edits cannot
assign or modify an owner. Explicit owner-only transfer requires exactly one
retained owner and an active recipient; the former owner becomes an admin.
Access changes and transfer revoke all affected browser-session lineage and
commit structured audit events in the same transaction. The organization row
serializes administration before identity and session locks across PostgreSQL
workers; SQLite tests also use a process mutex. Audit failure rolls back the
identities and revocations together.

Dormant administration adapters expose a bounded roster, provisioning, member
access edits, and ownership transfer only in an isolated HTTP harness. Their
separate immutable route manifest requires membership management or owner-only
transfer permission. They use the exact database/authentication/workflow
capability pairing, trusted HTTPS ingress, and current browser authority;
mutations require Origin, CSRF, and durable membership admission. The core
rechecks permissions after request admission. Expected failures are generic,
input errors do not echo identity fields, and success/error responses are
no-store with fixed browser security headers. Transfer invalidates both members'
existing cookies and requires a new login. The running app registers none of
these routes; administration UI and server deployment remain unfinished.

The same dormant router exposes security history only with current `audit:read`
permission. Owner/admin/auditor roles can read it; this does not grant auditors
access to the identity roster or member changes. Reads return at most 100
structured event snapshots with explicit UTC timestamps and a descending ID
cursor, without names, OIDC subjects, or credentials. The organization comes
only from rechecked authority, never from a query parameter. New events do not
shift subsequent cursor pages. Reads retain historical actor-role snapshots and
nullable actor IDs, emit no recursive audit events, and use the same no-store
response hardening. Retention and restricted archival export remain open.

Workspace creation, scope mutations, and finding-status edits require current
permission and commit actor attribution with the mutation. Scope mutations use
workspace locking before identity locks, preserving duplicate and count bounds
across workers. Scope evaluation commits authorization before optional DNS
resolution. Exports recheck current `report:export` permission after artifact
verification, then commit admission before returning a file response. This event
does not prove delivery, and later revocation cannot retract an admitted download.
Security events contain fixed reasons and opaque IDs, never user notes or targets.

Session generations belong to one stable, random family. They become idle after
30 minutes, update activity at most once every five minutes, and rotate the
bearer token and CSRF proof together after one hour. Rotation preserves the
original eight-hour absolute expiry. Replaced generations cannot authenticate,
but a retained predecessor can still identify the family for logout so a
concurrent rotation does not preserve access. Request-facing issue, use, and
logout operations own short isolated transactions. Lower-level revocation can
instead join an identity or membership change so both commit or roll back
together. Cleanup is bounded, and its PostgreSQL locking must remain safe beside
concurrent refresh. PostgreSQL tests cover issuance, touch, rotation, logout,
membership revocation, and cleanup races. These primitives now connect to dormant
HTTP adapters in an isolated harness. The running app registers no authentication
route, and server mode remains disabled.

Renewal and logout require trusted ingress, one exact Origin, and matching CSRF
proof before durable membership admission. Admission releases primary database
connections before limiter I/O and does not touch or mutate the session. Renewal
then rechecks active identity and rotates under the existing lifecycle transaction;
cookies and response expiry retain the original absolute deadline. Logout rechecks
the presented generation's proof and configured issuer/organization under family
locks before revoking. Inactive membership or a retained predecessor grants only
this revocation authority. Already-revoked retained families can complete logout
idempotently. Denials never clear or overwrite cookies. A dormant recovery read
now restores current role, permissions, absolute expiry, and the derived CSRF
proof. It requires trusted HTTPS ingress, exactly one bearer cookie, the
non-safelisted `X-RedDock-Session: recover` header, and exactly one
`Sec-Fetch-Site: same-origin` header. If Origin is present it must match exactly;
no authentication endpoint grants CORS access. Recovery uses the shared durable
membership request budget and rechecks identity after admission. It does not
touch idle activity, extend expiry, rotate tokens, emit session events, or set
cookies. Its no-store response contains no bearer, subject, or user identifier.
The dormant frontend session client stores the recovered CSRF proof only in
private page memory, exposes immutable role/permission/expiry state, and relies
on the browser's HttpOnly cookie. It coordinates recovery, renewal, logout, and
mutations within one page; concurrent reads cannot erase newer session state.
Discarding page state prevents late recovery from restoring it. Business API
requests use same-origin credentials, reject redirects, omit proofs on reads,
and never replay failed writes automatically. Logout is only reported as
confirmed after the server returns its success response. A cross-tab token
change requires explicit recovery after denial, without replaying the action.
The dormant client now publishes that change as a fixed same-origin notice with
no proof, role, or identifier. Peer pages drop the in-memory proof and do not
fetch or retry; only a later explicit recovery restores it. Confirmed logout
notifies those pages to sign out locally. A forgotten page or a failed logout
sends nothing. This client is not instantiated by the local UI. Sign-in screens
and full authentication acceptance remain separate gates.

## Ownership model

Phase 8 adds:

- `Organization`: tenant and policy boundary.
- `User`: an identity provisioned and matched only by its verified OIDC
  issuer/subject pair. Provider profile claims are not retained by the first
  authentication checkpoint.
- `Membership`: a user's role and status in an organization.
- `Dockyard.organization_id`: mandatory owner for engagement state.
- `Session`: one hash-only token generation in a stable, expiring, revocable
  family. Rotation replaces the bearer and CSRF pair without extending the
  family's absolute lifetime.
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
- PostgreSQL race coverage confirms concurrent session issuance, touch,
  rotation, revocation, cleanup, and one-winner callback consumption while the
  lifecycle and coordinator remain disconnected from the running app's routes.
- Authentication orchestration tests cover admission order, generic failures,
  provider outages, replay, unprovisioned identities, process lifecycle, and
  one-winner PostgreSQL callback concurrency.
- Isolated HTTP adapter tests cover trusted ingress, exact live capability
  pairing, exact login Origin, one-use browser-bound callbacks, secure cookies,
  CSRF delivery, no-store/no-referrer headers, denial cleanup, replay, and
  duplicate parameters/cookies. The same isolated app can mount the product route
  manifest: a callback session is allowed or denied from the current membership
  role, and logout removes it. The callback returns JSON with a CSRF proof and
  expiry; frontend handling still needs integration. The supported application
  does not register the authentication router. Both packaged Uvicorn
  entrypoints disable raw request access logs. The Compose proxy logs only fixed
  route/method categories, time, status, byte count, and duration. Request-level
  Nginx error logs are suppressed because they can append a raw request URI;
  master startup diagnostics remain on stderr. Diagnose HTTP failures through
  status metrics, readiness, and application diagnostics. Native container CI
  checks synthetic secrets in paths, queries, and headers against success,
  rejection, oversized-body, and upstream-unavailable responses. A future TLS
  ingress must preserve and reverify this boundary. See the official
  [Nginx log format](https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format)
  and [error log](https://nginx.org/en/docs/ngx_core_module.html#error_log) contracts.
- Primary database tests cover exact-config construction, effective session
  policy, bounded timeout options, serialized startup, owned session and engine
  lifecycle, and cleanup after partial startup failure.
- Request-binding tests cover explicit local and configured selection, generic
  failure for missing or malformed state, session closure, protected-route
  denial without browser identity, and discovery worker factory propagation.
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
