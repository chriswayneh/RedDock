# Optional PostgreSQL profile

RedDock remains a local, loopback-only application in this Phase 8 checkpoint.
The optional PostgreSQL profile replaces SQLite persistence so migrations,
drivers, backups, and concurrency can be validated before authenticated server
mode exists. It does **not** make the current unauthenticated API safe to expose.

The profile uses the official PostgreSQL 17.11 Bookworm image pinned to its
multi-architecture digest. PostgreSQL is reachable only on the private Compose
network and has no host port. Its password is mounted into both containers as a
Compose secret, not injected into their service environment.

## Start with PostgreSQL

Choose a unique strong password without placing it in shell history.

PowerShell:

```powershell
$credential = Read-Host "Temporary PostgreSQL password" -AsSecureString
$env:REDDOCK_POSTGRES_PASSWORD = [System.Net.NetworkCredential]::new("", $credential).Password
docker compose -f compose.yaml -f compose.postgres.yaml up --build
Remove-Item Env:REDDOCK_POSTGRES_PASSWORD
```

Bash:

```bash
read -rsp "Temporary PostgreSQL password: " REDDOCK_POSTGRES_PASSWORD && echo
export REDDOCK_POSTGRES_PASSWORD
docker compose -f compose.yaml -f compose.postgres.yaml up --build
unset REDDOCK_POSTGRES_PASSWORD
```

Open [http://localhost:8080](http://localhost:8080). The first start creates the
database with SCRAM host authentication and data checksums, then RedDock creates
and stamps its versioned schema. Later starts reuse the `reddock-postgres`
volume. Normal `docker compose ... down` retains both PostgreSQL and evidence.

The Compose secret is sourced from the invoking process only long enough for
Compose to mount `/run/secrets/reddock-postgres-password`. The password is
represented inside RedDock as a masked secret, and SQLAlchemy constructs the
connection URL without logging it. An empty, oversized, multiline, missing, or
symlinked secret file fails startup.

This local validation profile does not mount a rate-limit key or create a
limiter runtime. Those are server-only controls, and server mode remains
disabled.

## Combine PostgreSQL and local AI

The database and model overlays compose independently:

```bash
docker compose -f compose.yaml -f compose.postgres.yaml -f compose.ollama.yaml up --build
```

The same `REDDOCK_POSTGRES_PASSWORD` setup is required. Ollama and PostgreSQL
remain private services with no published host ports.

## Stop without deleting data

```bash
docker compose -f compose.yaml -f compose.postgres.yaml down
```

Do not add `-v` unless you intentionally want Docker to delete named volumes.
`reddock-postgres` contains the database, `reddock-data` contains RedLedger
evidence, and `reddock-ollama` contains optional model weights.

## External PostgreSQL

An orchestrator can provide the same non-secret connection fields and mount a
password file into the RedDock container:

| Variable | Meaning |
| --- | --- |
| `REDDOCK_DATABASE_HOST` | Exact PostgreSQL DNS host name |
| `REDDOCK_DATABASE_PORT` | TCP port; defaults to `5432` |
| `REDDOCK_DATABASE_NAME` | Database name |
| `REDDOCK_DATABASE_USER` | Login role |
| `REDDOCK_DATABASE_PASSWORD_FILE` | In-container path to one UTF-8 password secret |

These component settings take precedence over the legacy
`REDDOCK_DATABASE_URL`. A partial component configuration is rejected. A direct
URL remains available for development and CI, but managed deployments should
mount the password secret instead.

## Future server connection budget

The dormant server runtime accepts `REDDOCK_RATE_LIMIT_KEY_FILE` only when the
file contains exactly 64 lowercase hexadecimal characters. It decodes those
characters to a 32-byte key, masks the value, and keeps it paired with one
process-owned limiter capability. Every worker must mount the same key. Do not
rotate it through a rolling restart because mixed keys split rate-limit
counters. Stop all workers, replace the shared secret, and restart them
together.

Each process can use up to 15 main database connections and reserves 2 more in
an isolated, prewarmed limiter pool. PostgreSQL therefore needs at least 17
connections per process plus headroom for migrations, administration,
monitoring, and recovery. Pool checkout, database connection, statement, and
lock waits are bounded; if a trustworthy limiter decision cannot be completed,
the request is denied. Real PostgreSQL tests fill each pool and confirm that the
other remains usable.

## Future limiter database role

The dormant server contract separates normal application access from limiter
access. Configure these additional values only in a future server deployment:

| Variable | Meaning |
| --- | --- |
| `REDDOCK_RATE_LIMIT_DATABASE_USER` | Dedicated PostgreSQL login for limiter decisions |
| `REDDOCK_RATE_LIMIT_DATABASE_PASSWORD_FILE` | In-container path to that login's UTF-8 password secret |
| `REDDOCK_SERVER_WORKERS` | Total server process count, from 1 through 64 |

The limiter username must differ from `REDDOCK_DATABASE_USER`, and its password
must differ from the main database password. RedDock rejects either form of
credential reuse. Each future process still receives both secrets because it
owns both pools, so this separation reduces database authority rather than
creating a process-level secret boundary.

Set `REDDOCK_SERVER_WORKERS` to the actual total process count across the whole
deployment, and give every process the same value. RedDock compares the role's
connection limit with that declaration. It cannot discover how many processes
the orchestrator actually launched.

Provision the role through deployment automation or an administrator session
after the application role has run migrations. RedDock migrations intentionally
do not create, own, or rotate PostgreSQL logins. At startup, RedDock checks that
the limiter identity has exactly this effective contract:

- direct `LOGIN NOINHERIT` with a connection limit exactly twice
  `REDDOCK_SERVER_WORKERS` and no role-level settings;
- no memberships, superuser, database creation, role creation, replication, or
  row-security bypass flags;
- `CONNECT` on the configured database, without temporary access, database
  creation, ownership, or grant options;
- `USAGE` only on the `public` schema, without creation, ownership, or grant
  options;
- `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on
  `public.rate_limit_buckets`, without ownership, grant options, truncate,
  references, trigger, maintenance privileges, column-level grants, row-level
  security, triggers, foreign keys, rewrite rules, or inheritance;
- `USAGE` only on `public.rate_limit_buckets_id_seq`, without ownership, select,
  update, or grant options; and
- no access to another connectable database;
- no ownership or privileges on unrelated non-system schemas, tables, views,
  columns, foreign tables, materialized views, sequences, or user-defined
  routines, including no ownership of standalone PostgreSQL types; and
- no large-object, database-parameter, tablespace-creation, foreign-wrapper, or
  foreign-server privileges.

PostgreSQL can provide database `CONNECT`, temporary-table access, and routine
execution through `PUBLIC`. Meeting this contract may require changing those
defaults. Review such changes for the whole deployment because altering a
`PUBLIC` grant affects every database role, not only RedDock.

Limiter connections fix their search path to `pg_catalog,public`. A missing,
overprivileged, underprivileged, inherited, or wrong role fails startup with a
generic limiter-unavailable error. This is a startup-time verification, not
continuous monitoring of later database changes.

Rotate the limiter password with a coordinated restart: stop every worker,
replace the mounted password secret, update the PostgreSQL role, and restart all
workers together. The HMAC key has its own full-stop rotation procedure above.
Database-wide connection capacity, consistent HMAC-key distribution, TLS, and
route integration remain separate release gates.

This profile is a validation milestone, not the final production topology.
Tenant ownership, the reviewed role-permission contract, backup tooling, and
cross-worker rate-limit and pool-isolation tests now exist. OIDC and session
route integration, TLS proxy configuration, metrics, disaster recovery drills,
database capacity planning, and authenticated end-to-end tests remain
mandatory. The current Compose files do not provision the limiter role, mount
its credentials, or enable server mode. Setting
`REDDOCK_DEPLOYMENT_MODE=server` remains explicitly rejected; PostgreSQL
configuration can never silently enable shared mode.
