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

The current runtime uses the configured application database credentials to
build this dormant capability. A production server still needs a separate
least-privilege role with only the schema, table, and sequence access required
for `rate_limit_buckets`. This role, capacity planning, and route integration
remain release gates.

This profile is a validation milestone, not the final production topology.
Tenant ownership, the reviewed role-permission contract, backup tooling, and
cross-worker rate-limit and pool-isolation tests now exist. OIDC and session
route integration, a least-privilege limiter role, TLS proxy configuration,
metrics, disaster recovery drills, and authenticated end-to-end tests remain
mandatory. Setting `REDDOCK_DEPLOYMENT_MODE=server` is explicitly rejected until
those controls are implemented; PostgreSQL configuration can never silently
enable shared mode.
