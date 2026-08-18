# Architecture

## Phase 0 shape

```text
Browser → React UI (static files) → FastAPI → application service → SQLite
```

The production image builds the React/Vite application and serves it as static content from the same FastAPI process that exposes `/api`. A named Docker volume stores SQLite data at `/var/lib/reddock`. This deliberately avoids a reverse proxy, separate frontend service, queue, or remote dependency.

## Boundaries

- `backend/app/api`: HTTP validation and response mapping.
- `backend/app/services`: application behavior, currently Dockyard operations.
- `backend/app/models`: persistence mappings.
- `backend/app/schemas`: Pydantic input/output contracts.
- `frontend/src`: presentation and API client only.

## Future execution seam

Future tools remain behind a small adapter contract: `prepare`, `execute`, `parse`, `normalize`, and `collect_evidence`. An adapter is reached only after DockGuard validates scope and policy. No adapter framework is implemented in Phase 0 because no tools run yet.

```text
requested action → scope validation → policy validation → risk classification
→ optional approval → adapter → execution → evidence capture → audit event
```

## Evidence and AI boundaries

RedLedger will distinguish an **Observation** (a recorded signal), **Finding** (a normalized potential issue), and **Validated Finding** (a policy-approved conclusion supported by evidence). Future evidence retains provenance, timestamps, raw and normalized artifacts, validation state, confidence, asset linkage, and artifact hashes.

AI is optional. It may propose structured actions, but DockGuard evaluates them before any approved execution mechanism receives them. RedDock must remain useful with no AI provider configured.

## Persistence evolution

Database setup is isolated in `backend/app/database.py` and each domain model owns its table definition. `create_all` is suitable for this empty initial schema; before a destructive schema change, introduce versioned Alembic migrations rather than changing deployed tables in place.

