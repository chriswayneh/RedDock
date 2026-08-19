# Contributing

Thanks for helping build RedDock. Please keep contributions small, tested, and aligned with the safety model.

## Local checks

```bash
cd backend && pip install -e ".[dev]" && ruff check app tests && pytest
cd frontend && npm ci && npm run lint && npm run check && npm run test && npm run build
docker compose build
```

Backend development needs Python 3.13; running RedDock itself needs only Docker. To verify the full discovery and detection path end to end against loopback:

```bash
docker compose up -d --build && python scripts/smoke_test.py
```

## Guidelines

- Do not add exploitation, credential attacks, active vulnerability testing, or autonomous execution without an approved phase and DockGuard design.
- Every target must reach a tool through DockGuard. Never pass operator-supplied values to a subprocess as flags, and never build a command string.
- An adapter records what was observed. A detector says what it means, from stored observations only: it may not open a socket, start a process or reach the database, and a finding it produces must cite the observations behind it.
- Do not inflate a rating. A missing hardening header is not a high, a version banner is not a vulnerability, and a CVE association is not a test result.
- Preserve the API/domain/persistence/UI boundaries.
- Add tests for observable behavior and update documentation when behavior changes.
- Use clear names and explain non-obvious safety decisions.

