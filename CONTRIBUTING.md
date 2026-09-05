# Contributing

RedDock is open source under the MIT License, but it does not currently accept
unsolicited external pull requests. The safety model and phase boundaries are
owner-directed and intentionally closed. Bug reports, design discussion, and
responsible security disclosures remain welcome; accepted implementation work
follows the checks and constraints below.

## Local checks

```bash
cd backend && pip install -e ".[dev]" && ruff check app tests && pytest
cd frontend && npm ci && npm run lint && npm run check && npm run test && npm run build
docker compose build
```

Backend development needs Python 3.13; running RedDock itself needs only Docker. To verify the complete discovery-through-reporting path end to end against loopback:

```bash
docker compose up -d --build && python scripts/smoke_test.py
```

## Guidelines

- Do not add exploitation, credential attacks, active vulnerability testing, or autonomous execution without an approved phase and DockGuard design.
- Every target must reach a tool through DockGuard. Never pass operator-supplied values to a subprocess as flags, and never build a command string.
- An adapter records what was observed. A detector says what it means, from stored observations only: it may not open a socket, start a process or reach the database, and a finding it produces must cite the observations behind it.
- A report reads retained state only. Do not add a target, arbitrary source selector, output path, network request, dynamic template, or executable archive member; every included source artifact must be database-referenced and hash-verified.
- Do not inflate a rating. A missing hardening header is not a high, a version banner is not a vulnerability, and a CVE association is not a test result.
- Preserve the API/domain/persistence/UI boundaries.
- Add tests for observable behavior and update documentation when behavior changes.
- Use clear names and explain non-obvious safety decisions.

Opening an issue or discussion does not authorize active testing against any
system. Report suspected vulnerabilities through the private process described
in [SECURITY.md](SECURITY.md), not in a public issue.
