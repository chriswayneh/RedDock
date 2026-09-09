# Contributing

Trying the app rather than changing its code? Start with the [first-run guide](docs/GETTING_STARTED.md). For a guided view of the repository, use the [documentation index](docs/README.md). The commands below are developer checks, not installation steps for ordinary users.

RedDock is open source under the MIT License, but it does not currently accept
unsolicited external pull requests. The safety model and phase boundaries are
owner-directed and intentionally closed. Bug reports, design discussion, and
responsible security disclosures remain welcome; accepted implementation work
follows the checks and constraints below.

## Attribution

Keep the human author's Git identity. Credit only the assistants that actually
helped with the change. For Codex-assisted commits, add this GitHub-linked
trailer after a blank line in the commit message:

```text
Co-authored-by: Codex <codex@openai.com>
```

GitHub associates that email with [Codex](https://github.com/codex), OpenAI's
coding agent. Preserve Claude's existing credits and use its verified
co-author identity for work it assists. An `AI-assisted-by` note may provide
additional context, but does not replace GitHub's `Co-authored-by` field.
Tool attribution does not imply vendor endorsement. Do not rewrite existing
history merely to normalize these credits.

## Local checks

```bash
cd backend && pip install -e ".[dev]" && pip-audit --progress-spinner off . && ruff check app tests && pytest
cd frontend && npm ci && npm run lint && npm run check && npm run test && npm run build
docker compose build
```

Backend development needs Python 3.13; running RedDock itself needs only Docker. To verify the complete discovery-through-reporting path end to end against loopback:

```bash
docker compose up -d --build && python scripts/smoke_test.py
```

### Development dependency follow-up

The September 8 audit still reports the moderate
[Vitest mocker advisory](https://github.com/advisories/GHSA-82fw-gwwq-j7x9)
against Vitest 3.2.7. Its fix requires a separately tested major upgrade to
4.1.11 or later. RedDock uses `vitest run` with jsdom, does not register the
standalone mocker/interceptor plugins, and does not ship Node or test packages
in the final Python runtime image. Do not expose a test or development server
to the network. This follow-up is not an accepted-risk waiver or a clean audit;
the existing high-severity CI gate remains unchanged.

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
