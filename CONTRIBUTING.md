# Contributing

Thanks for helping build RedDock. Please keep contributions small, tested, and aligned with the safety model.

## Local checks

```bash
cd backend && pip install -e ".[dev]" && ruff check app tests && pytest
cd frontend && npm ci && npm run check && npm run test && npm run build
docker compose build
```

## Guidelines

- Do not add scanning, exploitation, credential attacks, or autonomous execution without an approved phase and DockGuard design.
- Preserve the API/domain/persistence/UI boundaries.
- Add tests for observable behavior and update documentation when behavior changes.
- Use clear names and explain non-obvious safety decisions.

