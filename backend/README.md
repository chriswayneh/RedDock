# RedDock backend

This package contains RedDock Core's FastAPI application: the API, DockGuard scope enforcement, the discovery adapters, and SQLite persistence. Run it via the repository's Docker Compose workflow, or install it locally for development with Python 3.13.

```text
app/targets.py      target parsing and normalization
app/dockguard.py    scope evaluation and decisions
app/services.py     Dockyard and scope operations
app/inventory.py    asset, service, and observation persistence rules
app/discovery/      adapter contract, adapters, registry, and run orchestration
app/evidence.py     hashed evidence storage
```
