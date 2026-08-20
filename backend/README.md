# RedDock backend

This package contains RedDock Core's FastAPI application: the API, DockGuard scope enforcement, the discovery adapters, the detectors, and SQLite persistence. Run it via the repository's Docker Compose workflow, or install it locally for development with Python 3.13.

```text
app/targets.py      target parsing and normalization
app/dockguard.py    scope evaluation and decisions
app/services.py     Dockyard and scope operations
app/inventory.py    asset, service, and observation persistence rules
app/discovery/      adapter contract, adapters, registry, and run orchestration
app/detection/      detector contract, detectors, registry, enrichment, and run orchestration
app/findings.py     finding persistence, deduplication, and lifecycle rules
app/validation/     approval-gated, fixed HTTP-origin validation orchestration
app/evidence.py     hashed evidence storage
```

A discovery adapter may contact a target after DockGuard allows it. A detector
may not contact anything: it is handed a frozen snapshot of one Dockyard and
returns value objects, with no session, socket, subprocess or operator input in
reach. `tests/test_detection_contract.py` reads the detection package and fails
if that stops being true.

Validation is not a general-purpose testing interface. It can recheck only an
eligible open HTTP security-header finding at its recorded origin. Requesting
one records intent without contacting a target; a separate approval note
re-evaluates DockGuard and then reuses the fixed, bodyless HTTP probe. The
raw result, normalized conclusion, metadata, and manifest are retained with
SHA-256 hashes.
