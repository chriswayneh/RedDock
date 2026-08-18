import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    """Runtime settings kept intentionally small for the local foundation."""

    app_name: str = "RedDock"
    version: str = "0.2.0"
    phase: str = "Phase 1 — Discovery"
    database_url: str = "sqlite:///./data/reddock.db"
    evidence_dir: str = "./data/evidence"
    nmap_path: str | None = None

    # Phase 1 safety bounds. These are constants rather than environment
    # settings because relaxing them would weaken the exact guarantees
    # DockGuard exists to provide; an operator who needs a wider engagement
    # adds more narrow scope entries instead of one broad one.
    max_scope_entries: int = 64
    max_network_addresses: int = 256  # IPv4 /24 or IPv6 /120
    max_concurrent_runs: int = 2
    max_run_seconds: int = 600
    max_evidence_bytes: int = 2 * 1024 * 1024
    max_resolved_addresses: int = 4


@lru_cache
def get_settings() -> Settings:
    defaults = Settings()
    database_url = os.getenv("REDDOCK_DATABASE_URL", defaults.database_url)
    if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite:////"):
        Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    return Settings(
        database_url=database_url,
        evidence_dir=os.getenv("REDDOCK_EVIDENCE_DIR", defaults.evidence_dir),
        nmap_path=os.getenv("REDDOCK_NMAP_PATH") or None,
    )
