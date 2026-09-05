import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    """Runtime settings kept intentionally small for the local foundation."""

    app_name: str = "RedDock"
    version: str = "0.6.0"
    phase: str = "Phase 5 — Intelligence"
    database_url: str = "sqlite:///./data/reddock.db"
    evidence_dir: str = "./data/evidence"
    nmap_path: str | None = None
    # Optional, local, and off unless an operator supplies it. RedDock never
    # downloads CVE data; see app/detection/enrichment.py.
    cve_catalog_path: str | None = None
    # Phase 5 is disabled unless the operator supplies a trusted process-level
    # OpenAI-compatible endpoint and model. The API never accepts provider
    # destinations or credentials.
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    llm_timeout_seconds: int = 60

    # Scope and execution bounds. These are constants rather than environment
    # settings because relaxing them would weaken the exact guarantees
    # DockGuard exists to provide; an operator who needs a wider engagement
    # adds more narrow scope entries instead of one broad one.
    max_scope_entries: int = 64
    max_network_addresses: int = 256  # IPv4 /24 or IPv6 /120
    max_concurrent_runs: int = 2
    max_run_seconds: int = 600
    max_evidence_bytes: int = 2 * 1024 * 1024
    max_resolved_addresses: int = 4

    # Phase 2 detection bounds. Detection only reads what RedDock already
    # stored, so these bound work rather than reach: a snapshot cannot grow
    # without limit, a detector cannot flood the findings table, and a finding
    # cannot drag an unbounded number of evidence links behind it.
    max_detection_assets: int = 2_000
    max_detection_observations: int = 20_000
    max_findings_per_detector: int = 500
    max_evidence_per_finding: int = 20
    max_cve_catalog_bytes: int = 5 * 1024 * 1024
    max_cve_catalog_entries: int = 20_000

    # Phase 3 validation is intentionally narrower than discovery: one
    # approved HTTP-origin recheck, with the existing fixed request profile.
    max_validation_runs_per_dockyard: int = 500

    # Phase 4 only relates already-stored records. A fixed edge bound prevents
    # a dense Dockyard from turning one correlation request into unbounded work.
    max_correlation_assets: int = 2_000
    max_correlation_findings: int = 2_000
    max_correlation_edges: int = 5_000

    # Intelligence receives a bounded projection of stored, evidence-linked
    # findings. These constants cannot be relaxed through environment input.
    max_intelligence_findings: int = 200
    max_intelligence_input_bytes: int = 512 * 1024
    max_intelligence_runs_per_dockyard: int = 200


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
        cve_catalog_path=os.getenv("REDDOCK_CVE_CATALOG") or None,
        llm_base_url=os.getenv("REDDOCK_LLM_BASE_URL") or None,
        llm_model=os.getenv("REDDOCK_LLM_MODEL") or None,
        llm_api_key=os.getenv("REDDOCK_LLM_API_KEY") or None,
    )
