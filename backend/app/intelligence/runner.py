"""Approval-gated Phase 5 intelligence over an immutable stored-data packet.

Creating a run contacts nothing. Approval may send the exact retained packet to
the operator-configured model provider. Model output is schema-validated and
stored as advice only; it cannot mutate findings or reach a RedDock action.
"""

import json
import logging
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_address
from threading import Lock
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.correlation.runner import latest_completed
from app.evidence import EVIDENCE_SCHEMA, INTELLIGENCE_SCOPE, NORMALIZED_FILE, EvidenceStore
from app.intelligence.providers import IntelligenceProvider, OpenAICompatibleProvider, ProviderError
from app.models import CorrelationRun, EvidenceRecord, Finding, FindingEvidence, IntelligenceRun

logger = logging.getLogger("reddock.intelligence")
ACTIVE_STATUSES = ("pending_approval", "running")
PROMPT_VERSION = "1"
_CREATE_LOCK = Lock()


class RunRejected(ValueError):
    """Raised when an intelligence run cannot safely be created or approved."""


class PriorityAdvice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: int
    priority: str = Field(pattern="^(urgent|high|normal|low)$")
    rationale: str = Field(min_length=1, max_length=1_000)
    remediation_steps: list[str] = Field(min_length=1, max_length=10)
    evidence_sha256: list[str] = Field(min_length=1, max_length=20)


class IntelligenceAdvice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2_000)
    priorities: list[PriorityAdvice] = Field(min_length=1, max_length=200)
    limitations: list[str] = Field(default_factory=list, max_length=20)


def provider_status() -> dict:
    provider = get_provider()
    if provider is None:
        return {
            "available": False,
            "provider": None,
            "model": None,
            "destination": None,
            "sends_data_external": False,
            "reason": (
                "Configure REDDOCK_LLM_BASE_URL and REDDOCK_LLM_MODEL to enable intelligence."
            ),
        }
    return {
        "available": True,
        "provider": provider.id,
        "model": provider.model,
        "destination": provider.destination,
        "sends_data_external": provider.sends_data_external,
        "reason": None,
    }


def get_provider() -> IntelligenceProvider | None:
    settings = get_settings()
    if not settings.llm_base_url or not settings.llm_model:
        return None
    parsed = urlsplit(settings.llm_base_url)
    host = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or len(settings.llm_base_url) > 500
        or len(settings.llm_model) > 120
    ):
        return None
    # `ollama` is the fixed service name in the optional, private Compose
    # bundle. It is never published on a host port. HTTP still fails closed if
    # a credential is configured, because bearer material must not cross it.
    local = host in {"localhost", "host.docker.internal", "ollama"}
    if not local:
        try:
            local = ip_address(host).is_loopback
        except ValueError:
            pass
    if (not local or settings.llm_api_key) and parsed.scheme != "https":
        return None
    return OpenAICompatibleProvider(
        base_url=settings.llm_base_url.rstrip("/"),
        model=settings.llm_model,
        api_key=settings.llm_api_key,
        timeout_seconds=settings.llm_timeout_seconds,
        sends_data_external=not local,
    )


def create_run(session: Session, dockyard_id: int) -> IntelligenceRun:
    # The supported deployment is one Uvicorn process. Serializing this short
    # reservation makes the active and retained-run bounds exact across its
    # request threads rather than check-then-insert races.
    with _CREATE_LOCK:
        return _create_run(session, dockyard_id)


def _create_run(session: Session, dockyard_id: int) -> IntelligenceRun:
    provider = get_provider()
    if provider is None:
        raise RunRejected("Intelligence is disabled until an operator configures a model provider")
    if session.scalar(
        select(func.count())
        .select_from(IntelligenceRun)
        .where(
            IntelligenceRun.dockyard_id == dockyard_id,
            IntelligenceRun.status.in_(ACTIVE_STATUSES),
        )
    ):
        raise RunRejected("An intelligence run is already awaiting approval or running")
    count = (
        session.scalar(
            select(func.count())
            .select_from(IntelligenceRun)
            .where(IntelligenceRun.dockyard_id == dockyard_id)
        )
        or 0
    )
    if count >= get_settings().max_intelligence_runs_per_dockyard:
        raise RunRejected("This Dockyard reached the fixed intelligence-run limit")

    correlation = latest_completed(session, dockyard_id)
    if correlation is None:
        raise RunRejected("Run correlation before creating an intelligence packet")
    packet = _packet(session, dockyard_id, correlation.id)
    if not packet["findings"]:
        raise RunRejected("No evidence-linked active findings are available for intelligence")
    encoded = _document_bytes(packet)
    if len(encoded) > get_settings().max_intelligence_input_bytes:
        raise RunRejected("The intelligence packet exceeds the fixed input size limit")

    run = IntelligenceRun(
        dockyard_id=dockyard_id,
        correlation_run_id=correlation.id,
        status="pending_approval",
        provider=provider.id,
        model=provider.model,
        destination=provider.destination,
        sends_data_external=provider.sends_data_external,
        prompt_version=PROMPT_VERSION,
        input=packet,
        input_sha256=sha256(encoded).hexdigest(),
    )
    session.add(run)
    session.flush()
    store = EvidenceStore()
    stored = store.write_normalized(dockyard_id, run.id, packet, INTELLIGENCE_SCOPE)
    run.evidence_path = store.relative_run_path(dockyard_id, run.id, INTELLIGENCE_SCOPE)
    run.input_sha256 = stored.sha256
    session.commit()
    session.refresh(run)
    return run


def approve_run(session: Session, dockyard_id: int, run_id: int, note: str) -> IntelligenceRun:
    run = get_run(session, dockyard_id, run_id)
    if run is None:
        raise RunRejected("Intelligence run not found")
    if run.status != "pending_approval":
        raise RunRejected("Only a pending intelligence run can be approved")
    if run.prompt_version != PROMPT_VERSION:
        raise RunRejected("Prompt version changed after the packet was created")
    _verify_retained_packet(run)
    provider = get_provider()
    if provider is None or _provider_identity(provider) != (
        run.provider,
        run.model,
        run.destination,
        run.sends_data_external,
    ):
        raise RunRejected("Provider configuration changed after the packet was created")
    claimed_at = datetime.now(UTC)
    claimed = session.execute(
        update(IntelligenceRun)
        .where(
            IntelligenceRun.id == run.id,
            IntelligenceRun.dockyard_id == dockyard_id,
            IntelligenceRun.status == "pending_approval",
            IntelligenceRun.prompt_version == PROMPT_VERSION,
        )
        .values(
            approval_note=note,
            approved_at=claimed_at,
            started_at=claimed_at,
            status="running",
        )
    )
    if claimed.rowcount != 1:
        session.rollback()
        raise RunRejected("Only a pending intelligence run can be approved")
    session.commit()
    session.refresh(run)
    try:
        raw = provider.analyze(dict(run.input or {}))
        advice = IntelligenceAdvice.model_validate(raw)
        _validate_advice(advice, dict(run.input or {}))
        result = {
            "schema": EVIDENCE_SCHEMA,
            "kind": "intelligence",
            "run_id": run.id,
            "prompt_version": PROMPT_VERSION,
            "advice": advice.model_dump(),
        }
        store = EvidenceStore()
        normalized = store.write_raw(
            dockyard_id,
            run.id,
            "advice.json",
            "application/json",
            _document_bytes(result),
            INTELLIGENCE_SCOPE,
        )
        metadata = store.write_metadata(
            dockyard_id,
            run.id,
            {
                "schema": EVIDENCE_SCHEMA,
                "kind": "intelligence",
                "dockyard_id": dockyard_id,
                "run_id": run.id,
                "correlation_run_id": run.correlation_run_id,
                "provider": run.provider,
                "model": run.model,
                "destination": run.destination,
                "sends_data_external": run.sends_data_external,
                "prompt_version": run.prompt_version,
                "approval_note": run.approval_note,
                "input_sha256": run.input_sha256,
                "artifacts": [{"path": normalized.relative_path, "sha256": normalized.sha256}],
            },
            INTELLIGENCE_SCOPE,
        )
        run.output = advice.model_dump()
        run.result_sha256 = normalized.sha256
        run.metadata_sha256 = metadata.sha256
        run.status = "completed"
    except (ProviderError, ValidationError, RunRejected) as error:
        run.status = "failed"
        run.error = str(error)[:500]
    except Exception:
        logger.exception("Intelligence run %s failed unexpectedly", run.id)
        run.status = "failed"
        run.error = "Intelligence failed unexpectedly; see the RedDock container log"
    run.completed_at = datetime.now(UTC)
    session.commit()
    session.refresh(run)
    return run


def list_runs(session: Session, dockyard_id: int, limit: int) -> list[IntelligenceRun]:
    return list(
        session.scalars(
            select(IntelligenceRun)
            .where(IntelligenceRun.dockyard_id == dockyard_id)
            .order_by(IntelligenceRun.id.desc())
            .limit(limit)
        )
    )


def get_run(session: Session, dockyard_id: int, run_id: int) -> IntelligenceRun | None:
    return session.scalar(
        select(IntelligenceRun).where(
            IntelligenceRun.dockyard_id == dockyard_id, IntelligenceRun.id == run_id
        )
    )


def recover_interrupted_runs(session: Session) -> int:
    rows = list(session.scalars(select(IntelligenceRun).where(IntelligenceRun.status == "running")))
    for run in rows:
        run.status = "failed"
        run.error = "Interrupted by a RedDock restart"
        run.completed_at = datetime.now(UTC)
    session.commit()
    return len(rows)


def _packet(session: Session, dockyard_id: int, correlation_run_id: int) -> dict:
    correlation = session.get(CorrelationRun, correlation_run_id)
    if correlation is None or not isinstance(correlation.graph, dict):
        raise RunRejected("The latest correlation snapshot is not available")
    snapshot_ids = {
        int(node["id"].removeprefix("finding:"))
        for node in correlation.graph.get("nodes", [])
        if isinstance(node, dict)
        and isinstance(node.get("id"), str)
        and node["id"].startswith("finding:")
        and node["id"].removeprefix("finding:").isdigit()
    }
    if not snapshot_ids:
        return {
            "schema": "reddock.intelligence-input/1",
            "purpose": "advice-only remediation and prioritization",
            "constraints": [
                "Stored evidence only; do not infer target contact or exploitability.",
                "Output cannot change findings, scope, tools, or validation state.",
            ],
            "dockyard_id": dockyard_id,
            "correlation_run_id": correlation_run_id,
            "findings": [],
        }
    findings = list(
        session.scalars(
            select(Finding)
            .where(
                Finding.dockyard_id == dockyard_id,
                Finding.id.in_(snapshot_ids),
                Finding.status.in_(("open", "accepted")),
            )
            .order_by(Finding.id)
            .limit(get_settings().max_intelligence_findings + 1)
        )
    )
    if len(findings) > get_settings().max_intelligence_findings:
        raise RunRejected("The Dockyard exceeds the fixed intelligence finding limit")
    evidence = _evidence_hashes(session, findings)
    rows = []
    for finding in findings:
        hashes = evidence.get(finding.id, [])
        if not hashes:
            continue
        rows.append(
            {
                "id": finding.id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "status": finding.status,
                "asset_id": finding.asset_id,
                "service_id": finding.service_id,
                "evidence_sha256": hashes,
            }
        )
    return {
        "schema": "reddock.intelligence-input/1",
        "purpose": "advice-only remediation and prioritization",
        "constraints": [
            "Stored evidence only; do not infer target contact or exploitability.",
            "Output cannot change findings, scope, tools, or validation state.",
        ],
        "dockyard_id": dockyard_id,
        "correlation_run_id": correlation_run_id,
        "findings": rows,
    }


def _evidence_hashes(session: Session, findings: list[Finding]) -> dict[int, list[str]]:
    if not findings:
        return {}
    statement = (
        select(FindingEvidence.finding_id, EvidenceRecord.sha256)
        .join(EvidenceRecord, EvidenceRecord.id == FindingEvidence.evidence_record_id)
        .where(FindingEvidence.finding_id.in_([item.id for item in findings]))
        .order_by(FindingEvidence.finding_id, FindingEvidence.id)
    )
    result: dict[int, list[str]] = {}
    for finding_id, digest in session.execute(statement):
        values = result.setdefault(finding_id, [])
        if digest not in values and len(values) < 20:
            values.append(digest)
    return result


def _validate_advice(advice: IntelligenceAdvice, packet: dict) -> None:
    allowed = {
        int(item["id"]): set(item["evidence_sha256"])
        for item in packet.get("findings", [])
        if isinstance(item, dict)
    }
    seen: set[int] = set()
    for priority in advice.priorities:
        if priority.finding_id in seen:
            raise RunRejected("The provider returned duplicate advice for one finding")
        if priority.finding_id not in allowed:
            raise RunRejected("The provider referenced a finding outside the approved packet")
        if not set(priority.evidence_sha256) <= allowed[priority.finding_id]:
            raise RunRejected("The provider referenced evidence outside the approved packet")
        if any(not step.strip() or len(step) > 500 for step in priority.remediation_steps):
            raise RunRejected("The provider returned an invalid remediation step")
        seen.add(priority.finding_id)
    if len(advice.summary) > 2_000 or any(len(item) > 500 for item in advice.limitations):
        raise RunRejected("The provider returned over-long advice")


def _provider_identity(provider: IntelligenceProvider) -> tuple[str, str, str, bool]:
    return provider.id, provider.model, provider.destination, provider.sends_data_external


def _verify_retained_packet(run: IntelligenceRun) -> None:
    packet_digest = sha256(_document_bytes(dict(run.input or {}))).hexdigest()
    if packet_digest != run.input_sha256 or not run.evidence_path:
        raise RunRejected("The retained intelligence packet failed integrity verification")
    store = EvidenceStore()
    packet_path = store.run_directory(run.dockyard_id, run.id, INTELLIGENCE_SCOPE) / NORMALIZED_FILE
    try:
        retained_digest = sha256(packet_path.read_bytes()).hexdigest()
    except OSError as error:
        raise RunRejected("The retained intelligence packet is unavailable") from error
    if retained_digest != run.input_sha256:
        raise RunRejected("The retained intelligence packet failed integrity verification")


def _document_bytes(document: dict) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True, default=str).encode()
