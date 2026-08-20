"""Phase 3 validation orchestration.

Validation is deliberately smaller than discovery. It can only recheck an
existing HTTP security-header finding, at the finding's already-recorded origin,
with the same bounded probe RedDock uses for discovery. An operator must create
the request and then approve it in a separate action. DockGuard runs at both
steps and again immediately before the one origin is contacted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.discovery.base import AdapterRequest
from app.discovery.http_probe import HttpProbeAdapter
from app.dockguard import Evaluation, evaluate, system_resolver
from app.evidence import EVIDENCE_SCHEMA, VALIDATION_SCOPE, EvidenceStore
from app.models import Asset, Finding, ValidationRun
from app.services import scope_rules
from app.targets import Target, TargetKind, normalize_target

PENDING_APPROVAL = "pending_approval"
RUNNING = "running"
COMPLETED = "completed"
DENIED = "denied"
FAILED = "failed"

CONFIRMED = "confirmed"
NOT_REPRODUCED = "not_reproduced"
INDETERMINATE = "indeterminate"

VALIDATOR_ID = "http.origin_recheck"
VALIDATOR_VERSION = "1.0.0"

_HTTP_RULES = frozenset(
    {
        "plaintext-http",
        "hsts-not-set",
        "content-type-options-not-nosniff",
        "content-security-policy-not-set",
        "frame-protection-not-set",
    }
)
_CONTENT_RULES = frozenset(
    {
        "content-type-options-not-nosniff",
        "content-security-policy-not-set",
        "frame-protection-not-set",
    }
)


class ValidationRejected(ValueError):
    """Raised when RedDock cannot safely create or approve a validation."""


@dataclass(frozen=True, slots=True)
class ValidationResult:
    outcome: str
    confidence: str
    summary: str
    detail: dict[str, object]
    raw: bytes


def validation_target(session: Session, finding: Finding) -> Target:
    """Return the one origin a finding is allowed to recheck, or refuse it."""
    if finding.detector != "http.security_headers" or finding.rule_id not in _HTTP_RULES:
        raise ValidationRejected(
            "This finding has no Phase 3 non-destructive validation profile"
        )
    if finding.asset_id is None:
        raise ValidationRejected("This finding is not linked to an HTTP origin")
    asset = session.get(Asset, finding.asset_id)
    if asset is None or asset.dockyard_id != finding.dockyard_id:
        raise ValidationRejected("The HTTP origin recorded for this finding is unavailable")
    target = normalize_target(asset.identity)
    if target.kind is not TargetKind.URL:
        raise ValidationRejected("This finding is not linked to an HTTP or HTTPS origin")
    return target


def create_run(session: Session, dockyard_id: int, finding: Finding) -> ValidationRun:
    """Persist a validation request and its first DockGuard decision.

    Denied requests are retained. They prove that a requested recheck did not
    reach a target; a missing row would not provide that assurance.
    """
    if finding.dockyard_id != dockyard_id:
        raise ValidationRejected("Finding does not belong to this Dockyard")
    if finding.status != "open":
        raise ValidationRejected("Only an open finding may be validated")
    _within_validation_limit(session, dockyard_id)
    target = validation_target(session, finding)
    evaluation = _evaluate(session, dockyard_id, target)
    now = datetime.now(UTC)
    run = ValidationRun(
        dockyard_id=dockyard_id,
        finding_id=finding.id,
        validator=VALIDATOR_ID,
        validator_version=VALIDATOR_VERSION,
        target=target.value,
        status=PENDING_APPROVAL if evaluation.allowed else DENIED,
        decision=str(evaluation.decision),
        decision_reason=evaluation.reason[:500],
        completed_at=None if evaluation.allowed else now,
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def approve_run(
    session: Session, dockyard_id: int, run_id: int, approval_note: str
) -> ValidationRun:
    """Apply the second, explicit approval gate and perform one safe recheck."""
    run = get_run(session, dockyard_id, run_id)
    if run is None:
        raise ValidationRejected("Validation run not found")
    if run.status != PENDING_APPROVAL:
        raise ValidationRejected("Only a pending validation may be approved")

    finding = session.get(Finding, run.finding_id)
    if finding is None or finding.dockyard_id != dockyard_id:
        raise ValidationRejected("Finding for this validation is no longer available")
    target = validation_target(session, finding)
    evaluation = _evaluate(session, dockyard_id, target)
    run.approval_note = approval_note
    run.approved_at = datetime.now(UTC)
    run.decision = str(evaluation.decision)
    run.decision_reason = evaluation.reason[:500]
    if not evaluation.allowed:
        run.status = DENIED
        run.completed_at = datetime.now(UTC)
        session.commit()
        return run

    run.status = RUNNING
    run.started_at = datetime.now(UTC)
    session.commit()
    try:
        result = _validate(finding, target, evaluation)
        _store_evidence(session, run, finding, evaluation, result)
        run.outcome = result.outcome
        run.confidence = result.confidence
        run.summary = result.summary[:500]
        run.detail = result.detail
        run.status = COMPLETED
    except Exception as error:  # A failed check is recorded and never reported as a conclusion.
        run.status = FAILED
        run.error = f"Validation failed: {type(error).__name__}"[:500]
    run.completed_at = datetime.now(UTC)
    session.commit()
    session.refresh(run)
    return run


def list_runs(session: Session, dockyard_id: int, limit: int) -> list[ValidationRun]:
    statement = (
        select(ValidationRun)
        .where(ValidationRun.dockyard_id == dockyard_id)
        .order_by(ValidationRun.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))


def list_for_finding(session: Session, finding_id: int, limit: int = 100) -> list[ValidationRun]:
    statement = (
        select(ValidationRun)
        .where(ValidationRun.finding_id == finding_id)
        .order_by(ValidationRun.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))


def get_run(session: Session, dockyard_id: int, run_id: int) -> ValidationRun | None:
    return session.scalar(
        select(ValidationRun).where(
            ValidationRun.id == run_id, ValidationRun.dockyard_id == dockyard_id
        )
    )


def _within_validation_limit(session: Session, dockyard_id: int) -> None:
    count = session.scalar(
        select(func.count())
        .select_from(ValidationRun)
        .where(ValidationRun.dockyard_id == dockyard_id)
    ) or 0
    if count >= get_settings().max_validation_runs_per_dockyard:
        raise ValidationRejected("This Dockyard has reached its validation-run limit")


def _evaluate(session: Session, dockyard_id: int, target: Target) -> Evaluation:
    return evaluate(target.value, scope_rules(session, dockyard_id), resolver=system_resolver)


def _validate(finding: Finding, target: Target, evaluation: Evaluation) -> ValidationResult:
    """Reuse the fixed HTTP probe; validation adds no new network primitive."""
    probe = HttpProbeAdapter()
    result = probe.run(
        AdapterRequest(
            target=target,
            profile="http_probe",
            resolved_addresses=evaluation.resolved_addresses,
            timeout_seconds=get_settings().max_run_seconds,
        )
    )
    response = next(
        (
            observation
            for observation in result.observations
            if observation.observation_type == "http_response"
        ),
        None,
    )
    headers = {
        str(observation.detail.get("header", "")).lower(): str(observation.detail.get("value", ""))
        for observation in result.observations
        if observation.observation_type == "http_header"
    }
    raw = result.artifacts[0].content if result.artifacts else b"{}"
    if response is None or not isinstance(response.detail.get("status"), int):
        return ValidationResult(
            outcome=INDETERMINATE,
            confidence="low",
            summary=f"RedDock could not obtain an HTTP response from {target.value}",
            detail={"rule_id": finding.rule_id, "headers": headers, "reachable": False},
            raw=raw,
        )

    status = int(response.detail["status"])
    outcome, confidence, summary = _judge(finding.rule_id, target, status, headers)
    return ValidationResult(
        outcome=outcome,
        confidence=confidence,
        summary=summary,
        detail={
            "rule_id": finding.rule_id,
            "target": target.value,
            "status": status,
            "headers_examined": sorted(headers),
            "address": response.detail.get("address"),
        },
        raw=raw,
    )


def _judge(
    rule_id: str, target: Target, status: int, headers: dict[str, str]
) -> tuple[str, str, str]:
    if rule_id == "plaintext-http":
        redirected = 300 <= status < 400 and headers.get("location", "").lower().startswith("https://")
        if redirected:
            return NOT_REPRODUCED, "high", "The origin now redirects plaintext HTTP to HTTPS"
        return (
            CONFIRMED,
            "high",
            f"The origin still answered over plaintext HTTP with HTTP {status}",
        )

    if rule_id in _CONTENT_RULES and not _content_response(status):
        return (
            INDETERMINATE,
            "medium",
            f"HTTP {status} is not a normal content response for this check",
        )

    if rule_id == "hsts-not-set":
        present = "strict-transport-security" in headers
        return _presence_result(present, "Strict-Transport-Security")
    if rule_id == "content-security-policy-not-set":
        return _presence_result("content-security-policy" in headers, "Content-Security-Policy")
    if rule_id == "content-type-options-not-nosniff":
        valid = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
        return _presence_result(valid, "X-Content-Type-Options: nosniff")
    if rule_id == "frame-protection-not-set":
        protected = "x-frame-options" in headers or "frame-ancestors" in headers.get(
            "content-security-policy", ""
        ).lower()
        return _presence_result(protected, "a framing restriction")
    raise ValidationRejected("This finding has no Phase 3 non-destructive validation profile")


def _presence_result(present: bool, label: str) -> tuple[str, str, str]:
    if present:
        return NOT_REPRODUCED, "high", f"The response now carries {label}"
    return CONFIRMED, "high", f"The response still does not carry {label}"


def _content_response(status: int) -> bool:
    return status < 300 or 400 <= status < 500


def _store_evidence(
    session: Session,
    run: ValidationRun,
    finding: Finding,
    evaluation: Evaluation,
    result: ValidationResult,
) -> None:
    store = EvidenceStore()
    raw = store.write_raw(
        run.dockyard_id,
        run.id,
        "http-recheck.json",
        "application/json",
        result.raw,
        scope=VALIDATION_SCOPE,
    )
    normalized = store.write_normalized(
        run.dockyard_id,
        run.id,
        {
            "finding": {
                "id": finding.id,
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
            },
            "outcome": result.outcome,
            "confidence": result.confidence,
            "summary": result.summary,
            "detail": result.detail,
        },
        scope=VALIDATION_SCOPE,
    )
    metadata = store.write_metadata(
        run.dockyard_id,
        run.id,
        {
            "schema": EVIDENCE_SCHEMA,
            "kind": "validation",
            "dockyard_id": run.dockyard_id,
            "validation_run_id": run.id,
            "finding_id": finding.id,
            "validator": {"id": run.validator, "version": run.validator_version},
            "target": run.target,
            "approval": {"note": run.approval_note, "approved_at": _iso(run.approved_at)},
            "dockguard": {
                "decision": str(evaluation.decision),
                "reason": evaluation.reason,
                "matched_rule": evaluation.matched_rule,
                "resolved_addresses": list(evaluation.resolved_addresses),
            },
            "started_at": _iso(run.started_at),
        },
        scope=VALIDATION_SCOPE,
    )
    manifest = store.write_raw(
        run.dockyard_id,
        run.id,
        "manifest.json",
        "application/json",
        _manifest(raw, normalized, metadata),
        scope=VALIDATION_SCOPE,
    )
    run.evidence_path = store.relative_run_path(run.dockyard_id, run.id, VALIDATION_SCOPE)
    run.metadata_sha256 = metadata.sha256
    run.result_sha256 = normalized.sha256
    run.manifest_sha256 = manifest.sha256
    session.commit()


def _manifest(*artifacts) -> bytes:
    import json

    return json.dumps(
        {
            "schema": "reddock.validation-package/1",
            "artifacts": [
                {
                    "kind": artifact.kind,
                    "path": artifact.relative_path,
                    "media_type": artifact.media_type,
                    "bytes": artifact.size_bytes,
                    "sha256": artifact.sha256,
                    "truncated": artifact.truncated,
                }
                for artifact in artifacts
            ],
        },
        indent=2,
        sort_keys=True,
    ).encode()


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).isoformat()
