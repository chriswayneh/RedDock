"""Execute already-validated, data-only rules over an immutable snapshot.

Manifest filesystem access and validation live outside the detection package.
This module receives only frozen value objects and therefore preserves the same
no-I/O detector boundary as RedDock's built-ins.
"""

import json
from dataclasses import dataclass
from hashlib import sha256

from app.detection.base import (
    DetectedFinding,
    DetectionContext,
    Detector,
    FindingCategory,
    FindingConfidence,
    ObservationView,
    Severity,
)

PLUGIN_SCHEMA = "reddock.detector-plugin/1"


@dataclass(frozen=True, slots=True)
class DeclarativeRule:
    id: str
    observation_type: str
    detail_key: str
    equals: str | int | bool
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    remediation: str | None = None


class DeclarativeDetector(Detector):
    """A compiled, data-only manifest that uses RedDock's detector contract."""

    source = "declarative"
    execution = "passive"

    def __init__(
        self,
        *,
        detector_id: str,
        version: str,
        title: str,
        description: str,
        rules: tuple[DeclarativeRule, ...],
        manifest_sha256: str,
        finding_limit: int,
    ):
        self.id = detector_id
        self.version = f"{version}+{manifest_sha256[:12]}"
        self.title = title
        self.description = description
        self.rules = tuple(sorted(rules, key=lambda item: item.id))
        self.consumes = tuple(sorted({rule.observation_type for rule in self.rules}))
        self.manifest_sha256 = manifest_sha256
        self.finding_limit = finding_limit

    def detect(self, context: DetectionContext) -> tuple[DetectedFinding, ...]:
        findings: list[DetectedFinding] = []
        for rule in self.rules:
            latest = _latest_by_subject(context.of_type(rule.observation_type))
            for observation in latest.values():
                if not _scalar_equal(observation.detail.get(rule.detail_key), rule.equals):
                    continue
                findings.append(_finding(rule, observation))
                if len(findings) > self.finding_limit:
                    return tuple(findings)
        return tuple(findings)


def _latest_by_subject(
    observations: tuple[ObservationView, ...],
) -> dict[tuple[int | None, int | None], ObservationView]:
    latest: dict[tuple[int | None, int | None], ObservationView] = {}
    for observation in observations:
        subject = (observation.asset_id, observation.service_id)
        current = latest.get(subject)
        if current is None or (observation.observed_at, observation.id) >= (
            current.observed_at,
            current.id,
        ):
            latest[subject] = observation
    return latest


def _scalar_equal(observed: object, expected: str | int | bool) -> bool:
    """JSON booleans and integers compare equal in Python; plugin matches must not."""
    return type(observed) is type(expected) and observed == expected


def _finding(rule: DeclarativeRule, observation: ObservationView) -> DetectedFinding:
    match_key = json.dumps(rule.equals, ensure_ascii=True, separators=(",", ":"))
    scope_key = (
        f"{observation.asset_id or 0}:{observation.service_id or 0}:"
        f"{rule.observation_type}:{rule.detail_key}:{sha256(match_key.encode()).hexdigest()[:12]}"
    )
    return DetectedFinding(
        rule_id=rule.id,
        title=rule.title,
        description=rule.description,
        category=FindingCategory(rule.category),
        severity=Severity(rule.severity),
        confidence=FindingConfidence(rule.confidence),
        evidence_observation_ids=(observation.id,),
        asset_id=observation.asset_id,
        service_id=observation.service_id,
        scope_key=scope_key,
        remediation=rule.remediation,
        detail={
            "plugin_schema": PLUGIN_SCHEMA,
            "observation_type": rule.observation_type,
            "detail_key": rule.detail_key,
            "expected": rule.equals,
            "observed": observation.detail.get(rule.detail_key),
            "discovery_run_id": observation.discovery_run_id,
        },
    )
