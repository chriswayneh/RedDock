from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field

from app.detection.base import OPERATOR_STATUSES, FindingStatus
from app.dockguard import ScopeRuleType


def _as_utc(value: datetime) -> datetime:
    """Timestamps are stored in UTC; say so explicitly on the wire."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_as_utc)]


class DockyardCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120, examples=["Q3 web application review"])
    description: str | None = Field(default=None, max_length=2_000)


class DockyardRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    status: str
    created_at: UtcDatetime
    updated_at: UtcDatetime


class ScopeEntryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: ScopeRuleType = Field(default=ScopeRuleType.INCLUDE)
    target: str = Field(min_length=1, max_length=255, examples=["192.168.1.0/24"])
    note: str | None = Field(default=None, max_length=255)


class ScopeEntryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule: str
    kind: str
    value: str
    note: str | None
    created_at: UtcDatetime


class ScopeEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=255, examples=["192.168.1.10"])
    resolve: bool = Field(
        default=False,
        description="Resolve named targets so exclusions can be checked against addresses.",
    )


class ScopeEvaluationRead(BaseModel):
    decision: str
    target: str
    reason: str
    normalized_target: str | None = None
    target_kind: str | None = None
    matched_rule: str | None = None
    resolved_addresses: list[str] = Field(default_factory=list)
    excluded_addresses: list[str] = Field(default_factory=list)
    allowed: bool


class ServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    transport: str
    port: int
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    first_seen: UtcDatetime
    last_seen: UtcDatetime


class ServiceRowRead(ServiceRead):
    """A service with enough asset context to render a Dockyard-wide table."""

    asset_label: str


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_type: str
    identity: str
    display_name: str
    ip_address: str | None
    hostname: str | None
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    service_count: int = 0


class AssetDetailRead(AssetRead):
    services: list[ServiceRead] = Field(default_factory=list)


class ObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    discovery_run_id: int | None
    asset_id: int | None
    service_id: int | None
    adapter: str
    observation_type: str
    summary: str
    detail: dict | None
    confidence: str
    raw_reference: str | None
    observed_at: UtcDatetime


class DiscoveryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=255, examples=["127.0.0.1"])
    adapter: str = Field(max_length=32, examples=["nmap"])
    profile: str = Field(max_length=32, examples=["service_discovery"])


class DiscoveryRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    dockyard_id: int
    adapter: str
    adapter_version: str
    profile: str
    requested_target: str
    normalized_target: str | None
    status: str
    decision: str
    decision_reason: str
    error: str | None
    asset_count: int
    service_count: int
    observation_count: int
    evidence_path: str | None
    created_at: UtcDatetime
    started_at: UtcDatetime | None
    completed_at: UtcDatetime | None


class EvidenceRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    discovery_run_id: int
    kind: str
    relative_path: str
    media_type: str
    size_bytes: int
    sha256: str
    truncated: bool
    created_at: UtcDatetime


def _operator_status(value: FindingStatus) -> FindingStatus:
    """`resolved` is RedDock's answer, not an operator's."""
    if value not in OPERATOR_STATUSES:
        allowed = ", ".join(str(status) for status in OPERATOR_STATUSES)
        raise ValueError(f"A finding status may be set to one of: {allowed}")
    return value


OperatorStatus = Annotated[FindingStatus, AfterValidator(_operator_status)]


def _as_list(value: object) -> object:
    """A finding with no enrichment stores null; the wire says empty."""
    return value if value is not None else []


class DetectionCreate(BaseModel):
    """A detection request carries nothing.

    Every registered detector runs over everything the Dockyard already
    recorded. There is no target, no detector selection and no option, so there
    is no operator-supplied value for a detector to act on.
    """

    model_config = ConfigDict(extra="forbid")


class DetectionRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    dockyard_id: int
    status: str
    detectors: list[dict] | None
    enrichment: dict | None
    asset_count: int
    service_count: int
    observation_count: int
    finding_count: int
    new_finding_count: int
    resolved_finding_count: int
    error: str | None
    evidence_path: str | None
    metadata_sha256: str | None
    result_sha256: str | None
    created_at: UtcDatetime
    started_at: UtcDatetime | None
    completed_at: UtcDatetime | None


class CveReferenceRead(BaseModel):
    cve_id: str
    source: str
    source_version: str | None = None
    match_type: str
    matched_product: str
    matched_version: str
    url: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    fingerprint: str
    detector: str
    detector_version: str
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    status_note: str | None
    asset_id: int | None
    service_id: int | None
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    resolved_at: UtcDatetime | None
    first_detection_run_id: int | None
    last_detection_run_id: int | None
    cve_references: Annotated[list[CveReferenceRead], BeforeValidator(_as_list)] = Field(
        default_factory=list
    )
    asset_label: str | None = None
    service_endpoint: str | None = None
    evidence_count: int = 0


class FindingEvidenceRead(BaseModel):
    """One observation that supported a finding, with the hash that proves it."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    observation_id: int
    discovery_run_id: int | None
    detection_run_id: int | None
    evidence_record_id: int | None
    summary: str
    created_at: UtcDatetime
    evidence_path: str | None = None
    sha256: str | None = None


class FindingDetailRead(FindingRead):
    description: str
    remediation: str | None
    detail: dict | None
    evidence: list[FindingEvidenceRead] = Field(default_factory=list)


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: OperatorStatus
    note: str | None = Field(default=None, max_length=255)


class DetectorRead(BaseModel):
    id: str
    version: str
    title: str
    description: str
    consumes: list[str]


class ProfileRead(BaseModel):
    name: str
    title: str
    description: str


class AdapterRead(BaseModel):
    name: str
    version: str
    title: str
    description: str
    profiles: list[ProfileRead]
    target_kinds: list[str]


class HealthRead(BaseModel):
    status: str
    service: str


class VersionRead(BaseModel):
    name: str
    version: str
    phase: str
