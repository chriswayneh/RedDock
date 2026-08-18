from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

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
