from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Dockyard(Base):
    """A bounded engagement workspace that owns an authorized scope."""

    __tablename__ = "dockyards"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scope_entries: Mapped[list["ScopeEntry"]] = relationship(
        back_populates="dockyard", cascade="all, delete-orphan"
    )


class ScopeEntry(Base):
    """One authorized inclusion or exclusion; the input DockGuard evaluates."""

    __tablename__ = "scope_entries"
    __table_args__ = (UniqueConstraint("dockyard_id", "rule", "value", name="uq_scope_entry"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    rule: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    dockyard: Mapped[Dockyard] = relationship(back_populates="scope_entries")


class Asset(Base):
    """Something observed inside an authorized Dockyard.

    Identity is deterministic: within one Dockyard an asset is the pair of its
    type and its normalized identity (an IP address for a host, an origin for a
    web asset), so repeated discovery updates a known asset instead of creating
    another one.
    """

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("dockyard_id", "asset_type", "identity", name="uq_asset_identity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String(16), nullable=False)
    identity: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    services: Mapped[list["Service"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Service(Base):
    """A transport endpoint on an asset.

    Product, version and service name stay null until an adapter actually
    identified them. A conventional port number is not evidence of a product.
    """

    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("asset_id", "transport", "port", name="uq_service_socket"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    transport: Mapped[str] = mapped_column(String(8), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="services")


class DiscoveryRun(Base):
    """One auditable discovery request, including requests DockGuard denied."""

    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    adapter: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(32), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_target: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_reason: Mapped[str] = mapped_column(String(500), nullable=False)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    service_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Observation(Base):
    """A recorded signal.

    An Observation is not a Finding. It states what an adapter saw, never what
    that means for risk. Interpretation belongs to a detector, which reads these
    rows and produces a separate Finding that cites them; nothing here is ever
    rewritten by that.
    """

    __tablename__ = "observations"
    __table_args__ = (Index("ix_observation_dockyard_time", "dockyard_id", "observed_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    discovery_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="SET NULL"), index=True, nullable=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=True
    )
    service_id: Mapped[int | None] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=True
    )
    adapter: Mapped[str] = mapped_column(String(32), nullable=False)
    observation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    raw_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidenceRecord(Base):
    """RedLedger foundation: a hashed pointer to one retained artifact."""

    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    discovery_run_id: Mapped[int] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    truncated: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DetectionRun(Base):
    """One auditable detection request.

    A detection run is separate from a DiscoveryRun on purpose: discovery
    contacts a target, detection only reads what discovery already recorded.
    A run therefore has no target, no adapter and no DockGuard decision, and it
    takes no operator parameters at all.
    """

    __tablename__ = "detection_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    detectors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Which enrichment source was in effect, and why it was not, so a finding
    # that carries no CVE reference can be told apart from one RedDock could
    # not enrich.
    enrichment: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    service_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # RedLedger hashes for this run's two retained documents. They are columns
    # rather than evidence_records rows because that table's discovery_run_id is
    # NOT NULL and Phase 2 stays additive; see ARCHITECTURE.md.
    metadata_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ValidationRun(Base):
    """One approval-gated, non-destructive recheck of an eligible finding.

    Validation is intentionally separate from both discovery and detection.
    It may contact one already-authorized origin, only after a stored finding
    has been explicitly approved for recheck. Its result is an outcome about
    that one rule, not a new discovery record or a broad assessment.
    """

    __tablename__ = "validation_runs"
    __table_args__ = (Index("ix_validation_dockyard_finding", "dockyard_id", "finding_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    validator: Mapped[str] = mapped_column(String(48), nullable=False)
    validator_version: Mapped[str] = mapped_column(String(16), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    approval_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    """A normalized security-relevant conclusion drawn by one named detector.

    A Finding is not an Observation. An observation states what an adapter saw;
    a finding states what a specific detector concluded from one or more
    observations, and it cannot exist without them. Identity is the fingerprint:
    within a Dockyard the same underlying issue is one row whose last_seen and
    evidence grow, never a new row per detection run.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("dockyard_id", "fingerprint", name="uq_finding_fingerprint"),
        Index("ix_finding_dockyard_status", "dockyard_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    detector: Mapped[str] = mapped_column(String(48), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # Severity and confidence are deliberately separate: how much this would
    # matter, and how sure RedDock is that it is true, are different questions.
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    status_note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=True
    )
    service_id: Mapped[int | None] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"), nullable=True
    )
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Enrichment, never proof: a CVE association describes a catalogue entry
    # that matched an observed product and version, not a confirmed weakness.
    cve_references: Mapped[list | None] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_detection_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_runs.id", ondelete="SET NULL"), nullable=True
    )
    last_detection_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_runs.id", ondelete="SET NULL"), index=True, nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    evidence: Mapped[list["FindingEvidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    validations: Mapped[list["ValidationRun"]] = relationship(cascade="all, delete-orphan")


class FindingEvidence(Base):
    """The link that makes a finding checkable.

    One row per observation that supported a finding, carrying the hashed
    RedLedger artifact that observation came from. A finding with no rows here
    is refused by the detection runner, because a conclusion without evidence is
    exactly what RedDock exists not to produce.
    """

    __tablename__ = "finding_evidence"
    __table_args__ = (
        UniqueConstraint("finding_id", "observation_id", name="uq_finding_evidence"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )
    detection_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_runs.id", ondelete="SET NULL"), nullable=True
    )
    discovery_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="SET NULL"), nullable=True
    )
    evidence_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence_records.id", ondelete="SET NULL"), nullable=True
    )
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class CorrelationRun(Base):
    """One immutable snapshot of evidence-linked Phase 4 relationships."""

    __tablename__ = "correlation_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    asset_relationship_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_correlation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    framework_mapping_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    graph: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AssetRelationship(Base):
    """A relationship asserted from one named observation and retained hash."""

    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "correlation_run_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationship_snapshot",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_run_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    target_asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    basis: Mapped[str] = mapped_column(String(500), nullable=False)
    observation_id: Mapped[int] = mapped_column(
        ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )
    discovery_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("discovery_runs.id", ondelete="SET NULL"), nullable=True
    )
    evidence_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence_records.id", ondelete="SET NULL"), nullable=True
    )
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingCorrelation(Base):
    """A symmetric relationship between two findings with an explicit basis."""

    __tablename__ = "finding_correlations"
    __table_args__ = (
        UniqueConstraint(
            "correlation_run_id",
            "source_finding_id",
            "target_finding_id",
            "relationship_type",
            name="uq_finding_correlation_snapshot",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_run_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    target_finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    basis: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_relationship_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_relationships.id", ondelete="SET NULL"), nullable=True
    )
    source_evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FrameworkMapping(Base):
    """A transparent classification of a finding under a fixed public framework."""

    __tablename__ = "framework_mappings"
    __table_args__ = (
        UniqueConstraint(
            "correlation_run_id", "finding_id", "framework", "external_id",
            name="uq_framework_mapping_snapshot",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_run_id: Mapped[int] = mapped_column(
        ForeignKey("correlation_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    dockyard_id: Mapped[int] = mapped_column(
        ForeignKey("dockyards.id", ondelete="CASCADE"), index=True, nullable=False
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    external_id: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    basis: Mapped[str] = mapped_column(String(500), nullable=False)
    mapping_version: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
