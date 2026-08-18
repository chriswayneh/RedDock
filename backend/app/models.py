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
    that means for risk; interpretation belongs to a later phase.
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
