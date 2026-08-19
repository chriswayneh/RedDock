"""Building the immutable snapshot a detection run reasons over.

This module is the only place where database rows become detector input. It
reads one Dockyard, converts rows into frozen views and hands those views on, so
a detector holds no session, no identity from another Dockyard and nothing it
can write through.
"""

from datetime import UTC, datetime
from types import MappingProxyType

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.detection.base import (
    AssetView,
    DetectionContext,
    Enrichment,
    ObservationView,
    ServiceView,
)
from app.models import Asset, Observation, Service


def build_context(
    session: Session,
    dockyard_id: int,
    *,
    enrichment: Enrichment | None = None,
    generated_at: datetime | None = None,
) -> DetectionContext:
    """Snapshot one Dockyard's recorded state, bounded by the Phase 2 limits."""
    settings = get_settings()
    assets = _assets(session, dockyard_id, settings.max_detection_assets)
    observations = _observations(session, dockyard_id, settings.max_detection_observations)
    return DetectionContext(
        dockyard_id=dockyard_id,
        generated_at=generated_at or datetime.now(UTC),
        assets=assets,
        observations=observations,
        enrichment=enrichment,
    )


def _assets(session: Session, dockyard_id: int, limit: int) -> tuple[AssetView, ...]:
    rows = list(
        session.scalars(
            select(Asset)
            .where(Asset.dockyard_id == dockyard_id)
            .order_by(Asset.id)
            .limit(limit)
        )
    )
    if not rows:
        return ()

    services: dict[int, list[ServiceView]] = {}
    asset_ids = [asset.id for asset in rows]
    for service in session.scalars(
        select(Service).where(Service.asset_id.in_(asset_ids)).order_by(Service.id)
    ):
        services.setdefault(service.asset_id, []).append(
            ServiceView(
                id=service.id,
                asset_id=service.asset_id,
                transport=service.transport,
                port=service.port,
                state=service.state,
                service_name=service.service_name,
                product=service.product,
                version=service.version,
                first_seen=_utc(service.first_seen),
                last_seen=_utc(service.last_seen),
            )
        )

    return tuple(
        AssetView(
            id=asset.id,
            asset_type=asset.asset_type,
            identity=asset.identity,
            display_name=asset.display_name,
            ip_address=asset.ip_address,
            hostname=asset.hostname,
            first_seen=_utc(asset.first_seen),
            last_seen=_utc(asset.last_seen),
            services=tuple(services.get(asset.id, ())),
        )
        for asset in rows
    )


def _observations(session: Session, dockyard_id: int, limit: int) -> tuple[ObservationView, ...]:
    """The most recent observations, returned oldest first.

    The limit takes the newest rows because a detector reasons about the current
    state of a Dockyard, but the result is ordered oldest first so that "the
    latest observation of this kind" is simply the last one.
    """
    newest = list(
        session.scalars(
            select(Observation)
            .where(Observation.dockyard_id == dockyard_id)
            .order_by(Observation.id.desc())
            .limit(limit)
        )
    )
    return tuple(
        ObservationView(
            id=observation.id,
            discovery_run_id=observation.discovery_run_id,
            asset_id=observation.asset_id,
            service_id=observation.service_id,
            adapter=observation.adapter,
            observation_type=observation.observation_type,
            summary=observation.summary,
            confidence=observation.confidence,
            observed_at=_utc(observation.observed_at),
            detail=MappingProxyType(dict(observation.detail or {})),
        )
        for observation in reversed(newest)
    )


def _utc(moment: datetime) -> datetime:
    """Timestamps are stored in UTC; detectors are given aware values."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
