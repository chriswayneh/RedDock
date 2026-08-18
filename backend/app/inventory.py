"""Persistence rules for assets, services and observations.

Assets and services are reconciled: a repeat discovery of the same thing
updates what is already known instead of adding a near-duplicate. Observations
are never reconciled — each one is a dated statement about what an adapter saw,
and history is what makes a run auditable.
"""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.discovery.base import DiscoveredAsset, DiscoveredObservation, DiscoveredService
from app.models import Asset, Observation, Service


def upsert_asset(
    session: Session, dockyard_id: int, discovered: DiscoveredAsset, seen_at: datetime
) -> Asset:
    """Reconcile one discovered asset against the Dockyard inventory."""
    asset = session.scalar(
        select(Asset).where(
            Asset.dockyard_id == dockyard_id,
            Asset.asset_type == str(discovered.asset_type),
            Asset.identity == discovered.identity,
        )
    )
    if asset is None:
        asset = Asset(
            dockyard_id=dockyard_id,
            asset_type=str(discovered.asset_type),
            identity=discovered.identity,
            display_name=discovered.display_name,
            ip_address=discovered.ip_address,
            hostname=discovered.hostname,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        session.add(asset)
        session.flush()
        return asset

    asset.last_seen = seen_at
    # Only fill in what is newly known: a later run that learned less must not
    # erase a fact an earlier run established.
    asset.ip_address = discovered.ip_address or asset.ip_address
    asset.hostname = discovered.hostname or asset.hostname
    if discovered.display_name and asset.display_name == asset.identity:
        asset.display_name = discovered.display_name
    session.flush()
    return asset


def upsert_service(
    session: Session, asset: Asset, discovered: DiscoveredService, seen_at: datetime
) -> Service:
    """Reconcile one discovered service against an asset."""
    service = session.scalar(
        select(Service).where(
            Service.asset_id == asset.id,
            Service.transport == discovered.transport,
            Service.port == discovered.port,
        )
    )
    if service is None:
        service = Service(
            asset_id=asset.id,
            transport=discovered.transport,
            port=discovered.port,
            state=discovered.state,
            service_name=discovered.service_name,
            product=discovered.product,
            version=discovered.version,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        session.add(service)
        session.flush()
        return service

    service.last_seen = seen_at
    service.state = discovered.state
    service.service_name = discovered.service_name or service.service_name
    service.product = discovered.product or service.product
    service.version = discovered.version or service.version
    session.flush()
    return service


def record_observation(
    session: Session,
    dockyard_id: int,
    run_id: int | None,
    adapter: str,
    discovered: DiscoveredObservation,
    observed_at: datetime,
    asset_id: int | None = None,
    service_id: int | None = None,
    raw_reference: str | None = None,
) -> Observation:
    observation = Observation(
        dockyard_id=dockyard_id,
        discovery_run_id=run_id,
        asset_id=asset_id,
        service_id=service_id,
        adapter=adapter,
        observation_type=discovered.observation_type,
        summary=discovered.summary[:500],
        detail=discovered.detail,
        confidence=str(discovered.confidence),
        raw_reference=raw_reference,
        observed_at=observed_at,
    )
    session.add(observation)
    session.flush()
    return observation


def list_assets(session: Session, dockyard_id: int, limit: int) -> list[tuple[Asset, int]]:
    """Assets with their current service count, most recently seen first."""
    statement = (
        select(Asset, func.count(Service.id))
        .outerjoin(Service, Service.asset_id == Asset.id)
        .where(Asset.dockyard_id == dockyard_id)
        .group_by(Asset.id)
        .order_by(Asset.last_seen.desc(), Asset.id.desc())
        .limit(limit)
    )
    return [(asset, count) for asset, count in session.execute(statement)]


def get_asset(session: Session, dockyard_id: int, asset_id: int) -> Asset | None:
    return session.scalar(
        select(Asset).where(Asset.dockyard_id == dockyard_id, Asset.id == asset_id)
    )


def list_services(session: Session, dockyard_id: int, limit: int) -> list[tuple[Service, Asset]]:
    statement = (
        select(Service, Asset)
        .join(Asset, Service.asset_id == Asset.id)
        .where(Asset.dockyard_id == dockyard_id)
        .order_by(Service.last_seen.desc(), Service.id.desc())
        .limit(limit)
    )
    return [(service, asset) for service, asset in session.execute(statement)]


def list_observations(session: Session, dockyard_id: int, limit: int) -> list[Observation]:
    statement = (
        select(Observation)
        .where(Observation.dockyard_id == dockyard_id)
        .order_by(Observation.observed_at.desc(), Observation.id.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))
