from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.discovery.base import (
    AssetType,
    Confidence,
    DiscoveredAsset,
    DiscoveredObservation,
    DiscoveredService,
)
from app.inventory import list_observations, record_observation, upsert_asset, upsert_service
from app.models import Dockyard

FIRST = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
LATER = FIRST + timedelta(hours=2)


def make_dockyard(session: Session) -> int:
    dockyard = Dockyard(name="Authorized lab")
    session.add(dockyard)
    session.commit()
    return dockyard.id


def host(identity: str = "192.168.1.10", **overrides) -> DiscoveredAsset:
    defaults = {
        "asset_type": AssetType.HOST,
        "identity": identity,
        "display_name": identity,
        "ip_address": identity,
    }
    return DiscoveredAsset(**{**defaults, **overrides})


def test_the_same_address_maps_to_one_asset_per_dockyard(session: Session):
    dockyard_id = make_dockyard(session)
    first = upsert_asset(session, dockyard_id, host(), FIRST)
    second = upsert_asset(session, dockyard_id, host(), LATER)

    assert first.id == second.id
    assert second.first_seen.replace(tzinfo=UTC) == FIRST
    assert second.last_seen.replace(tzinfo=UTC) == LATER


def test_the_same_address_in_another_dockyard_is_a_separate_asset(session: Session):
    first = upsert_asset(session, make_dockyard(session), host(), FIRST)
    second = upsert_asset(session, make_dockyard(session), host(), FIRST)
    assert first.id != second.id


def test_a_later_run_adds_facts_without_erasing_earlier_ones(session: Session):
    dockyard_id = make_dockyard(session)
    upsert_asset(session, dockyard_id, host(hostname="app.lab.local"), FIRST)
    asset = upsert_asset(session, dockyard_id, host(hostname=None), LATER)
    assert asset.hostname == "app.lab.local"


def test_services_deduplicate_on_transport_and_port(session: Session):
    dockyard_id = make_dockyard(session)
    asset = upsert_asset(session, dockyard_id, host(), FIRST)

    first = upsert_service(
        session, asset, DiscoveredService(transport="tcp", port=22, state="open"), FIRST
    )
    second = upsert_service(
        session,
        asset,
        DiscoveredService(
            transport="tcp", port=22, state="open", service_name="ssh", product="OpenSSH"
        ),
        LATER,
    )

    assert first.id == second.id
    assert second.first_seen.replace(tzinfo=UTC) == FIRST
    assert second.last_seen.replace(tzinfo=UTC) == LATER
    # Identification arrived later; it is added, not invented earlier.
    assert (second.service_name, second.product) == ("ssh", "OpenSSH")


def test_a_service_state_change_is_recorded(session: Session):
    dockyard_id = make_dockyard(session)
    asset = upsert_asset(session, dockyard_id, host(), FIRST)
    upsert_service(session, asset, DiscoveredService("tcp", 22, "open"), FIRST)
    updated = upsert_service(session, asset, DiscoveredService("tcp", 22, "filtered"), LATER)
    assert updated.state == "filtered"


def test_observations_accumulate_as_history(session: Session):
    dockyard_id = make_dockyard(session)
    asset = upsert_asset(session, dockyard_id, host(), FIRST)
    signal = DiscoveredObservation(
        observation_type="port_state",
        summary="TCP/22 open on 192.168.1.10",
        confidence=Confidence.OBSERVED,
        asset_identity="192.168.1.10",
    )

    record_observation(session, dockyard_id, 1, "nmap", signal, FIRST, asset_id=asset.id)
    record_observation(session, dockyard_id, 2, "nmap", signal, LATER, asset_id=asset.id)
    session.commit()

    stored = list_observations(session, dockyard_id, limit=10)
    assert len(stored) == 2
    assert [observation.discovery_run_id for observation in stored] == [2, 1]
    # An observation states what was seen and carries no verdict.
    assert not hasattr(stored[0], "severity")
    assert stored[0].confidence == "observed"
