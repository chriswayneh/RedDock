from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, Role
from app.authorization_dependencies import current_authorization
from app.models import Dockyard, Membership, Organization, User
from app.schemas import DockyardCreate
from app.services import create_dockyard, get_dockyard, list_dockyards


def _second_organization(session: Session) -> int:
    organization = Organization(slug="other", name="Other organization")
    user = User(
        oidc_issuer="https://identity.example",
        oidc_subject="other-owner",
        display_name="Other owner",
    )
    session.add_all([organization, user])
    session.flush()
    session.add(
        Membership(
            organization_id=organization.id,
            user_id=user.id,
            role="owner",
        )
    )
    session.commit()
    return organization.id


def test_dockyard_loaders_never_cross_organizations(session: Session):
    other_organization_id = _second_organization(session)
    local = create_dockyard(session, 1, DockyardCreate(name="Local"))
    other = create_dockyard(
        session,
        other_organization_id,
        DockyardCreate(name="Other"),
    )

    assert [dockyard.id for dockyard in list_dockyards(session, 1)] == [local.id]
    assert [dockyard.id for dockyard in list_dockyards(session, other_organization_id)] == [
        other.id
    ]
    assert get_dockyard(session, 1, other.id) is None
    assert get_dockyard(session, other_organization_id, local.id) is None
    assert get_dockyard(session, 1, local.id) is local


def test_api_local_context_cannot_load_another_organizations_dockyard(
    client, session: Session
):
    other_organization_id = _second_organization(session)
    other = Dockyard(organization_id=other_organization_id, name="Hidden")
    session.add(other)
    session.commit()
    session.refresh(other)

    response = client.get(f"/api/dockyards/{other.id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "Dockyard not found"}
    assert session.scalar(select(Dockyard).where(Dockyard.id == other.id)) is not None


def test_request_context_selects_exactly_one_organization(client, session: Session):
    from app.main import app

    other_organization_id = _second_organization(session)
    local = create_dockyard(session, 1, DockyardCreate(name="Local"))
    other = create_dockyard(
        session,
        other_organization_id,
        DockyardCreate(name="Other"),
    )
    app.dependency_overrides[current_authorization] = lambda: AuthorizationContext(
        organization_id=other_organization_id,
        user_id=2,
        membership_id=2,
        role=Role.OWNER,
    )
    try:
        listed = client.get("/api/dockyards")
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()] == [other.id]
        assert client.get(f"/api/dockyards/{other.id}").status_code == 200
        assert client.get(f"/api/dockyards/{local.id}").status_code == 404
    finally:
        app.dependency_overrides.pop(current_authorization, None)

    assert client.get(f"/api/dockyards/{local.id}").status_code == 200
    assert client.get(f"/api/dockyards/{other.id}").status_code == 404
