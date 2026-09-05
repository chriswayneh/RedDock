import pytest
from sqlalchemy.orm import Session

from app.authorization import LOCAL_AUTHORIZATION
from app.models import Organization
from app.security_audit import (
    SecurityAction,
    SecurityOutcome,
    append_security_event,
    list_security_events,
)


def test_security_events_are_structured_and_tenant_scoped(session: Session):
    other = Organization(slug="other", name="Other")
    session.add(other)
    session.flush()
    event = append_security_event(
        session,
        organization_id=1,
        actor=LOCAL_AUTHORIZATION,
        action=SecurityAction.SESSION_REVOKE,
        outcome=SecurityOutcome.SUCCESS,
        target_type="browser_session",
        target_id="42",
        reason_code="operator_logout",
        request_id="request-123",
    )
    append_security_event(
        session,
        organization_id=other.id,
        action=SecurityAction.AUTHENTICATION_DENY,
        outcome=SecurityOutcome.DENIED,
        reason_code="invalid_session",
    )
    session.commit()

    assert list_security_events(session, 1) == [event]
    assert event.actor_user_id == event.actor_membership_id == 1
    assert event.actor_role == "owner"
    assert len(list_security_events(session, other.id)) == 1


def test_audit_actor_cannot_cross_the_event_tenant(session: Session):
    with pytest.raises(ValueError, match="event organization"):
        append_security_event(
            session,
            organization_id=2,
            actor=LOCAL_AUTHORIZATION,
            action=SecurityAction.MEMBERSHIP_CHANGE,
            outcome=SecurityOutcome.SUCCESS,
        )


@pytest.mark.parametrize("field", ["target_type", "target_id", "reason_code", "request_id"])
def test_audit_metadata_refuses_free_form_content(session: Session, field: str):
    with pytest.raises(ValueError, match="bounded opaque identifier"):
        append_security_event(
            session,
            organization_id=1,
            action=SecurityAction.AUTHENTICATION_DENY,
            outcome=SecurityOutcome.DENIED,
            **{field: "secret value with spaces"},
        )


@pytest.mark.parametrize("limit", [0, 1_001])
def test_audit_read_limit_is_bounded(session: Session, limit: int):
    with pytest.raises(ValueError, match="between 1 and 1000"):
        list_security_events(session, 1, limit=limit)
