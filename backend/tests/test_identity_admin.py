import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.config import DormantServerIdentityConfig
from app.identity_admin import (
    _BOOTSTRAP_ADVISORY_LOCK_ID,
    BootstrapError,
    _acquire_bootstrap_lock,
    bootstrap_owner,
)
from app.models import Membership, Organization, SecurityAuditEvent, User


def _bootstrap(session: Session, **changes):
    values = {
        "issuer": "https://identity.example/realms/reddock",
        "subject": "owner-subject",
        "organization_slug": "server-team",
        "organization_name": "Server Team",
        "display_name": "Initial Owner",
    }
    values.update(changes)
    return bootstrap_owner(session, **values)


def test_bootstrap_uses_one_fixed_postgresql_transaction_advisory_lock():
    session = Mock()
    session.get_bind.return_value.dialect.name = "postgresql"

    _acquire_bootstrap_lock(session)

    statement, parameters = session.execute.call_args.args
    assert str(statement) == "SELECT pg_advisory_xact_lock(:lock_id)"
    assert parameters == {"lock_id": _BOOTSTRAP_ADVISORY_LOCK_ID}


def test_bootstrap_creates_separate_owner_and_is_exactly_idempotent(session: Session):
    first = _bootstrap(session)
    second = _bootstrap(session)

    assert first == second
    assert first.organization_id != 1
    assert first.user_id != 1
    assert first.membership_id != 1
    assert session.get(Organization, 1).slug == "local"
    assert session.get(User, 1).oidc_issuer == "urn:reddock:local"
    assert session.get(Membership, 1).role == "owner"
    assert session.scalar(
        select(func.count()).select_from(SecurityAuditEvent).where(
            SecurityAuditEvent.reason_code == "bootstrap_owner"
        )
    ) == 1
    event = session.scalar(
        select(SecurityAuditEvent).where(SecurityAuditEvent.reason_code == "bootstrap_owner")
    )
    assert event is not None
    assert event.actor_user_id is None
    assert event.actor_membership_id is None
    assert event.actor_role is None


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"organization_slug": "local"}, "non-reserved"),
        ({"issuer": "http://identity.example"}, "HTTPS"),
        ({"subject": ""}, "Subject"),
        ({"subject": "x\nsecret"}, "Subject"),
        ({"organization_name": ""}, "Organization name"),
        ({"display_name": " "}, "Display name"),
    ],
)
def test_bootstrap_rejects_unsafe_identity_inputs(session: Session, changes: dict, message: str):
    with pytest.raises(BootstrapError, match=message):
        _bootstrap(session, **changes)
    assert session.scalar(select(func.count()).select_from(Organization)) == 1


def test_bootstrap_refuses_any_non_exact_existing_state(session: Session):
    _bootstrap(session)
    for changes in (
        {"subject": "other-subject"},
        {"organization_name": "Renamed"},
        {"display_name": "Renamed"},
    ):
        with pytest.raises(BootstrapError):
            _bootstrap(session, **changes)

    organization = session.scalar(select(Organization).where(Organization.slug == "server-team"))
    extra = User(
        oidc_issuer="https://identity.example/realms/reddock",
        oidc_subject="second-user",
        display_name="Second User",
    )
    session.add(extra)
    session.flush()
    session.add(
        Membership(
            organization_id=organization.id,
            user_id=extra.id,
            role="viewer",
            status="active",
        )
    )
    session.commit()
    with pytest.raises(BootstrapError, match="different data"):
        _bootstrap(session)


def test_bootstrap_refuses_a_second_non_local_organization(session: Session):
    session.add(Organization(slug="other", name="Other"))
    session.commit()
    with pytest.raises(BootstrapError, match="outside this organization"):
        _bootstrap(session)


def test_bootstrap_cli_uses_dormant_config_dedicated_engine_without_secret_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    database = tmp_path / "bootstrap.db"
    dedicated_engine = create_engine(f"sqlite:///{database.as_posix()}")
    config = DormantServerIdentityConfig(
        public_origin="https://reddock.example",
        oidc_issuer="https://identity.example/realms/reddock",
        oidc_client_id="reddock",
        oidc_client_secret=SecretStr("client-secret-must-not-print"),
        oidc_endpoint_origins=("https://identity.example",),
        organization_slug="server-team",
        database_host="postgres",
        database_port=5432,
        database_name="reddock",
        database_user="reddock",
        database_password=SecretStr("database-secret-must-not-print"),
    )
    import sqlalchemy

    import app.config
    import app.identity_admin

    monkeypatch.setattr(app.config, "dormant_server_identity_config", lambda: config)
    monkeypatch.setattr(sqlalchemy, "create_engine", lambda _: dedicated_engine)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "identity_admin",
            "bootstrap-owner",
            "--confirm-offline",
            "--subject",
            "owner-subject",
            "--organization-name",
            "Server Team",
            "--display-name",
            "Initial Owner",
        ],
    )

    assert app.identity_admin.main() == 0
    output = capsys.readouterr().out
    assert "Provisioned owner membership" in output
    assert "secret-must-not-print" not in output


def test_bootstrap_cli_requires_explicit_offline_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    import app.identity_admin

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "identity_admin",
            "bootstrap-owner",
            "--subject",
            "owner-subject",
            "--organization-name",
            "Server Team",
            "--display-name",
            "Owner",
        ],
    )
    assert app.identity_admin.main() == 2
    error = capsys.readouterr().err
    assert "--confirm-offline" in error
    assert "Traceback" not in error


def test_bootstrap_cli_bounds_expected_database_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    import sqlalchemy

    import app.config
    import app.identity_admin

    config = DormantServerIdentityConfig(
        public_origin="https://reddock.example",
        oidc_issuer="https://identity.example/realms/reddock",
        oidc_client_id="reddock",
        oidc_client_secret=SecretStr("client-secret-must-not-print"),
        oidc_endpoint_origins=("https://identity.example",),
        organization_slug="server-team",
        database_host="private-database.example",
        database_port=5432,
        database_name="reddock",
        database_user="private-user",
        database_password=SecretStr("database-secret-must-not-print"),
    )

    class BrokenEngine:
        def dispose(self):
            pass

    def fail_upgrade(_engine):
        raise OperationalError("postgresql://private-user:database-secret@host", {}, None)

    monkeypatch.setattr(app.config, "dormant_server_identity_config", lambda: config)
    monkeypatch.setattr(sqlalchemy, "create_engine", lambda _: BrokenEngine())
    monkeypatch.setattr("app.migration_runner.upgrade_database", fail_upgrade)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "identity_admin",
            "bootstrap-owner",
            "--confirm-offline",
            "--subject",
            "owner-subject",
            "--organization-name",
            "Server Team",
            "--display-name",
            "Owner",
        ],
    )

    assert app.identity_admin.main() == 2
    error = capsys.readouterr().err
    assert error == (
        "bootstrap-owner failed: check the PostgreSQL connection and migration state\n"
    )
    assert "private-user" not in error
    assert "secret" not in error
    assert "Traceback" not in error
