"""Offline-only bootstrap for the future single-organization server mode."""

from __future__ import annotations

import argparse
import re
import sys

from alembic.util.exc import CommandError
from sqlalchemy import func, select, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, Role
from app.config import ConfigurationError, canonical_oidc_issuer
from app.models import Membership, Organization, User
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event

_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# PostgreSQL transaction-scoped namespace for the single server-organization
# bootstrap invariant. All installations deliberately contend on this one key.
_BOOTSTRAP_ADVISORY_LOCK_ID = 0x524544444F434B


class BootstrapError(RuntimeError):
    """The requested owner is unsafe or conflicts with retained identity state."""


def _bounded(value: str, *, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 0x20 for character in value)
    ):
        raise BootstrapError(f"{field} must be bounded non-control text")
    return value


def _reserved_local_identity_is_intact(session: Session) -> None:
    organization = session.get(Organization, 1)
    user = session.get(User, 1)
    membership = session.get(Membership, 1)
    if (
        organization is None
        or (organization.slug, organization.name) != ("local", "Local RedDock")
        or user is None
        or (user.oidc_issuer, user.oidc_subject) != (
            "urn:reddock:local",
            "single-operator",
        )
        or membership is None
        or (
            membership.organization_id,
            membership.user_id,
            membership.role,
            membership.status,
        )
        != (1, 1, "owner", "active")
    ):
        raise BootstrapError("Reserved local identity is missing or inconsistent")


def _acquire_bootstrap_lock(session: Session) -> None:
    """Serialize first-owner invariant reads on the future PostgreSQL backend."""
    if session.get_bind().dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": _BOOTSTRAP_ADVISORY_LOCK_ID},
    )


def bootstrap_owner(
    session: Session,
    *,
    issuer: str,
    subject: str,
    organization_slug: str,
    organization_name: str,
    display_name: str,
) -> AuthorizationContext:
    """Create the first future server owner, or accept one exact prior result."""
    try:
        exact_issuer = canonical_oidc_issuer(issuer)
    except ConfigurationError as error:
        raise BootstrapError(str(error)) from error
    exact_subject = _bounded(subject, field="Subject", maximum=255)
    exact_organization_name = _bounded(
        organization_name, field="Organization name", maximum=120
    )
    exact_display_name = _bounded(display_name, field="Display name", maximum=120)
    if organization_slug == "local" or not _SLUG.fullmatch(organization_slug):
        raise BootstrapError("Organization slug must be non-reserved lowercase text")

    try:
        with session.begin():
            _acquire_bootstrap_lock(session)
            _reserved_local_identity_is_intact(session)
            organization = session.scalar(
                select(Organization)
                .where(Organization.slug == organization_slug)
                .with_for_update()
            )
            user = session.scalar(
                select(User)
                .where(
                    User.oidc_issuer == exact_issuer,
                    User.oidc_subject == exact_subject,
                )
                .with_for_update()
            )
            other_organizations = session.scalar(
                select(func.count()).select_from(Organization).where(Organization.id != 1)
            )
            if organization is not None:
                if other_organizations != 1:
                    raise BootstrapError(
                        "Bootstrap requires exactly one non-local server organization"
                    )
                if organization.id == 1 or organization.name != exact_organization_name:
                    raise BootstrapError("Server organization already exists with different data")
                if user is None or user.id == 1 or user.display_name != exact_display_name:
                    raise BootstrapError("Bootstrap owner already exists with different data")
                membership = session.scalar(
                    select(Membership)
                    .where(
                        Membership.organization_id == organization.id,
                        Membership.user_id == user.id,
                    )
                    .with_for_update()
                )
                organization_memberships = list(
                    session.scalars(
                        select(Membership).where(
                            Membership.organization_id == organization.id
                        )
                    )
                )
                if (
                    membership is None
                    or membership.id == 1
                    or membership.role != "owner"
                    or membership.status != "active"
                    or user.status != "active"
                    or organization_memberships != [membership]
                ):
                    raise BootstrapError("Bootstrap owner already exists with different data")
            else:
                if user is not None or other_organizations:
                    raise BootstrapError(
                        "Bootstrap identity already exists outside this organization"
                    )
                organization = Organization(
                    slug=organization_slug,
                    name=exact_organization_name,
                )
                user = User(
                    oidc_issuer=exact_issuer,
                    oidc_subject=exact_subject,
                    display_name=exact_display_name,
                    status="active",
                )
                session.add_all([organization, user])
                session.flush()
                if organization.id == 1 or user.id == 1:
                    raise BootstrapError("Bootstrap would overwrite reserved local identity")
                membership = Membership(
                    organization_id=organization.id,
                    user_id=user.id,
                    role="owner",
                    status="active",
                )
                session.add(membership)
                session.flush()
                if membership.id == 1:
                    raise BootstrapError("Bootstrap would overwrite reserved local identity")
                append_security_event(
                    session,
                    organization_id=organization.id,
                    action=SecurityAction.MEMBERSHIP_CHANGE,
                    outcome=SecurityOutcome.SUCCESS,
                    target_type="membership",
                    target_id=str(membership.id),
                    reason_code="bootstrap_owner",
                )
            result = AuthorizationContext(
                organization_id=organization.id,
                user_id=user.id,
                membership_id=membership.id,
                role=Role.OWNER,
            )
        return result
    except IntegrityError as error:
        session.rollback()
        raise BootstrapError("Bootstrap identity conflicts with retained state") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision the future server mode's first owner while RedDock is offline."
    )
    parser.add_argument("bootstrap-owner", choices=["bootstrap-owner"])
    parser.add_argument("--confirm-offline", action="store_true")
    parser.add_argument("--subject", required=True)
    parser.add_argument("--organization-name", required=True)
    parser.add_argument("--display-name", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.config import dormant_server_identity_config
    from app.migration_runner import MigrationError, upgrade_database

    if not arguments.confirm_offline:
        print(
            "bootstrap-owner refused: stop RedDock and pass --confirm-offline",
            file=sys.stderr,
        )
        return 2
    try:
        config = dormant_server_identity_config()
    except ConfigurationError as error:
        print(f"bootstrap-owner refused: {error}", file=sys.stderr)
        return 2
    url = URL.create(
        "postgresql+psycopg",
        username=config.database_user,
        password=config.database_password.get_secret_value(),
        host=config.database_host,
        port=config.database_port,
        database=config.database_name,
    )
    try:
        engine = create_engine(url)
    except (SQLAlchemyError, CommandError, MigrationError):
        print(
            "bootstrap-owner failed: check the PostgreSQL connection and migration state",
            file=sys.stderr,
        )
        return 2
    try:
        try:
            upgrade_database(engine)
            sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
            with sessions() as session:
                owner = bootstrap_owner(
                    session,
                    issuer=config.oidc_issuer,
                    subject=arguments.subject,
                    organization_slug=config.organization_slug,
                    organization_name=arguments.organization_name,
                    display_name=arguments.display_name,
                )
        except BootstrapError as error:
            print(f"bootstrap-owner refused: {error}", file=sys.stderr)
            return 2
        except (SQLAlchemyError, CommandError, MigrationError):
            print(
                "bootstrap-owner failed: check the PostgreSQL connection and migration state",
                file=sys.stderr,
            )
            return 2
    finally:
        engine.dispose()
    print(
        "Provisioned owner membership "
        f"{owner.membership_id} in organization {owner.organization_id}."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main tests
    raise SystemExit(main())
