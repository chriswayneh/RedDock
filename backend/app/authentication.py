"""Dormant orchestration for a future authenticated server boundary.

This module connects already-reviewed identity primitives but registers no HTTP
route and cannot enable server mode. A future adapter must supply only the
canonical client address produced by ``TrustedIngressMiddleware``.
"""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.authorization import AuthorizationContext
from app.browser_security import (
    BrowserRequestCredentials,
    browser_request_credentials,
    origin_matches,
    parse_public_origin,
    session_recovery_credentials,
)
from app.config import DormantServerRuntimeConfig
from app.models import Organization
from app.oidc import (
    OidcError,
    OidcProvider,
    consume_login_attempt,
    issue_login_attempt,
    resolve_verified_identity,
)
from app.rate_limits import (
    OIDC_CALLBACK_PLAN,
    OIDC_LOGIN_PLAN,
    REQUEST_MUTATION_PLAN,
    RateLimiterRuntime,
    RateLimitUnavailable,
    client_subject,
    membership_subject,
)
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event
from app.session_auth import (
    IssuedSession,
    SessionRejected,
    SessionUnavailable,
    SessionUseResult,
    csrf_token_for_session,
    is_browser_session_token,
    issue_browser_session,
    logout_proven_browser_session,
    resolve_browser_logout_membership,
    resolve_browser_session,
    use_browser_session,
)

SAFE_REQUEST_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class RequestAuthenticationUnavailable(RuntimeError):
    """The configured request identity capability could not make a decision."""


class RequestAuthenticationThrottled(RuntimeError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Request limit reached")
        self.retry_after_seconds = retry_after_seconds


class AuthenticationFailure(RuntimeError):
    """A future authentication operation failed without exposing its cause."""

    def __init__(self, *, retry_after_seconds: int | None = None) -> None:
        super().__init__("Authentication failed")
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class LoginChallenge:
    """The minimum values a future login response will need."""

    authorization_url: str = field(repr=False)
    browser_token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveredSession:
    context: AuthorizationContext
    expires_at: datetime
    csrf_token: str = field(repr=False)


class AuthenticationRuntime:
    """Compose throttling, OIDC, identity mapping, and session issuance."""

    def __init__(
        self,
        config: DormantServerRuntimeConfig,
        provider: OidcProvider,
        limiter: RateLimiterRuntime,
        lifecycle_engine: Engine,
    ) -> None:
        if not isinstance(config, DormantServerRuntimeConfig):
            raise ValueError("validated dormant server runtime configuration is required")
        if not isinstance(lifecycle_engine, Engine):
            raise ValueError("a dedicated lifecycle engine is required")
        if provider is None or limiter is None:
            raise ValueError("provider and limiter runtimes are required")
        self.__config = config
        self.__origin = parse_public_origin(config.public_origin)
        self.__provider = provider
        self.__limiter = limiter
        self.__lifecycle_engine = lifecycle_engine
        self.__closed = False

    def __repr__(self) -> str:
        return f"AuthenticationRuntime(closed={self.__closed})"

    def _subject(self, verified_client_ip: str):
        if self.__closed:
            raise AuthenticationFailure()
        try:
            return client_subject(verified_client_ip)
        except ValueError:
            raise AuthenticationFailure() from None

    def _record_callback_denial(self, reason_code: str) -> None:
        """Best-effort, bounded audit after an attempt has been irreversibly burned."""

        try:
            with Session(self.__lifecycle_engine) as session:
                organization_id = session.scalar(
                    select(Organization.id).where(
                        Organization.slug == self.__config.organization_slug
                    )
                )
                if organization_id is None:
                    return
                append_security_event(
                    session,
                    organization_id=organization_id,
                    action=SecurityAction.AUTHENTICATION_DENY,
                    outcome=SecurityOutcome.DENIED,
                    reason_code=reason_code,
                )
                session.commit()
        except (SQLAlchemyError, ValueError):
            # Authentication still fails closed if the audit store is unavailable.
            return

    def begin_login(
        self,
        verified_client_ip: str,
        *,
        now: datetime | None = None,
    ) -> LoginChallenge:
        """Create one browser-bound login attempt after durable admission."""

        subject = self._subject(verified_client_ip)
        try:
            decision = self.__limiter.enforce(OIDC_LOGIN_PLAN, subject=subject, now=now)
            if not decision.allowed:
                raise AuthenticationFailure(retry_after_seconds=decision.retry_after_seconds)
            # Discover first so a provider outage cannot leave an orphaned attempt.
            self.__provider.discovery()
            with Session(self.__lifecycle_engine) as session:
                attempt = issue_login_attempt(session, now=now)
            authorization_url = self.__provider.authorization_url(attempt)
            return LoginChallenge(
                authorization_url=authorization_url,
                browser_token=attempt.browser_token,
                expires_at=attempt.expires_at,
            )
        except AuthenticationFailure:
            raise
        except (OidcError, RateLimitUnavailable, SQLAlchemyError):
            raise AuthenticationFailure() from None

    def complete_callback(
        self,
        verified_client_ip: str,
        *,
        state: str,
        browser_token: str,
        code: str,
        now: datetime | None = None,
    ) -> IssuedSession:
        """Burn one login attempt before provider I/O and issue one session."""

        subject = self._subject(verified_client_ip)
        try:
            decision = self.__limiter.enforce(OIDC_CALLBACK_PLAN, subject=subject, now=now)
            if not decision.allowed:
                raise AuthenticationFailure(retry_after_seconds=decision.retry_after_seconds)
            if (
                not is_browser_session_token(state)
                or not is_browser_session_token(browser_token)
                or not isinstance(code, str)
                or not 1 <= len(code) <= 4_096
                or any(ord(character) < 0x20 for character in code)
            ):
                raise AuthenticationFailure()
            with Session(self.__lifecycle_engine) as session:
                attempt = consume_login_attempt(
                    session,
                    state=state,
                    browser_token=browser_token,
                    now=now,
                )

            try:
                id_token = self.__provider.exchange_code(
                    code=code,
                    pkce_verifier=attempt.pkce_verifier,
                )
            except OidcError:
                self._record_callback_denial("provider_exchange_failed")
                raise AuthenticationFailure() from None
            try:
                identity = self.__provider.validate_id_token(
                    id_token,
                    expected_nonce_hash=attempt.nonce_hash,
                )
            except OidcError:
                self._record_callback_denial("id_token_invalid")
                raise AuthenticationFailure() from None
            with Session(self.__lifecycle_engine) as session:
                context = resolve_verified_identity(session, self.__config, identity)
                issued = issue_browser_session(
                    session,
                    context.membership_id,
                    now=now,
                )
                session.commit()
                return issued
        except AuthenticationFailure:
            raise
        except (OidcError, RateLimitUnavailable, SessionRejected, SQLAlchemyError):
            raise AuthenticationFailure() from None

    def authorize_browser_request(
        self, request: Request, *, now: datetime | None = None,
    ) -> AuthorizationContext | None:
        """Resolve active browser identity through the exact owned lifecycle engine.

        Only trusted ingress may supply the client marker. Session use owns its
        transaction and cannot commit a route's business transaction. Rotation
        remains a separate, future browser operation.
        """
        if self.__closed:
            raise RequestAuthenticationUnavailable("Authentication unavailable")
        if self.verified_browser_client(request) is None:
            return None
        credentials = browser_request_credentials(request, self.__origin)
        if credentials is None:
            return None
        try:
            result = use_browser_session(
                self.__lifecycle_engine, credentials.token,
                csrf_token=credentials.csrf_token, now=now,
                expected_issuer=self.__config.oidc_issuer,
                expected_organization_slug=self.__config.organization_slug,
            )
            if result is None:
                return None
            if request.method.upper() not in SAFE_REQUEST_METHODS:
                decision = self.__limiter.enforce(
                    REQUEST_MUTATION_PLAN,
                    subject=membership_subject(result.context.membership_id), now=now,
                )
                if not decision.allowed:
                    raise RequestAuthenticationThrottled(decision.retry_after_seconds)
            return result.context
        except (SessionUnavailable, RateLimitUnavailable, SQLAlchemyError):
            raise RequestAuthenticationUnavailable("Authentication unavailable") from None

    def recover_browser_session(
        self, request: Request, *, now: datetime | None = None,
    ) -> RecoveredSession:
        """Recover current browser state without touching expiry or rotating tokens."""
        if self.verified_browser_client(request) is None:
            raise AuthenticationFailure()
        credentials = session_recovery_credentials(request, self.__origin)
        if credentials is None:
            raise AuthenticationFailure()
        csrf_token = csrf_token_for_session(credentials.token)
        if csrf_token is None:
            raise AuthenticationFailure()
        try:
            # Release the primary connection before durable admission, then
            # recheck identity/session validity after admission may have waited.
            with Session(self.__lifecycle_engine) as session:
                context = resolve_browser_session(
                    session, credentials.token, csrf_token=csrf_token, now=now,
                    expected_issuer=self.__config.oidc_issuer,
                    expected_organization_slug=self.__config.organization_slug,
                )
            if context is None:
                raise AuthenticationFailure()
            decision = self.__limiter.enforce(
                REQUEST_MUTATION_PLAN, subject=membership_subject(context.membership_id), now=now,
            )
            if not decision.allowed:
                raise AuthenticationFailure(retry_after_seconds=decision.retry_after_seconds)
            result = use_browser_session(
                self.__lifecycle_engine, credentials.token, csrf_token=csrf_token,
                touch=False, now=now, expected_issuer=self.__config.oidc_issuer,
                expected_organization_slug=self.__config.organization_slug,
            )
            if result is None:
                raise AuthenticationFailure()
            return RecoveredSession(result.context, result.expires_at, csrf_token)
        except (SessionUnavailable, RateLimitUnavailable, SQLAlchemyError):
            raise AuthenticationFailure() from None

    def _admit_session_mutation(
        self, request: Request, *, logout: bool, now: datetime | None,
    ) -> BrowserRequestCredentials:
        if request.method != "POST" or self.verified_browser_client(request) is None:
            raise AuthenticationFailure()
        credentials = browser_request_credentials(request, self.__origin)
        if credentials is None or credentials.csrf_token is None:
            raise AuthenticationFailure()
        # Release primary-pool connections and row locks before limiter I/O.
        # Admission never touches, rotates, or revokes a session.
        with Session(self.__lifecycle_engine) as session:
            if logout:
                membership_id = resolve_browser_logout_membership(
                    session, credentials.token, credentials.csrf_token,
                    expected_issuer=self.__config.oidc_issuer,
                    expected_organization_slug=self.__config.organization_slug,
                )
            else:
                context = resolve_browser_session(
                    session, credentials.token, csrf_token=credentials.csrf_token, now=now,
                    expected_issuer=self.__config.oidc_issuer,
                    expected_organization_slug=self.__config.organization_slug,
                )
                membership_id = context.membership_id if context is not None else None
        if membership_id is None:
            raise AuthenticationFailure()
        decision = self.__limiter.enforce(
            REQUEST_MUTATION_PLAN, subject=membership_subject(membership_id), now=now,
        )
        if not decision.allowed:
            raise AuthenticationFailure(retry_after_seconds=decision.retry_after_seconds)
        return credentials

    def renew_browser_session(
        self, request: Request, *, now: datetime | None = None,
    ) -> SessionUseResult:
        """Admit renewal before the isolated, identity-rechecking rotation transaction."""

        try:
            credentials = self._admit_session_mutation(request, logout=False, now=now)
            result = use_browser_session(
                self.__lifecycle_engine, credentials.token, csrf_token=credentials.csrf_token,
                rotate_if_due=True, now=now, expected_issuer=self.__config.oidc_issuer,
                expected_organization_slug=self.__config.organization_slug,
            )
            if result is None:
                raise AuthenticationFailure()
            return result
        except (SessionUnavailable, RateLimitUnavailable, SQLAlchemyError):
            raise AuthenticationFailure() from None

    def logout_browser_request(self, request: Request, *, now: datetime | None = None) -> None:
        """Admit and revoke a proven family, even if rotation won after admission."""

        try:
            credentials = self._admit_session_mutation(request, logout=True, now=now)
            if not logout_proven_browser_session(
                self.__lifecycle_engine, credentials.token, credentials.csrf_token,
                expected_issuer=self.__config.oidc_issuer,
                expected_organization_slug=self.__config.organization_slug, now=now,
            ):
                raise AuthenticationFailure()
        except (SessionUnavailable, RateLimitUnavailable, SQLAlchemyError):
            raise AuthenticationFailure() from None

    def verified_browser_client(
        self, request: Request, *, require_origin: bool = False,
    ) -> str | None:
        """Accept only canonical ingress metadata and, for login, one exact Origin."""

        hosts = request.headers.getlist("host")
        if self.__closed or request.url.scheme != "https" or len(hosts) != 1:
            return None
        if not origin_matches("https://" + hosts[0], self.__origin):
            return None
        if require_origin:
            origins = request.headers.getlist("origin")
            if len(origins) != 1 or not origin_matches(origins[0], self.__origin):
                return None
        client_ip = getattr(request.state, "reddock_client_ip", None)
        try:
            client_subject(client_ip)
        except (ValueError, TypeError):
            return None
        return client_ip

    def close(self) -> None:
        """Disable this facade without taking ownership of shared resources."""

        self.__closed = True


def create_authentication_runtime(
    config: DormantServerRuntimeConfig,
    provider: OidcProvider,
    limiter: RateLimiterRuntime,
    lifecycle_engine: Engine,
) -> AuthenticationRuntime:
    return AuthenticationRuntime(config, provider, limiter, lifecycle_engine)
