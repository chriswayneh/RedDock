"""Dormant, fail-closed OIDC authorization-code primitives.

This module has no registered routes.  It accepts provider destinations only
from validated deployment configuration and cannot enable server mode.
"""

from __future__ import annotations

import json
import math
import re
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from joserfc import jwk, jwt
from joserfc.errors import JoseError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.authorization import AuthorizationContext, Role
from app.config import DormantServerIdentityConfig
from app.models import Membership, OidcLoginAttempt, Organization, User
from app.security_audit import SecurityAction, SecurityOutcome, append_security_event

LOGIN_ATTEMPT_LIFETIME = timedelta(minutes=10)
MAX_PENDING_LOGIN_ATTEMPTS = 1_024
MAX_DISCOVERY_BYTES = 64 * 1024
MAX_JWKS_BYTES = 256 * 1024
MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
MAX_ID_TOKEN_BYTES = 64 * 1024
MAX_JWKS_KEYS = 32
JWKS_REFRESH_BACKOFF = timedelta(seconds=30)
JWKS_CACHE_LIFETIME = timedelta(hours=1)
OIDC_CLOCK_SKEW_SECONDS = 60
MAX_ID_TOKEN_AGE_SECONDS = 10 * 60
MAX_ID_TOKEN_HORIZON_SECONDS = 60 * 60
ALLOWED_ID_TOKEN_ALGORITHMS = frozenset({"RS256", "ES256"})
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_PKCE = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_KID = re.compile(r"[\x21-\x7e]{1,128}")
_JWT_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})


class OidcError(RuntimeError):
    """An OIDC transaction or provider response failed closed."""


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    signing_algorithms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IssuedLoginAttempt:
    state: str = field(repr=False)
    browser_token: str = field(repr=False)
    nonce: str = field(repr=False)
    pkce_challenge: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ConsumedLoginAttempt:
    id: int
    nonce_hash: str
    pkce_verifier: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    issuer: str
    subject: str


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _digest(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


def _token() -> str:
    value = secrets.token_urlsafe(32)
    if not _TOKEN.fullmatch(value):  # pragma: no cover - secrets contract guard
        raise OidcError("Secure token generation returned an unexpected shape")
    return value


def _pkce_challenge(verifier: str) -> str:
    return urlsafe_b64encode(sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def issue_login_attempt(
    session: Session,
    *,
    now: datetime | None = None,
) -> IssuedLoginAttempt:
    """Create one bounded transaction after purging stale attempts."""
    issued_at = _as_utc(now or _now())
    session.execute(
        delete(OidcLoginAttempt).where(OidcLoginAttempt.expires_at <= issued_at)
    )
    pending = session.scalar(
        select(func.count()).select_from(OidcLoginAttempt).where(
            OidcLoginAttempt.expires_at > issued_at,
        )
    )
    if (pending or 0) >= MAX_PENDING_LOGIN_ATTEMPTS:
        session.rollback()
        raise OidcError("Too many pending login attempts")

    state = _token()
    browser_token = _token()
    nonce = _token()
    verifier = _token()
    expires_at = issued_at + LOGIN_ATTEMPT_LIFETIME
    session.add(
        OidcLoginAttempt(
            state_hash=_digest(state),
            browser_token_hash=_digest(browser_token),
            nonce_hash=_digest(nonce),
            pkce_verifier=verifier,
            expires_at=expires_at,
        )
    )
    session.commit()
    return IssuedLoginAttempt(
        state=state,
        browser_token=browser_token,
        nonce=nonce,
        pkce_challenge=_pkce_challenge(verifier),
        expires_at=expires_at,
    )


def consume_login_attempt(
    session: Session,
    *,
    state: str,
    browser_token: str,
    now: datetime | None = None,
) -> ConsumedLoginAttempt:
    """Atomically consume exactly one unexpired browser-bound transaction."""
    if not _TOKEN.fullmatch(state) or not _TOKEN.fullmatch(browser_token):
        raise OidcError("Login transaction is invalid or expired")
    consumed_at = _as_utc(now or _now())
    row = session.execute(
        delete(OidcLoginAttempt)
        .where(
            OidcLoginAttempt.state_hash == _digest(state),
            OidcLoginAttempt.browser_token_hash == _digest(browser_token),
            OidcLoginAttempt.expires_at > consumed_at,
        )
        .returning(
            OidcLoginAttempt.id,
            OidcLoginAttempt.nonce_hash,
            OidcLoginAttempt.pkce_verifier,
        )
        .execution_options(synchronize_session=False)
    ).one_or_none()
    if row is None:
        session.rollback()
        raise OidcError("Login transaction is invalid or expired")
    session.commit()
    return ConsumedLoginAttempt(
        id=row.id,
        nonce_hash=row.nonce_hash,
        pkce_verifier=row.pkce_verifier,
    )


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OidcError("OIDC response contains duplicate JSON members")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise OidcError("OIDC JSON contains a non-finite number")


def _decode_json(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise OidcError(f"OIDC {label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise OidcError(f"OIDC {label} must be a JSON object")
    return value


def _jwt_part(token: str, part: int) -> dict[str, Any]:
    segments = token.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        raise OidcError("OIDC ID token is malformed")
    encoded = segments[part]
    if len(encoded) > MAX_ID_TOKEN_BYTES:
        raise OidcError("OIDC ID token is oversized")
    if not _JWT_SEGMENT.fullmatch(encoded):
        raise OidcError("OIDC ID token is malformed")
    try:
        payload = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, UnicodeError) as error:
        raise OidcError("OIDC ID token is malformed") from error
    if urlsafe_b64encode(payload).rstrip(b"=").decode("ascii") != encoded:
        raise OidcError("OIDC ID token is not canonically encoded")
    return _decode_json(payload, label="ID token")


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _bounded_string_list(value: Any, *, label: str, maximum: int = 32) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= maximum
        or any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 128
            or any(ord(character) < 0x20 for character in item)
            for item in value
        )
    ):
        raise OidcError(f"OIDC {label} is malformed")
    return value


def _numeric_date(value: Any) -> int | float:
    """Return a safely bounded NumericDate before JOSE performs arithmetic."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise OidcError("OIDC ID token time claims are invalid")
    # This boundary spans 1970 through 2100 and is deliberately checked on
    # integers before any float conversion, avoiding attacker-controlled
    # bignum conversion work or OverflowError.
    if value < 0 or value > 4_102_444_800:
        raise OidcError("OIDC ID token time claims are invalid")
    if isinstance(value, float) and not math.isfinite(value):
        raise OidcError("OIDC ID token time claims are invalid")
    return value


def _base64url_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value or not _JWT_SEGMENT.fullmatch(value):
        return None
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        return None
    if urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        return None
    return decoded


class OidcProvider:
    """Bounded provider client whose destinations come only from configuration."""

    def __init__(
        self,
        config: DormantServerIdentityConfig,
        *,
        client: httpx.Client | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None
        self._clock = now or _now
        self._metadata: ProviderMetadata | None = None
        self._jwks: dict[str, Any] | None = None
        self._last_jwks_refresh: datetime | None = None
        self._jwks_loaded_at: datetime | None = None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OidcProvider:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _allowed_endpoint(self, value: Any, *, label: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > 2_048
            or "\\" in value
            or "%" in value
            or any(character.isspace() or ord(character) < 0x20 for character in value)
        ):
            raise OidcError(f"OIDC {label} is missing or oversized")
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.fragment
            or _origin(value) not in self._config.oidc_endpoint_origins
            or any(segment in {"", ".", ".."} for segment in parts.path.split("/")[1:])
        ):
            raise OidcError(f"OIDC {label} is outside the configured HTTPS origins")
        if label == "authorization endpoint" and parts.query:
            raise OidcError("OIDC authorization endpoint must not contain a query")
        if label != "authorization endpoint" and parts.query:
            raise OidcError(f"OIDC {label} must not contain a query")
        return value

    def _json_request(
        self,
        method: str,
        url: str,
        *,
        max_bytes: int,
        data: dict[str, str] | None = None,
        auth: httpx.BasicAuth | None = None,
    ) -> dict[str, Any]:
        try:
            with self._client.stream(
                method,
                url,
                data=data,
                auth=auth,
                follow_redirects=False,
                headers={"Accept": "application/json"},
            ) as response:
                if 300 <= response.status_code < 400:
                    raise OidcError("OIDC provider redirects are not accepted")
                if response.status_code != 200:
                    raise OidcError("OIDC provider request failed")
                media_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if media_type not in {"application/json", "application/jwk-set+json"}:
                    raise OidcError("OIDC provider returned an unexpected content type")
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise OidcError("OIDC provider response is oversized")
                    chunks.append(chunk)
        except httpx.HTTPError as error:
            raise OidcError("OIDC provider request failed") from error
        return _decode_json(b"".join(chunks), label="provider response")

    def discovery(self) -> ProviderMetadata:
        if self._metadata is not None:
            return self._metadata
        url = self._config.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
        document = self._json_request("GET", url, max_bytes=MAX_DISCOVERY_BYTES)
        if document.get("issuer") != self._config.oidc_issuer:
            raise OidcError("OIDC discovery issuer does not match configuration")
        metadata = ProviderMetadata(
            issuer=self._config.oidc_issuer,
            authorization_endpoint=self._allowed_endpoint(
                document.get("authorization_endpoint"), label="authorization endpoint"
            ),
            token_endpoint=self._allowed_endpoint(
                document.get("token_endpoint"), label="token endpoint"
            ),
            jwks_uri=self._allowed_endpoint(document.get("jwks_uri"), label="JWKS endpoint"),
            signing_algorithms=(),
        )
        methods = _bounded_string_list(
            document.get("code_challenge_methods_supported"),
            label="PKCE methods",
        )
        if "S256" not in methods:
            raise OidcError("OIDC provider does not advertise PKCE S256")
        algorithms = _bounded_string_list(
            document.get("id_token_signing_alg_values_supported"),
            label="ID-token algorithms",
        )
        advertised_algorithms = tuple(
            sorted(ALLOWED_ID_TOKEN_ALGORITHMS.intersection(algorithms))
        )
        if not advertised_algorithms:
            raise OidcError("OIDC provider has no allowed ID-token algorithm")
        response_types = _bounded_string_list(
            document.get("response_types_supported"),
            label="response types",
        )
        if "code" not in response_types:
            raise OidcError("OIDC provider does not advertise authorization code flow")
        auth_methods = _bounded_string_list(
            document.get("token_endpoint_auth_methods_supported"),
            label="token endpoint authentication methods",
        )
        if "client_secret_basic" not in auth_methods:
            raise OidcError("OIDC provider does not advertise client_secret_basic")
        metadata = ProviderMetadata(
            issuer=metadata.issuer,
            authorization_endpoint=metadata.authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            jwks_uri=metadata.jwks_uri,
            signing_algorithms=advertised_algorithms,
        )
        self._metadata = metadata
        return metadata

    def authorization_url(self, attempt: IssuedLoginAttempt) -> str:
        metadata = self.discovery()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._config.oidc_client_id,
                "redirect_uri": self._config.public_origin + "/api/auth/callback",
                "scope": "openid",
                "state": attempt.state,
                "nonce": attempt.nonce,
                "code_challenge": attempt.pkce_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{metadata.authorization_endpoint}?{query}"

    def _load_jwks(self, *, refresh: bool) -> dict[str, Any]:
        checked_at = _as_utc(self._clock())
        fresh_cache = (
            self._jwks is not None
            and self._jwks_loaded_at is not None
            and checked_at - self._jwks_loaded_at < JWKS_CACHE_LIFETIME
        )
        if fresh_cache and not refresh:
            return self._jwks
        if self._last_jwks_refresh is not None:
            if checked_at - self._last_jwks_refresh < JWKS_REFRESH_BACKOFF:
                raise OidcError("OIDC JWKS refresh is temporarily rate limited")
        # Advance before I/O so a failing endpoint cannot be hammered by kid storms.
        self._last_jwks_refresh = checked_at
        document = self._json_request(
            "GET", self.discovery().jwks_uri, max_bytes=MAX_JWKS_BYTES
        )
        keys = document.get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
            raise OidcError("OIDC JWKS contains an invalid number of keys")
        if any(not isinstance(key, dict) for key in keys):
            raise OidcError("OIDC JWKS contains an invalid key")
        self._jwks = {"keys": keys}
        self._jwks_loaded_at = checked_at
        return self._jwks

    @staticmethod
    def _select_key(jwks: dict[str, Any], kid: str, algorithm: str) -> dict[str, Any] | None:
        valid_keys = []
        for key in jwks["keys"]:
            values = {name: key.get(name) for name in ("kid", "use", "alg", "kty", "crv")}
            if any(
                value is not None
                and (
                    not isinstance(value, str)
                    or not 1 <= len(value) <= 128
                    or any(ord(character) < 0x20 for character in value)
                )
                for value in values.values()
            ):
                continue
            valid_keys.append(key)
        matches = [key for key in valid_keys if key.get("kid") == kid]
        if len(matches) != 1:
            return None
        key = matches[0]
        if key.get("use") not in {None, "sig"} or key.get("alg") not in {None, algorithm}:
            return None
        expected_type = "RSA" if algorithm == "RS256" else "EC"
        modulus = _base64url_bytes(key.get("n")) if algorithm == "RS256" else None
        exponent = _base64url_bytes(key.get("e")) if algorithm == "RS256" else None
        x_coordinate = _base64url_bytes(key.get("x")) if algorithm == "ES256" else None
        y_coordinate = _base64url_bytes(key.get("y")) if algorithm == "ES256" else None
        if (
            key.get("kty") != expected_type
            or _PRIVATE_JWK_MEMBERS.intersection(key)
            or any(name in key for name in ("jku", "x5u", "jwk"))
            or (algorithm == "ES256" and key.get("crv") != "P-256")
            or (
                algorithm == "RS256"
                and (
                    modulus is None
                    or not 2_048 <= int.from_bytes(modulus, "big").bit_length() <= 8_192
                    or exponent is None
                    or int.from_bytes(exponent, "big") != 65_537
                )
            )
            or (
                algorithm == "ES256"
                and (
                    x_coordinate is None
                    or len(x_coordinate) != 32
                    or y_coordinate is None
                    or len(y_coordinate) != 32
                )
            )
        ):
            return None
        return key

    def exchange_code(self, *, code: str, pkce_verifier: str) -> str:
        if not isinstance(code, str) or not 1 <= len(code) <= 4_096 or any(
            ord(character) < 0x20 for character in code
        ):
            raise OidcError("OIDC authorization code is malformed")
        if not _PKCE.fullmatch(pkce_verifier):
            raise OidcError("OIDC PKCE verifier is malformed")
        document = self._json_request(
            "POST",
            self.discovery().token_endpoint,
            max_bytes=MAX_TOKEN_RESPONSE_BYTES,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._config.public_origin + "/api/auth/callback",
                "code_verifier": pkce_verifier,
            },
            auth=httpx.BasicAuth(
                self._config.oidc_client_id,
                self._config.oidc_client_secret.get_secret_value(),
            ),
        )
        token = document.get("id_token")
        if not isinstance(token, str) or not token or len(token.encode()) > MAX_ID_TOKEN_BYTES:
            raise OidcError("OIDC token response has no bounded ID token")
        return token

    def validate_id_token(self, token: str, *, expected_nonce_hash: str) -> VerifiedIdentity:
        if not isinstance(token, str) or len(token.encode()) > MAX_ID_TOKEN_BYTES:
            raise OidcError("OIDC ID token is oversized")
        header = _jwt_part(token, 0)
        _jwt_part(token, 1)  # Reject duplicate/invalid claim JSON before JOSE parses it.
        algorithm = header.get("alg")
        kid = header.get("kid")
        if (
            algorithm not in self.discovery().signing_algorithms
            or not isinstance(kid, str)
            or not _KID.fullmatch(kid)
        ):
            raise OidcError("OIDC ID token algorithm or key identifier is not allowed")
        if any(name in header for name in ("jku", "x5u", "jwk")):
            raise OidcError("OIDC ID token embeds an untrusted key reference")

        jwks = self._load_jwks(refresh=False)
        key_data = self._select_key(jwks, kid, algorithm)
        if key_data is None:
            jwks = self._load_jwks(refresh=True)
            key_data = self._select_key(jwks, kid, algorithm)
        if key_data is None:
            raise OidcError("OIDC ID token key is unknown")
        try:
            key = jwk.import_key(key_data)
            decoded = jwt.decode(token, key, algorithms=[algorithm])
            claims = decoded.claims
        except (JoseError, ValueError, TypeError) as error:
            raise OidcError("OIDC ID token signature is invalid") from error

        now = int(_as_utc(self._clock()).timestamp())
        issuer = claims.get("iss")
        subject = claims.get("sub")
        audience = claims.get("aud")
        authorized_party = claims.get("azp")
        expires = claims.get("exp")
        issued = claims.get("iat")
        not_before = claims.get("nbf")
        nonce = claims.get("nonce")
        expires = _numeric_date(expires)
        issued = _numeric_date(issued)
        if not_before is not None:
            not_before = _numeric_date(not_before)
        try:
            jwt.JWTClaimsRegistry(
                now=now,
                leeway=OIDC_CLOCK_SKEW_SECONDS,
                iss={"essential": True, "value": self._config.oidc_issuer},
                sub={"essential": True},
                aud={"essential": True, "value": self._config.oidc_client_id},
                exp={"essential": True},
                iat={"essential": True},
                nonce={"essential": True},
            ).validate(claims)
        except JoseError as error:
            raise OidcError("OIDC ID token claims are invalid") from error
        if issuer != self._config.oidc_issuer:
            raise OidcError("OIDC ID token issuer is invalid")
        if not isinstance(subject, str) or not 1 <= len(subject) <= 255 or any(
            ord(character) < 0x20 for character in subject
        ):
            raise OidcError("OIDC ID token subject is invalid")
        audiences = [audience] if isinstance(audience, str) else audience
        if (
            not isinstance(audiences, list)
            or not audiences
            or any(not isinstance(item, str) for item in audiences)
            or len(audiences) > 8
            or len(set(audiences)) != len(audiences)
            or self._config.oidc_client_id not in audiences
            or (len(audiences) > 1 and authorized_party != self._config.oidc_client_id)
            or (authorized_party is not None and authorized_party != self._config.oidc_client_id)
        ):
            raise OidcError("OIDC ID token audience is invalid")
        if (
            expires <= now - OIDC_CLOCK_SKEW_SECONDS
            or expires > now + MAX_ID_TOKEN_HORIZON_SECONDS
            or issued > now + OIDC_CLOCK_SKEW_SECONDS
            or issued < now - MAX_ID_TOKEN_AGE_SECONDS
            or expires <= issued
            or (
                not_before is not None
                and not_before > now + OIDC_CLOCK_SKEW_SECONDS
            )
        ):
            raise OidcError("OIDC ID token time claims are invalid")
        if (
            not isinstance(nonce, str)
            or not _TOKEN.fullmatch(nonce)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_nonce_hash)
            or not compare_digest(_digest(nonce), expected_nonce_hash)
        ):
            raise OidcError("OIDC ID token nonce is invalid")

        return VerifiedIdentity(
            issuer=issuer,
            subject=subject,
        )


def resolve_verified_identity(
    session: Session,
    config: DormantServerIdentityConfig,
    identity: VerifiedIdentity,
) -> AuthorizationContext:
    """Resolve only one explicitly provisioned active membership; never sign up."""
    organization = session.scalar(
        select(Organization).where(Organization.slug == config.organization_slug)
    )
    if organization is None:
        session.rollback()
        raise OidcError("Authenticated identity is not provisioned")
    if (
        identity.issuer != config.oidc_issuer
        or not isinstance(identity.subject, str)
        or not 1 <= len(identity.subject) <= 255
        or any(ord(character) < 0x20 for character in identity.subject)
    ):
        append_security_event(
            session,
            organization_id=organization.id,
            action=SecurityAction.AUTHENTICATION_DENY,
            outcome=SecurityOutcome.DENIED,
            reason_code="identity_claim_invalid",
        )
        session.commit()
        raise OidcError("Authenticated identity is not provisioned")
    rows = list(
        session.execute(
            select(User, Membership)
            .join(Membership, Membership.user_id == User.id)
            .where(
                User.oidc_issuer == identity.issuer,
                User.oidc_subject == identity.subject,
                Membership.organization_id == organization.id,
                User.status == "active",
                Membership.status == "active",
            )
            .limit(2)
        )
    )
    if len(rows) != 1:
        append_security_event(
            session,
            organization_id=organization.id,
            action=SecurityAction.AUTHENTICATION_DENY,
            outcome=SecurityOutcome.DENIED,
            reason_code="identity_not_provisioned" if not rows else "identity_ambiguous",
        )
        session.commit()
        raise OidcError("Authenticated identity is not provisioned")
    user, membership = rows[0]
    try:
        role = Role(membership.role)
    except ValueError as error:
        append_security_event(
            session,
            organization_id=organization.id,
            action=SecurityAction.AUTHENTICATION_DENY,
            outcome=SecurityOutcome.DENIED,
            reason_code="identity_role_invalid",
        )
        session.commit()
        raise OidcError("Authenticated identity is not provisioned") from error
    return AuthorizationContext(
        organization_id=organization.id,
        user_id=user.id,
        membership_id=membership.id,
        role=role,
    )
