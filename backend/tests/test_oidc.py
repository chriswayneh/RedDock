from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwk, jwt
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import DormantServerIdentityConfig
from app.models import Membership, OidcLoginAttempt, Organization, SecurityAuditEvent, User
from app.oidc import (
    ALLOWED_ID_TOKEN_ALGORITHMS,
    MAX_DISCOVERY_BYTES,
    OidcError,
    OidcProvider,
    VerifiedIdentity,
    consume_login_attempt,
    issue_login_attempt,
    resolve_verified_identity,
)

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


def _config(*, endpoint_origins: tuple[str, ...] = ("https://identity.example",)):
    return DormantServerIdentityConfig(
        public_origin="https://reddock.example",
        oidc_issuer="https://identity.example/realms/reddock",
        oidc_client_id="reddock",
        oidc_client_secret=SecretStr("client-secret"),
        oidc_endpoint_origins=endpoint_origins,
        organization_slug="server-team",
        database_host="postgres",
        database_port=5432,
        database_name="reddock",
        database_user="reddock",
        database_password=SecretStr("database-secret"),
    )


def _metadata(**changes: object) -> dict[str, object]:
    document: dict[str, object] = {
        "issuer": "https://identity.example/realms/reddock",
        "authorization_endpoint": "https://identity.example/authorize",
        "token_endpoint": "https://identity.example/token",
        "jwks_uri": "https://identity.example/jwks",
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
        "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }
    document.update(changes)
    return document


def _provider(
    handler,
    *,
    config: DormantServerIdentityConfig | None = None,
    clock=lambda: NOW,
) -> OidcProvider:
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    return OidcProvider(config or _config(), client=client, now=clock)


def _signing_key(algorithm: str = "RS256", kid: str = "key-1"):
    if algorithm == "ES256":
        return jwk.ECKey.generate_key(
            "P-256", parameters={"kid": kid, "use": "sig", "alg": algorithm}
        )
    return jwk.RSAKey.generate_key(
        2048, parameters={"kid": kid, "use": "sig", "alg": algorithm}
    )


def _claims(default_nonce: str, **changes: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": "https://identity.example/realms/reddock",
        "sub": "owner-subject",
        "aud": "reddock",
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "iat": int(NOW.timestamp()),
        "nonce": default_nonce,
        "name": "Owner Name",
        "email": "owner@example.test",
        "email_verified": True,
    }
    claims.update(changes)
    return claims


def _signed_token(key, expected_nonce: str, **claim_changes: object) -> str:
    algorithm = key.as_dict().get("alg", "RS256")
    return jwt.encode(
        {"alg": algorithm, "kid": key.as_dict()["kid"]},
        _claims(expected_nonce, **claim_changes),
        key,
        algorithms=[algorithm],
    )


def test_login_attempt_is_bounded_browser_bound_and_consumed_once(session: Session):
    attempt = issue_login_attempt(session, now=NOW)
    assert len(attempt.state) == len(attempt.browser_token) == len(attempt.nonce) == 43
    assert len(attempt.pkce_challenge) == 43
    row = session.scalar(select(OidcLoginAttempt))
    assert row is not None
    verifier = row.pkce_verifier
    assert attempt.state not in repr(row)
    assert row.state_hash != attempt.state
    assert row.browser_token_hash != attempt.browser_token

    consumed = consume_login_attempt(
        session,
        state=attempt.state,
        browser_token=attempt.browser_token,
        now=NOW + timedelta(seconds=1),
    )
    assert consumed.pkce_verifier == verifier
    assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 0
    with pytest.raises(OidcError, match="invalid or expired"):
        consume_login_attempt(
            session,
            state=attempt.state,
            browser_token=attempt.browser_token,
            now=NOW + timedelta(seconds=2),
        )


def test_login_attempt_rejects_wrong_browser_and_expiry(session: Session):
    attempt = issue_login_attempt(session, now=NOW)
    with pytest.raises(OidcError, match="invalid or expired"):
        consume_login_attempt(
            session,
            state=attempt.state,
            browser_token="A" * 43,
            now=NOW + timedelta(seconds=1),
        )
    with pytest.raises(OidcError, match="invalid or expired"):
        consume_login_attempt(
            session,
            state=attempt.state,
            browser_token=attempt.browser_token,
            now=NOW + timedelta(minutes=10),
        )


def test_login_attempt_pending_row_cap_fails_closed(
    session: Session, monkeypatch: pytest.MonkeyPatch
):
    import app.oidc

    monkeypatch.setattr(app.oidc, "MAX_PENDING_LOGIN_ATTEMPTS", 1)
    issue_login_attempt(session, now=NOW)
    with pytest.raises(OidcError, match="Too many"):
        issue_login_attempt(session, now=NOW)
    assert session.scalar(select(func.count()).select_from(OidcLoginAttempt)) == 1


def test_discovery_builds_fixed_openid_pkce_authorization_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/.well-known/openid-configuration")
        return httpx.Response(200, json=_metadata(), headers={"Content-Type": "application/json"})

    attempt = type(
        "Attempt",
        (),
        {"state": "S" * 43, "nonce": "N" * 43, "pkce_challenge": "C" * 43},
    )()
    with _provider(handler) as provider:
        url = provider.authorization_url(attempt)

    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    assert parsed.path == "/authorize"
    assert query == {
        "response_type": ["code"],
        "client_id": ["reddock"],
        "redirect_uri": ["https://reddock.example/api/auth/callback"],
        "scope": ["openid"],
        "state": ["S" * 43],
        "nonce": ["N" * 43],
        "code_challenge": ["C" * 43],
        "code_challenge_method": ["S256"],
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"issuer": "https://attacker.example"}, "issuer"),
        ({"authorization_endpoint": "http://identity.example/authorize"}, "configured HTTPS"),
        ({"authorization_endpoint": "https://identity.example/authorize?x=1"}, "query"),
        ({"jwks_uri": "https://keys.attacker.example/jwks"}, "configured HTTPS"),
        ({"code_challenge_methods_supported": ["plain"]}, "PKCE"),
        ({"id_token_signing_alg_values_supported": ["HS256", "none"]}, "algorithm"),
        ({"response_types_supported": ["token"]}, "authorization code"),
        ({"token_endpoint_auth_methods_supported": ["client_secret_post"]}, "client_secret_basic"),
    ],
)
def test_discovery_rejects_untrusted_or_incomplete_metadata(change: dict, message: str):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_metadata(**change))

    with _provider(handler) as provider, pytest.raises(OidcError, match=message):
        provider.discovery()


def test_discovery_rejects_redirect_duplicate_nonfinite_and_oversized_json():
    responses = iter(
        [
            httpx.Response(302, headers={"Location": "https://identity.example/other"}),
            httpx.Response(
                200,
                content=b'{"issuer":"a","issuer":"b"}',
                headers={"Content-Type": "application/json"},
            ),
            httpx.Response(
                200,
                content=b'{"value":NaN}',
                headers={"Content-Type": "application/json"},
            ),
            httpx.Response(
                200,
                content=b"{" + b" " * MAX_DISCOVERY_BYTES + b"}",
                headers={"Content-Type": "application/json"},
            ),
            httpx.Response(
                200,
                content=b'{"value":' + b"9" * 5_000 + b"}",
                headers={"Content-Type": "application/json"},
            ),
        ]
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return next(responses)

    for message in ("redirect", "duplicate", "non-finite", "oversized", "valid JSON"):
        with _provider(handler) as provider, pytest.raises(OidcError, match=message):
            provider.discovery()


@pytest.mark.parametrize(
    "change",
    [
        {"id_token_signing_alg_values_supported": [{"alg": "RS256"}]},
        {"response_types_supported": [["code"]]},
        {"token_endpoint_auth_methods_supported": [{"method": "client_secret_basic"}]},
        {"code_challenge_methods_supported": [["S256"]]},
    ],
)
def test_discovery_rejects_non_string_capability_entries(change: dict):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_metadata(**change))

    with _provider(handler) as provider, pytest.raises(OidcError, match="malformed"):
        provider.discovery()


def test_token_exchange_uses_basic_auth_and_discards_other_tokens():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(
            200,
            json={"id_token": "a.b.c", "access_token": "discard", "refresh_token": "discard"},
        )

    with _provider(handler) as provider:
        assert provider.exchange_code(code="opaque-code", pkce_verifier="V" * 43) == "a.b.c"
    request = seen[-1]
    form = parse_qs(request.content.decode())
    assert request.headers["authorization"].startswith("Basic ")
    assert "client_id" not in form
    assert form["grant_type"] == ["authorization_code"]
    assert form["code_verifier"] == ["V" * 43]
    assert "discard" not in repr(provider)


@pytest.mark.parametrize("algorithm", sorted(ALLOWED_ID_TOKEN_ALGORITHMS))
def test_id_token_signature_and_claims_validate_for_allowed_algorithms(algorithm: str):
    key = _signing_key(algorithm)
    attempt_nonce = "N" * 43

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(200, json={"keys": [key.as_dict()]})

    with _provider(handler) as provider:
        identity = provider.validate_id_token(
            _signed_token(key, attempt_nonce),
            expected_nonce_hash=__import__("hashlib").sha256(attempt_nonce.encode()).hexdigest(),
        )
    assert identity == VerifiedIdentity(
        issuer="https://identity.example/realms/reddock",
        subject="owner-subject",
    )


def test_id_token_rejects_signature_from_untrusted_key_with_same_kid():
    trusted_key = _signing_key(kid="shared-kid")
    attacker_key = _signing_key(kid="shared-kid")
    nonce = "N" * 43

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(200, json={"keys": [trusted_key.as_dict()]})

    with _provider(handler) as provider, pytest.raises(OidcError, match="signature"):
        provider.validate_id_token(
            _signed_token(attacker_key, nonce),
            expected_nonce_hash=__import__("hashlib").sha256(nonce.encode()).hexdigest(),
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"iss": "https://attacker.example"}, "claims|issuer"),
        ({"aud": "other"}, "claims|audience"),
        ({"aud": ["reddock", "other"]}, "audience"),
        ({"aud": ["reddock", "other"], "azp": "other"}, "audience"),
        (
            {
                "aud": ["reddock", *[f"other-{index}" for index in range(8)]],
                "azp": "reddock",
            },
            "audience",
        ),
        ({"exp": int((NOW - timedelta(minutes=2)).timestamp())}, "claims|time"),
        ({"exp": int((NOW + timedelta(hours=2)).timestamp())}, "time"),
        ({"iat": int((NOW - timedelta(minutes=11)).timestamp())}, "time"),
        ({"exp": 10**1_000}, "time"),
        ({"iat": 10**1_000}, "time"),
        ({"nbf": 10**1_000}, "time"),
        (
            {
                "iat": int((NOW + timedelta(seconds=30)).timestamp()),
                "exp": int((NOW + timedelta(seconds=20)).timestamp()),
            },
            "time",
        ),
        ({"sub": ""}, "claims|subject"),
        ({"nonce": "X" * 43}, "nonce"),
    ],
)
def test_id_token_rejects_invalid_identity_claims(changes: dict, message: str):
    key = _signing_key()
    nonce = "N" * 43

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(200, json={"keys": [key.as_dict()]})

    token = _signed_token(key, nonce, **changes)
    with _provider(handler) as provider, pytest.raises(OidcError, match=message):
        provider.validate_id_token(
            token,
            expected_nonce_hash=__import__("hashlib").sha256(nonce.encode()).hexdigest(),
        )


def test_id_token_rejects_embedded_key_reference_and_unadvertised_algorithm():
    key = _signing_key()
    nonce = "N" * 43
    embedded = jwt.encode(
        {"alg": "RS256", "kid": "key-1", "jku": "https://attacker.example/jwks"},
        _claims(nonce),
        key,
        algorithms=["RS256"],
    )

    def ordinary_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(200, json={"keys": [key.as_dict()]})

    with _provider(ordinary_handler) as provider, pytest.raises(OidcError, match="key reference"):
        provider.validate_id_token(embedded, expected_nonce_hash="0" * 64)

    ordinary = _signed_token(key, nonce)
    def unadvertised_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json=_metadata(id_token_signing_alg_values_supported=["ES256"]),
            )
        return httpx.Response(200, json={"keys": [key.as_dict()]})

    with _provider(unadvertised_handler) as provider, pytest.raises(OidcError, match="algorithm"):
        provider.validate_id_token(ordinary, expected_nonce_hash="0" * 64)


@pytest.mark.parametrize(
    "key_change",
    [
        {"kid": ["key-1"]},
        {"use": ["sig"]},
        {"alg": ["RS256"]},
        {"kty": ["RSA"]},
        {"d": "private-material"},
        {"n": "AQ"},
    ],
)
def test_jwks_rejects_malformed_private_or_weak_keys_without_type_errors(key_change: dict):
    key = _signing_key()
    nonce = "N" * 43
    public = key.as_dict()
    public.update(key_change)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(200, json={"keys": [public]})

    with _provider(handler) as provider, pytest.raises(OidcError):
        provider.validate_id_token(
            _signed_token(key, nonce),
            expected_nonce_hash=__import__("hashlib").sha256(nonce.encode()).hexdigest(),
        )


def test_jwks_rejects_overlarge_rsa_and_malformed_ec_coordinates():
    nonce = "N" * 43
    rsa = _signing_key()
    oversized_rsa = rsa.as_dict()
    oversized_rsa["n"] = urlsafe_b64encode(b"\x01" + b"\x00" * 1_024).rstrip(b"=").decode()
    ec = _signing_key("ES256")
    malformed_ec = ec.as_dict()
    malformed_ec["x"] = urlsafe_b64encode(b"x" * 31).rstrip(b"=").decode()

    for key, public in ((rsa, oversized_rsa), (ec, malformed_ec)):
        def handler(request: httpx.Request, public_key=public) -> httpx.Response:
            if request.url.path.endswith("openid-configuration"):
                return httpx.Response(200, json=_metadata())
            return httpx.Response(200, json={"keys": [public_key]})

        with _provider(handler) as provider, pytest.raises(OidcError):
            provider.validate_id_token(
                _signed_token(key, nonce),
                expected_nonce_hash=__import__("hashlib").sha256(nonce.encode()).hexdigest(),
            )


def test_id_token_rejects_nonfinite_claim_and_invalid_compact_alphabet():
    key = _signing_key()
    nonce = "N" * 43
    token = _signed_token(key, nonce, exp=float("nan"))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        return httpx.Response(200, json={"keys": [key.as_dict()]})

    with _provider(handler) as provider, pytest.raises(OidcError, match="non-finite"):
        provider.validate_id_token(token, expected_nonce_hash="0" * 64)
    with _provider(handler) as provider, pytest.raises(OidcError, match="malformed"):
        provider.validate_id_token("a+.b.c", expected_nonce_hash="0" * 64)


def test_unknown_kid_refresh_is_backoff_bounded():
    old_key = _signing_key(kid="old")
    new_key = _signing_key(kid="new")
    nonce = "N" * 43
    jwks_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal jwks_calls
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json=_metadata())
        jwks_calls += 1
        return httpx.Response(200, json={"keys": [old_key.as_dict()]})

    with _provider(handler) as provider, pytest.raises(OidcError, match="rate limited"):
        provider.validate_id_token(
            _signed_token(new_key, nonce),
            expected_nonce_hash=__import__("hashlib").sha256(nonce.encode()).hexdigest(),
        )
    assert jwks_calls == 1


def _server_identity(session: Session, *, subject: str = "owner-subject", status: str = "active"):
    organization = Organization(slug="server-team", name="Server Team")
    user = User(
        oidc_issuer="https://identity.example/realms/reddock",
        oidc_subject=subject,
        display_name="Owner",
        status=status,
    )
    session.add_all([organization, user])
    session.flush()
    membership = Membership(
        organization_id=organization.id,
        user_id=user.id,
        role="owner",
        status="active",
    )
    session.add(membership)
    session.commit()
    return organization, user, membership


def test_verified_identity_resolves_only_exact_active_preprovisioned_membership(session: Session):
    organization, user, membership = _server_identity(session)
    collision = User(
        oidc_issuer="https://other-issuer.example",
        oidc_subject="other-user",
        display_name="Other",
        email="collision@example.test",
    )
    session.add(collision)
    session.commit()
    context = resolve_verified_identity(
        session,
        _config(),
        VerifiedIdentity(
            issuer=user.oidc_issuer,
            subject=user.oidc_subject,
        ),
    )
    assert (context.organization_id, context.user_id, context.membership_id) == (
        organization.id,
        user.id,
        membership.id,
    )
    assert user.email is None
    assert user.display_name == "Owner"
    assert collision.oidc_issuer == "https://other-issuer.example"


def test_verified_identity_resolver_rejects_a_direct_different_issuer(session: Session):
    _server_identity(session)
    with pytest.raises(OidcError, match="not provisioned"):
        resolve_verified_identity(
            session,
            _config(),
            VerifiedIdentity(
                issuer="https://other-issuer.example",
                subject="owner-subject",
            ),
        )
    event = session.scalar(select(SecurityAuditEvent).order_by(SecurityAuditEvent.id.desc()))
    assert event.reason_code == "identity_claim_invalid"


@pytest.mark.parametrize("status", ["disabled", "active"])
def test_verified_identity_rejects_inactive_or_unknown_without_jit(
    session: Session, status: str
):
    _, user, _ = _server_identity(session, status=status)
    subject = user.oidc_subject if status == "disabled" else "unknown-subject"
    with pytest.raises(OidcError, match="not provisioned"):
        resolve_verified_identity(
            session,
            _config(),
            VerifiedIdentity(
                issuer=user.oidc_issuer,
                subject=subject,
            ),
        )
    assert session.scalar(select(User).where(User.oidc_subject == "unknown-subject")) is None
    event = session.scalar(
        select(SecurityAuditEvent).order_by(SecurityAuditEvent.id.desc())
    )
    assert event is not None
    assert event.action == "authentication.deny"
    assert event.reason_code == "identity_not_provisioned"
    assert "unknown-subject" not in repr(event)
