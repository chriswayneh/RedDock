"""Fail-closed browser security primitives for the future server mode.

Nothing in this module enables authentication.  It defines the exact origin
and cookie contract that OIDC/session routes must use before server mode can be
enabled.
"""

from dataclasses import dataclass
from hmac import compare_digest
from urllib.parse import urlsplit

from starlette.responses import Response

from app.session_auth import SESSION_LIFETIME, is_browser_session_token
from app.targets import TargetError, TargetKind, normalize_target

MAX_PUBLIC_ORIGIN_LENGTH = 512
SESSION_COOKIE_NAME = "__Host-reddock_session"
CSRF_HEADER_NAME = "X-RedDock-CSRF"
SESSION_COOKIE_MAX_AGE = int(SESSION_LIFETIME.total_seconds())


class BrowserSecurityError(ValueError):
    """A browser-facing security value is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class PublicOrigin:
    """One canonical HTTPS origin and the exact Host name it authorizes."""

    value: str
    trusted_host: str


def parse_public_origin(raw: str) -> PublicOrigin:
    """Parse one HTTPS origin without accepting URL locations or credentials."""
    if not isinstance(raw, str) or not raw:
        raise BrowserSecurityError("Public origin must be non-empty text")
    if len(raw) > MAX_PUBLIC_ORIGIN_LENGTH:
        raise BrowserSecurityError(
            f"Public origin must be {MAX_PUBLIC_ORIGIN_LENGTH} characters or fewer"
        )
    if raw != raw.strip() or any(character.isspace() or ord(character) < 0x20 for character in raw):
        raise BrowserSecurityError("Public origin must not contain whitespace or controls")
    if "\\" in raw:
        raise BrowserSecurityError("Public origin must not contain backslashes")

    parts = urlsplit(raw)
    if parts.scheme.lower() != "https":
        raise BrowserSecurityError("Public origin must use HTTPS")
    if parts.username is not None or parts.password is not None:
        raise BrowserSecurityError("Public origin must not embed credentials")
    if parts.netloc.endswith(":"):
        raise BrowserSecurityError("Public origin must include a port after ':'")
    if parts.path or parts.query or parts.fragment or "?" in raw or "#" in raw:
        raise BrowserSecurityError("Public origin must not include a path, query, or fragment")

    try:
        target = normalize_target(raw)
    except TargetError as error:
        raise BrowserSecurityError(f"Invalid public origin: {error}") from error
    if target.kind is not TargetKind.URL or target.scheme != "https":
        raise BrowserSecurityError("Public origin must use HTTPS")
    return PublicOrigin(value=target.value, trusted_host=target.host)


def origin_matches(presented: str | None, expected: PublicOrigin) -> bool:
    """Return true only for the same canonical HTTPS Origin header value."""
    if presented is None or presented == "null":
        return False
    try:
        candidate = parse_public_origin(presented)
    except BrowserSecurityError:
        return False
    return compare_digest(candidate.value, expected.value)


def set_browser_session_cookie(response: Response, token: str) -> None:
    """Set the bearer cookie with an invariant ``__Host-`` security policy."""
    if not is_browser_session_token(token):
        raise BrowserSecurityError("Browser session token is malformed")
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def clear_browser_session_cookie(response: Response) -> None:
    """Expire the bearer cookie using the same host-only security attributes."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
