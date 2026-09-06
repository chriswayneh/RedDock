from http.cookies import SimpleCookie

import pytest
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import Response

from app.browser_security import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_MAX_AGE,
    SESSION_COOKIE_NAME,
    BrowserSecurityError,
    authenticate_browser_request,
    clear_browser_session_cookie,
    origin_matches,
    parse_public_origin,
    set_browser_session_cookie,
)
from app.session_auth import issue_browser_session


def _request(method: str, headers: list[tuple[str, str]]) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": "/api/dockyards",
            "raw_path": b"/api/dockyards",
            "query_string": b"",
            "server": ("red.example", 443),
            "client": ("127.0.0.1", 12345),
            "headers": [(name.lower().encode(), value.encode()) for name, value in headers],
        }
    )


@pytest.mark.parametrize(
    ("raw", "canonical", "trusted_host"),
    [
        ("https://red.example", "https://red.example", "red.example"),
        ("HTTPS://RED.EXAMPLE:443", "https://red.example", "red.example"),
        ("https://red.example:8443", "https://red.example:8443", "red.example"),
        ("https://[2001:db8::10]:8443", "https://[2001:db8::10]:8443", "2001:db8::10"),
    ],
)
def test_public_origin_is_canonical_and_yields_one_trusted_host(
    raw: str, canonical: str, trusted_host: str
):
    origin = parse_public_origin(raw)

    assert origin.value == canonical
    assert origin.trusted_host == trusted_host


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "http://red.example",
        "https://user:password@red.example",
        "https://red.example/",
        "https://red.example/path",
        "https://red.example?query",
        "https://red.example#fragment",
        " https://red.example",
        "https://red.example ",
        "https://red.example:",
        "https://red.example\\@attacker.example",
        "https://*.example",
        "null",
    ],
)
def test_public_origin_rejects_every_non_origin_or_ambiguous_form(raw: str):
    with pytest.raises(BrowserSecurityError):
        parse_public_origin(raw)


def test_origin_check_is_canonical_but_not_prefix_suffix_or_missing():
    expected = parse_public_origin("https://red.example")

    assert origin_matches("https://red.example", expected)
    assert origin_matches("HTTPS://RED.EXAMPLE:443", expected)
    assert not origin_matches(None, expected)
    assert not origin_matches("null", expected)
    assert not origin_matches("https://red.example.attacker.test", expected)
    assert not origin_matches("https://attacker.test/red.example", expected)
    assert not origin_matches("https://red.example:8443", expected)
    assert not origin_matches("https://red.example, https://attacker.test", expected)


def test_session_cookie_is_host_only_http_only_secure_and_bounded():
    response = Response()
    token = "A" * 43
    set_browser_session_cookie(response, token)

    header = response.headers["set-cookie"]
    parsed = SimpleCookie()
    parsed.load(header)
    morsel = parsed[SESSION_COOKIE_NAME]
    assert morsel.value == token
    assert morsel["path"] == "/"
    assert morsel["max-age"] == str(SESSION_COOKIE_MAX_AGE)
    assert morsel["secure"]
    assert morsel["httponly"]
    assert morsel["samesite"].lower() == "lax"
    assert not morsel["domain"]
    assert CSRF_HEADER_NAME == "X-RedDock-CSRF"


def test_session_cookie_refuses_non_session_values_and_clears_symmetrically():
    response = Response()
    with pytest.raises(BrowserSecurityError, match="malformed"):
        set_browser_session_cookie(response, "not-a-session")
    with pytest.raises(BrowserSecurityError, match="malformed"):
        set_browser_session_cookie(response, None)  # type: ignore[arg-type]

    clear_browser_session_cookie(response)
    header = response.headers["set-cookie"]
    assert header.startswith(f'{SESSION_COOKIE_NAME}=""')
    assert "Max-Age=0" in header
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=lax" in header
    assert "Path=/" in header
    assert "Domain=" not in header


def test_safe_browser_request_requires_one_valid_session_cookie(session: Session):
    issued = issue_browser_session(session, 1)
    expected = parse_public_origin("https://red.example")

    context = authenticate_browser_request(
        session,
        _request("GET", [("Cookie", f"other=x; {SESSION_COOKIE_NAME}={issued.token}")]),
        expected,
    )

    assert context is not None
    assert context.organization_id == 1


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "CUSTOM"])
def test_unsafe_browser_request_requires_session_exact_origin_and_csrf(
    session: Session, method: str
):
    issued = issue_browser_session(session, 1)
    expected = parse_public_origin("https://red.example")
    request = _request(
        method,
        [
            ("Cookie", f"{SESSION_COOKIE_NAME}={issued.token}"),
            ("Origin", expected.value),
            (CSRF_HEADER_NAME, issued.csrf_token),
        ],
    )

    assert authenticate_browser_request(session, request, expected) is not None


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Origin", "https://red.example")],
        [(CSRF_HEADER_NAME, "A" * 43)],
        [("Origin", "https://attacker.example"), (CSRF_HEADER_NAME, "A" * 43)],
        [("Origin", "https://red.example"), (CSRF_HEADER_NAME, "B" * 43)],
        [
            ("Origin", "https://red.example"),
            ("Origin", "https://attacker.example"),
            (CSRF_HEADER_NAME, "A" * 43),
        ],
        [
            ("Origin", "https://red.example"),
            (CSRF_HEADER_NAME, "A" * 43),
            (CSRF_HEADER_NAME, "A" * 43),
        ],
    ],
)
def test_unsafe_browser_request_rejects_missing_wrong_or_duplicate_proof(
    session: Session, headers: list[tuple[str, str]]
):
    issued = issue_browser_session(session, 1)
    expected = parse_public_origin("https://red.example")
    request = _request(
        "POST",
        [("Cookie", f"{SESSION_COOKIE_NAME}={issued.token}"), *headers],
    )

    assert authenticate_browser_request(session, request, expected) is None


def test_browser_request_rejects_duplicate_or_quoted_session_cookie(session: Session):
    issued = issue_browser_session(session, 1)
    expected = parse_public_origin("https://red.example")
    duplicate = _request(
        "GET",
        [
            ("Cookie", f"{SESSION_COOKIE_NAME}={issued.token}"),
            ("Cookie", f"{SESSION_COOKIE_NAME}={issued.token}"),
        ],
    )
    quoted = _request("GET", [("Cookie", f'{SESSION_COOKIE_NAME}="{issued.token}"')])

    assert authenticate_browser_request(session, duplicate, expected) is None
    assert authenticate_browser_request(session, quoted, expected) is None
