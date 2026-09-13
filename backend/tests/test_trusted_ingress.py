import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest

from app.trusted_ingress import TrustedIngressMiddleware

REPOSITORY = Path(__file__).resolve().parents[2]


def _scope(
    *,
    peer: str = "10.20.0.2",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/health",
        "raw_path": b"/api/health",
        "query_string": b"",
        "root_path": "",
        "server": ("0.0.0.0", 8080),
        "client": (peer, 43100),
        "headers": headers
        or [
            (b"host", b"reddock.example"),
            (b"x-forwarded-for", b"203.0.113.8"),
            (b"x-forwarded-host", b"reddock.example"),
            (b"x-forwarded-proto", b"https"),
        ],
        "state": {},
    }


def _run(scope: dict) -> tuple[list[dict], dict | None]:
    received: dict | None = None

    async def downstream(inner_scope, _receive, send):
        nonlocal received
        received = inner_scope
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = TrustedIngressMiddleware(
        downstream,
        public_origin="https://reddock.example",
        trusted_proxy_cidrs=("10.20.0.2/32", "2001:db8:20::/64"),
    )
    messages: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(middleware(scope, receive, send))
    return messages, received


def test_exact_single_proxy_hop_sets_verified_client_and_https_scheme():
    messages, received = _run(_scope())

    assert messages[0]["status"] == 204
    assert received is not None
    assert received["scheme"] == "https"
    assert received["state"]["reddock_client_ip"] == "203.0.113.8"


def _replace_header(
    headers: list[tuple[bytes, bytes]], name: bytes, value: bytes
) -> list[tuple[bytes, bytes]]:
    return [(key, value if key == name else item) for key, item in headers]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda scope: scope.update(client=("10.20.0.3", 43100)),
        lambda scope: scope.update(client=None),
        lambda scope: scope["headers"].append((b"x-forwarded-proto", b"https")),
        lambda scope: scope["headers"].append((b"forwarded", b"for=203.0.113.8")),
        lambda scope: scope["headers"].append((b"x-forwarded-port", b"443")),
        lambda scope: scope.update(
            headers=_replace_header(scope["headers"], b"host", b"attacker.example")
        ),
        lambda scope: scope.update(
            headers=_replace_header(scope["headers"], b"x-forwarded-host", b"attacker.example")
        ),
        lambda scope: scope.update(
            headers=_replace_header(scope["headers"], b"x-forwarded-proto", b"http")
        ),
        lambda scope: scope.update(
            headers=_replace_header(scope["headers"], b"x-forwarded-for", b"203.0.113.8, 10.20.0.2")
        ),
        lambda scope: scope.update(
            headers=_replace_header(scope["headers"], b"x-forwarded-for", b"203.0.113.008")
        ),
        lambda scope: scope.update(
            headers=[item for item in scope["headers"] if item[0] != b"x-forwarded-for"]
        ),
    ],
)
def test_untrusted_ambiguous_or_non_https_ingress_is_rejected(
    mutate: Callable[[dict], None],
):
    scope = _scope()
    mutate(scope)

    messages, received = _run(scope)

    assert messages[0]["status"] == 400
    assert received is None
    assert b"203.0.113.8" not in messages[-1]["body"]


def test_exact_ipv6_proxy_and_client_are_supported():
    headers = _scope()["headers"]
    headers = _replace_header(headers, b"x-forwarded-for", b"2001:db8:30::8")

    messages, received = _run(_scope(peer="2001:db8:20::2", headers=headers))

    assert messages[0]["status"] == 204
    assert received is not None
    assert received["state"]["reddock_client_ip"] == "2001:db8:30::8"


def test_non_http_lifespan_scope_passes_through_unchanged():
    scope = {"type": "lifespan", "state": {}}
    messages, received = _run(scope)

    assert messages[0]["status"] == 204
    assert received is scope


def test_container_disables_implicit_uvicorn_proxy_header_trust():
    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")

    assert '"--no-proxy-headers"' in dockerfile
