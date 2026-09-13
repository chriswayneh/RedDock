"""Strict reverse-proxy boundary for the future authenticated server mode.

Uvicorn is launched with implicit proxy-header handling disabled.  This
middleware is the only component allowed to interpret forwarded request
metadata, and it accepts one deliberately narrow proxy hop.
"""

from collections.abc import Awaitable, Callable, Iterable
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send

IngressApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_REQUIRED_HEADERS = (
    b"host",
    b"x-forwarded-for",
    b"x-forwarded-host",
    b"x-forwarded-proto",
)
_REJECTED_HEADERS = (
    b"forwarded",
    b"x-forwarded-port",
    b"x-forwarded-prefix",
)


class TrustedIngressMiddleware:
    """Accept HTTPS metadata only from one explicitly trusted proxy hop."""

    def __init__(
        self,
        app: IngressApp,
        *,
        public_origin: str,
        trusted_proxy_cidrs: Iterable[str],
    ) -> None:
        self.app = app
        authority = urlsplit(public_origin).netloc
        if not authority:
            raise ValueError("A validated public origin is required")
        self._authority = authority.encode("ascii")
        self._trusted_proxies = tuple(ip_network(value) for value in trusted_proxy_cidrs)
        if not self._trusted_proxies:
            raise ValueError("At least one trusted proxy network is required")

    @staticmethod
    def _values(scope: Scope, name: bytes) -> list[bytes]:
        return [value for key, value in scope.get("headers", []) if key.lower() == name]

    def _verified_client(self, scope: Scope) -> str | None:
        peer = scope.get("client")
        if not peer:
            return None
        try:
            peer_address = ip_address(peer[0])
        except ValueError:
            return None
        if not any(peer_address in network for network in self._trusted_proxies):
            return None

        if any(self._values(scope, name) for name in _REJECTED_HEADERS):
            return None
        values = {name: self._values(scope, name) for name in _REQUIRED_HEADERS}
        if any(len(items) != 1 for items in values.values()):
            return None
        if values[b"host"][0] != self._authority:
            return None
        if values[b"x-forwarded-host"][0] != self._authority:
            return None
        if values[b"x-forwarded-proto"][0] != b"https":
            return None

        forwarded = values[b"x-forwarded-for"][0]
        try:
            text = forwarded.decode("ascii")
            client_address = ip_address(text)
        except (UnicodeDecodeError, ValueError):
            return None
        if str(client_address) != text:
            return None
        return text

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        client_address = self._verified_client(scope)
        if client_address is None:
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            response = PlainTextResponse("Invalid request boundary", status_code=400)
            await response(scope, receive, send)
            return
        scope.setdefault("state", {})["reddock_client_ip"] = client_address
        scope["scheme"] = "https"
        await self.app(scope, receive, send)
