"""Uniform browser response hardening for API and application routes."""

from collections.abc import Awaitable, Callable

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

SecurityHeaderApp = Callable[[Scope, Receive, Send], Awaitable[None]]

SECURITY_HEADERS = {
    "Content-Security-Policy": "base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Permitted-Cross-Domain-Policies": "none",
}


class ResponseSecurityMiddleware:
    """Apply fixed headers without buffering or rewriting streaming responses."""

    def __init__(self, app: SecurityHeaderApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if scope.get("path", "").startswith("/api/"):
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
