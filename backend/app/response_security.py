"""Uniform browser response hardening for API and application routes."""

from collections.abc import Awaitable, Callable

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Receive, Scope, Send

SecurityHeaderApp = Callable[[Scope, Receive, Send], Awaitable[None]]

# The application is a same-origin Vite bundle: it loads no third-party script,
# style, font, frame or image, and reaches no origin but its own. Stating that
# positively means an injected reference has nowhere to resolve to. Nothing is
# relaxed for inline content, because the build emits none: the served
# index.html references only /assets, and the bundle sets no style property, so
# neither 'unsafe-inline' nor a hash is required to render the application.
APPLICATION_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

#: Swagger and ReDoc load their bundles and inline initializer from a CDN, so
#: the strict policy would blank them. They are developer surfaces rather than
#: application surfaces, and they keep the framing and object restrictions.
_DOCUMENTATION_CSP = "frame-ancestors 'none'; object-src 'none'"
_DOCUMENTATION_PATHS = frozenset(
    {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
)

SECURITY_HEADERS = {
    "Content-Security-Policy": APPLICATION_CSP,
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
                path = scope.get("path", "")
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
                if path in _DOCUMENTATION_PATHS:
                    headers["Content-Security-Policy"] = _DOCUMENTATION_CSP
                if path.startswith("/api/"):
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
