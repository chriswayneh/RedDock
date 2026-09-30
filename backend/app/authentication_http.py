"""Dormant OIDC HTTP adapters, deliberately absent from the application router.

An isolated integration harness must install the exact database/authentication
binding and trusted ingress. This factory does not enable server deployment.
"""

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from app.authentication import AuthenticationFailure, AuthenticationRuntime
from app.browser_security import (
    clear_oidc_transaction_cookie,
    oidc_transaction_cookie,
    set_browser_session_cookie,
    set_oidc_transaction_cookie,
)
from app.database import database_request_binding
from app.request_authentication import request_authentication_runtime
from app.response_security import SECURITY_HEADERS


def _harden(response: Response) -> Response:
    # The adapter's cookie and code responses stay protected even in a harness
    # without the application's response middleware.
    response.headers.update(SECURITY_HEADERS)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _failure(error: AuthenticationFailure | None = None) -> Response:
    retry = error.retry_after_seconds if error is not None else None
    response = JSONResponse(
        {"detail": "Authentication failed"}, status_code=429 if retry is not None else 401,
    )
    if retry is not None:
        response.headers["Retry-After"] = str(retry)
    return response


def _runtime(request: Request) -> AuthenticationRuntime | None:
    database = database_request_binding(request)
    return request_authentication_runtime(request, database) if database is not None else None


def build_authentication_router() -> APIRouter:
    """Build reviewed login/callback routes without registering them anywhere."""

    router = APIRouter(prefix="/api/auth", include_in_schema=False)

    @router.post("/login")
    def login(request: Request) -> Response:
        runtime = _runtime(request)
        client_ip = (
            runtime.verified_browser_client(request, require_origin=True) if runtime else None
        )
        if client_ip is None:
            return _harden(_failure())
        try:
            challenge = runtime.begin_login(client_ip)
            # The destination comes only from the constrained provider runtime.
            # No request parameter selects a provider or a post-login destination.
            response = RedirectResponse(challenge.authorization_url, status_code=303)
            set_oidc_transaction_cookie(response, challenge.browser_token)
        except AuthenticationFailure as error:
            response = _failure(error)
        return _harden(response)

    @router.get("/callback")
    def callback(request: Request) -> Response:
        runtime = _runtime(request)
        client_ip = runtime.verified_browser_client(request) if runtime else None
        if client_ip is None:
            # Untrusted requests cannot overwrite the browser's binding cookie.
            return _harden(_failure())
        parameters = request.query_params
        valid = (
            "error" not in parameters
            and len(parameters.getlist("state")) == 1
            and len(parameters.getlist("code")) == 1
        )
        try:
            # Malformed and provider-error callbacks still pass durable admission
            # before credential validation, but cannot consume a valid attempt.
            # RFC 6749 requires ignoring unknown response parameters. None can
            # select a provider, redirect destination, or field in our response.
            issued = runtime.complete_callback(
                client_ip,
                state=parameters["state"] if valid else "",
                code=parameters["code"] if valid else "",
                browser_token=oidc_transaction_cookie(request) or "",
            )
            response = JSONResponse({
                "csrf_token": issued.csrf_token,
                "expires_at": issued.expires_at.isoformat(),
            })
            set_browser_session_cookie(response, issued.token)
        except AuthenticationFailure as error:
            response = _failure(error)
        # Every trusted callback outcome ends this browser transaction. Preserve
        # any pre-existing session on denial; only successful issuance replaces it.
        clear_oidc_transaction_cookie(response)
        return _harden(response)

    return router
