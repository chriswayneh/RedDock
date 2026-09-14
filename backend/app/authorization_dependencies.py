from collections.abc import AsyncIterator
from contextvars import ContextVar
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.authorization import (
    LOCAL_AUTHORIZATION,
    PUBLIC_ROUTES,
    ROUTE_PERMISSIONS,
    AuthorizationContext,
    AuthorizationDenied,
)
from app.database import database_request_binding
from app.local_security import (
    LOCAL_OPERATOR_RUNTIME_STATE,
    SAFE_METHODS,
    LocalMutationDenied,
    LocalMutationThrottled,
    LocalOperatorRuntime,
    LocalOperatorUnavailable,
)

_REQUEST_AUTHORIZATION: ContextVar[AuthorizationContext | None] = ContextVar(
    "reddock_request_authorization",
    default=None,
)


def current_authorization(request: Request) -> AuthorizationContext | None:
    """Resolve local authority only for an explicitly initialized local app."""

    binding = database_request_binding(request)
    if binding is not None and binding.mode == "local":
        return LOCAL_AUTHORIZATION
    return None


def request_authorization() -> AuthorizationContext:
    authorization = _REQUEST_AUTHORIZATION.get()
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return authorization


async def authorize_request(
    request: Request,
    authorization: Annotated[AuthorizationContext | None, Depends(current_authorization)],
) -> AsyncIterator[None]:
    """Enforce the reviewed method/path manifest at the API boundary."""
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    key = (request.method, route_path)
    if key in PUBLIC_ROUTES:
        yield
        return
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    permission = ROUTE_PERMISSIONS.get(key)
    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Route is not authorized",
        )
    try:
        authorization.require(permission)
    except AuthorizationDenied as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied",
        ) from error
    binding = database_request_binding(request)
    if (
        binding is not None
        and binding.mode == "local"
        and request.method.upper() not in SAFE_METHODS
    ):
        runtime = getattr(request.app.state, LOCAL_OPERATOR_RUNTIME_STATE, None)
        if not isinstance(runtime, LocalOperatorRuntime):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Local operator authorization unavailable",
            )
        try:
            runtime.authorize_mutation(request)
        except LocalOperatorUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Local operator authorization unavailable",
            ) from None
        except LocalMutationThrottled:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Local mutation limit reached",
                headers={"Retry-After": "60"},
            ) from None
        except LocalMutationDenied:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Local operator authorization required",
            ) from None
    token = _REQUEST_AUTHORIZATION.set(authorization)
    request.state.authorization = authorization
    try:
        yield
    finally:
        _REQUEST_AUTHORIZATION.reset(token)
