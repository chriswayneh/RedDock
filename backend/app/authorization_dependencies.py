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

_REQUEST_AUTHORIZATION: ContextVar[AuthorizationContext | None] = ContextVar(
    "reddock_request_authorization",
    default=None,
)


def current_authorization() -> AuthorizationContext | None:
    """Resolve the explicit local owner until authenticated server mode exists."""
    return LOCAL_AUTHORIZATION


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
    token = _REQUEST_AUTHORIZATION.set(authorization)
    request.state.authorization = authorization
    try:
        yield
    finally:
        _REQUEST_AUTHORIZATION.reset(token)
