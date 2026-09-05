from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.authorization import (
    LOCAL_AUTHORIZATION,
    PUBLIC_ROUTES,
    ROUTE_PERMISSIONS,
    AuthorizationContext,
    AuthorizationDenied,
)


def current_authorization() -> AuthorizationContext | None:
    """Resolve the explicit local owner until authenticated server mode exists."""
    return LOCAL_AUTHORIZATION


def authorize_request(
    request: Request,
    authorization: Annotated[AuthorizationContext | None, Depends(current_authorization)],
) -> None:
    """Enforce the reviewed method/path manifest at the API boundary."""
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    key = (request.method, route_path)
    if key in PUBLIC_ROUTES:
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
    request.state.authorization = authorization
