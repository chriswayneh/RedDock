"""Dormant team HTTP adapters, never registered by the running application."""

from types import MappingProxyType
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse, Response

from app import team_administration as team
from app.authorization import AuthorizationContext, AuthorizationDenied, Permission
from app.authorization_dependencies import current_authorization
from app.database import get_session
from app.response_security import SECURITY_HEADERS
from app.workflow_authorization import WorkflowExecutionPolicy
from app.workflow_requests import request_workflow_policy

TEAM_ROUTE_PERMISSIONS = MappingProxyType(
    {
        ("GET", "/api/team/members"): Permission.MEMBERSHIP_MANAGE,
        ("POST", "/api/team/members"): Permission.MEMBERSHIP_MANAGE,
        ("PATCH", "/api/team/members/{membership_id}"): Permission.MEMBERSHIP_MANAGE,
        ("POST", "/api/team/ownership"): Permission.ORGANIZATION_TRANSFER,
    }
)

MemberRole = Literal["admin", "operator", "auditor", "viewer"]
MemberId = Annotated[int, Field(strict=True, gt=1)]


class ProvisionMember(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=120)
    role: MemberRole


class ChangeMember(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: MemberRole
    status: Literal["active", "disabled"]


class TransferOwnership(BaseModel):
    model_config = ConfigDict(extra="forbid")

    membership_id: MemberId


class _ProtectedTeamRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def protected(request: Request) -> Response:
            try:
                response = await handler(request)
            except RequestValidationError:
                # Never echo OIDC subjects, submitted text, or malformed bodies.
                response = JSONResponse({"detail": "Invalid team request"}, status_code=422)
            except AuthorizationDenied:
                response = JSONResponse({"detail": "Permission denied"}, status_code=403)
            except team.TeamAdministrationRejected:
                response = JSONResponse({"detail": "Team change rejected"}, status_code=409)
            except SQLAlchemyError:
                response = JSONResponse(
                    {"detail": "Team administration unavailable"}, status_code=503
                )
            except HTTPException as error:
                response = JSONResponse(
                    {"detail": error.detail}, status_code=error.status_code, headers=error.headers
                )
            response.headers.update(SECURITY_HEADERS)
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            return response

        return protected


def _authorize(request: Request) -> tuple[AuthorizationContext, WorkflowExecutionPolicy]:
    policy = request_workflow_policy(request)
    if policy.mode != "server":
        raise HTTPException(status_code=403, detail="Team administration unavailable")
    actor = current_authorization(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    route = request.scope.get("route")
    permission = TEAM_ROUTE_PERMISSIONS.get((request.method, getattr(route, "path", None)))
    if permission is None:
        raise AuthorizationDenied("Permission denied")
    actor.require(permission)
    return actor, policy


TeamAuthority = Annotated[tuple[AuthorizationContext, WorkflowExecutionPolicy], Depends(_authorize)]
TeamSession = Annotated[Session, Depends(get_session)]


def build_team_administration_router() -> APIRouter:
    """Build an isolated, explicitly protected adapter without enabling team access."""

    router = APIRouter(prefix="/api/team", route_class=_ProtectedTeamRoute, include_in_schema=False)

    @router.get("/members")
    def members(
        authority: TeamAuthority,
        session: TeamSession,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    ) -> Response:
        actor, policy = authority
        roster = team.list_members(
            session, authorization=actor, policy=policy, limit=limit, offset=offset
        )
        return JSONResponse(jsonable_encoder(roster))

    @router.post("/members")
    def provision(
        payload: ProvisionMember, authority: TeamAuthority, session: TeamSession
    ) -> Response:
        actor, policy = authority
        member = team.provision_member(
            session, authorization=actor, policy=policy, **payload.model_dump()
        )
        return JSONResponse(jsonable_encoder(member), status_code=201)

    @router.patch("/members/{membership_id}")
    def change(
        membership_id: Annotated[int, Path(gt=1)],
        payload: ChangeMember,
        authority: TeamAuthority,
        session: TeamSession,
    ) -> Response:
        actor, policy = authority
        member = team.change_member(
            session, membership_id, authorization=actor, policy=policy, **payload.model_dump()
        )
        return JSONResponse(jsonable_encoder(member))

    @router.post("/ownership")
    def transfer(
        payload: TransferOwnership, authority: TeamAuthority, session: TeamSession
    ) -> Response:
        actor, policy = authority
        member = team.transfer_ownership(
            session, payload.membership_id, authorization=actor, policy=policy
        )
        return JSONResponse(jsonable_encoder(member))

    return router
