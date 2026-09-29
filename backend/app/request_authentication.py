"""One exact database/authentication pairing owned by the application lifespan."""

from dataclasses import dataclass

from starlette.requests import Request

from app.authentication import AuthenticationRuntime
from app.database import DatabaseRequestBinding

AUTHENTICATION_REQUEST_BINDING_STATE = "authentication_request_binding"


@dataclass(frozen=True, slots=True)
class AuthenticationRequestBinding:
    database: DatabaseRequestBinding
    runtime: AuthenticationRuntime


def request_authentication_runtime(
    request: Request, database: DatabaseRequestBinding,
) -> AuthenticationRuntime | None:
    binding = getattr(request.app.state, AUTHENTICATION_REQUEST_BINDING_STATE, None)
    if (
        database.mode != "server"
        or not isinstance(binding, AuthenticationRequestBinding)
        or binding.database is not database
        or not isinstance(binding.runtime, AuthenticationRuntime)
    ):
        return None
    return binding.runtime
