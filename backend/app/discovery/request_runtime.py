from fastapi import HTTPException, Request

from app.database import database_request_binding
from app.discovery.runner import DISCOVERY_RUNTIME_STATE, DiscoveryRuntime


def request_discovery_runtime(request: Request) -> DiscoveryRuntime:
    binding = database_request_binding(request)
    runtime = getattr(request.app.state, DISCOVERY_RUNTIME_STATE, None)
    if (
        binding is None or not isinstance(runtime, DiscoveryRuntime)
        or not runtime.owns(binding.session_factory)
    ):
        raise HTTPException(status_code=503, detail="Discovery unavailable")
    return runtime
