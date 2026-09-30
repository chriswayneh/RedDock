"""Pair synchronous workflow policy with the exact request database capability."""

from dataclasses import dataclass

from fastapi import HTTPException, Request

from app.database import DatabaseRequestBinding, database_request_binding
from app.workflow_authorization import WorkflowExecutionPolicy

WORKFLOW_REQUEST_BINDING_STATE = "workflow_request_binding"


@dataclass(frozen=True, slots=True)
class WorkflowRequestBinding:
    database: DatabaseRequestBinding
    policy: WorkflowExecutionPolicy


def request_workflow_policy(request: Request) -> WorkflowExecutionPolicy:
    database = database_request_binding(request)
    binding = getattr(request.app.state, WORKFLOW_REQUEST_BINDING_STATE, None)
    if (
        database is None or not isinstance(binding, WorkflowRequestBinding)
        or binding.database is not database
        or not isinstance(binding.policy, WorkflowExecutionPolicy)
        or binding.policy.mode != database.mode
    ):
        raise HTTPException(status_code=503, detail="Workflow authorization unavailable")
    return binding.policy
