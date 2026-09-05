# Phase 7 lab mode

Lab mode adds narrowly defined capabilities for an isolated environment the
operator is authorized to assess. It is not a general command runner or an
authorization bypass.

## Two independent gates

1. The deployment owner explicitly starts RedDock with lab mode enabled.
2. An operator creates a short-lived authorization for one capability and one
   Dockyard by accepting the exact acknowledgement in the Lab console.

Enable only the deployment gate with:

```bash
docker compose -f compose.yaml -f compose.lab.yaml up --build
```

The API cannot turn that switch on. Enabling it creates no authorization by
itself. A Dockyard grant lasts 5–120 minutes, can be revoked immediately, and is
superseded by a newer grant for the same capability.

## Current capability

`discovery.nmap.extended-service` permits the fixed
`lab_extended_service_discovery` profile for one scoped host. It uses unprivileged
TCP connect discovery over Nmap's top 1,000 TCP ports with bounded version
detection. It still accepts no operator flags and includes no scripts, UDP, OS
detection, evasion, credentials, brute force, payloads, or exploitation. Network
targets are refused even when a network exists in DockGuard scope.

RedDock checks the deployment gate and active authorization when the request is
made and again immediately before execution. DockGuard remains mandatory and is
also re-evaluated at execution time.

## Audit trail

Authorization, request, execution, denial, and revocation decisions are retained
as append-only lab audit events. Each records the capability, decision, reason,
authorization, optional discovery run, and timestamp. The Lab console presents
the deployment state, exact acknowledgement, current grant, expiration, revoke
control, and audit ledger together.

Disable the deployment gate when the lab session ends and restart RedDock. Revoke
any active grant first when practical. Neither action deletes its audit history.
