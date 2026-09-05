"""Fixed Phase 7 capability identifiers and operator-facing declarations."""

from dataclasses import dataclass

EXTENDED_SERVICE_DISCOVERY = "discovery.nmap.extended-service"
LAB_ACKNOWLEDGEMENT = (
    "I confirm this Dockyard is an isolated lab that I am authorized to test."
)


@dataclass(frozen=True, slots=True)
class LabCapability:
    id: str
    title: str
    description: str
    risk: str
    single_host_only: bool


CAPABILITIES = (
    LabCapability(
        id=EXTENDED_SERVICE_DISCOVERY,
        title="Extended TCP service discovery",
        description=(
            "Fixed TCP connect scan of the 1,000 most common ports with bounded "
            "version detection. No scripts, UDP, stealth, credentials, or raw flags."
        ),
        risk="lab",
        single_host_only=True,
    ),
)


def capability(capability_id: str) -> LabCapability | None:
    return next((item for item in CAPABILITIES if item.id == capability_id), None)
