"""The discovery adapter boundary.

An adapter is the only component allowed to talk to a target, and it is reached
only after DockGuard has allowed the request. The contract is deliberately
small: `supports` and `run`. Inside `run`, an adapter follows the same four
stages — prepare an invocation, execute it, parse the output, normalize it into
the value objects below — and returns the raw artifacts it wants retained, which
the run orchestrator hands to the evidence store.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

from app.targets import Target, TargetKind


class AssetType(StrEnum):
    HOST = "host"
    WEB = "web"


class Confidence(StrEnum):
    """How a value was established.

    OBSERVED  RedDock saw the behaviour itself.
    REPORTED  The target said so; useful, but self-reported and not proof.
    """

    OBSERVED = "observed"
    REPORTED = "reported"


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"


class AdapterError(RuntimeError):
    """Raised when an adapter cannot complete a run it was allowed to start."""


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """Everything an adapter is permitted to know about a run."""

    target: Target
    profile: str
    resolved_addresses: tuple[str, ...] = ()
    excluded_addresses: tuple[str, ...] = ()
    timeout_seconds: int = 600


@dataclass(frozen=True, slots=True)
class DiscoveredService:
    transport: str
    port: int
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    asset_type: AssetType
    identity: str
    display_name: str
    ip_address: str | None = None
    hostname: str | None = None
    services: tuple[DiscoveredService, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveredObservation:
    observation_type: str
    summary: str
    confidence: Confidence
    asset_identity: str | None = None
    service_port: tuple[str, int] | None = None
    detail: dict | None = None


@dataclass(frozen=True, slots=True)
class RawArtifact:
    """Raw tool output retained as evidence."""

    name: str
    media_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class AdapterResult:
    assets: tuple[DiscoveredAsset, ...] = ()
    observations: tuple[DiscoveredObservation, ...] = ()
    artifacts: tuple[RawArtifact, ...] = ()
    tool_version: str | None = None
    invocation: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    title: str
    description: str


class DiscoveryAdapter(ABC):
    """Base class for every discovery tool RedDock can drive."""

    name: str
    version: str
    title: str
    description: str
    profiles: tuple[Profile, ...]
    supported_kinds: tuple[TargetKind, ...]

    def supports(self, target: Target) -> bool:
        """Whether this adapter can act on a normalized target."""
        return target.kind in self.supported_kinds

    @abstractmethod
    def run(self, request: AdapterRequest) -> AdapterResult:
        """Execute one allowed request and return normalized results."""

    def profile(self, name: str) -> Profile | None:
        return next((profile for profile in self.profiles if profile.name == name), None)
