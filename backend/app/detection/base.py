"""The detection contract.

A detector turns observations into findings. It is deliberately weaker than a
discovery adapter: an adapter may contact a target, a detector may not. A
detector is handed an immutable snapshot of what a Dockyard already knows and
returns value objects. It never receives a database session, a socket, a
subprocess, a target string or an operator-supplied option, so there is nothing
for it to widen, execute or reach. That is enforced structurally rather than by
convention, and tests/test_detection_contract.py asserts it.

    snapshot -> detect -> validate -> normalize -> findings

Validation and normalization belong to the runner rather than the detector: a
detector that returns something malformed is treated as failed and its results
are discarded, rather than partially trusted.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType

EMPTY_DETAIL: Mapping[str, object] = MappingProxyType({})


class Severity(StrEnum):
    """How much this would matter if it is true."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingConfidence(StrEnum):
    """How sure RedDock is that it is true.

    HIGH    RedDock observed the behaviour itself and the rule is unambiguous.
    MEDIUM  The conclusion rests on something the target reported about itself.
    LOW     The conclusion rests on an inference RedDock could not check.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(StrEnum):
    """The small lifecycle a finding is allowed to have.

    OPEN        Reproduced by the most recent successful run of its detector.
    RESOLVED    Not reproduced by a later successful run of the same detector.
                Set by RedDock, never by an operator, and never by deletion.
    SUPPRESSED  An operator decided this is noise. It stays out of the open set
                even when it is reproduced again.
    ACCEPTED    An operator decided this is a known and accepted condition.
    """

    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACCEPTED = "accepted"


class FindingCategory(StrEnum):
    TRANSPORT = "transport"
    HARDENING = "hardening"
    INFORMATION_DISCLOSURE = "information_disclosure"


class DetectionRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


#: Statuses an operator may set. `resolved` is missing on purpose: whether an
#: issue is still reproduced is a fact about the data, not an opinion about it.
OPERATOR_STATUSES: tuple[FindingStatus, ...] = (
    FindingStatus.OPEN,
    FindingStatus.SUPPRESSED,
    FindingStatus.ACCEPTED,
)

#: Statuses an operator has taken responsibility for, which automatic
#: resolution therefore leaves alone.
OPERATOR_OWNED_STATUSES: tuple[FindingStatus, ...] = (
    FindingStatus.SUPPRESSED,
    FindingStatus.ACCEPTED,
)


class DetectorError(RuntimeError):
    """Raised when a detector cannot complete."""


@dataclass(frozen=True, slots=True)
class ServiceView:
    """A read-only view of one recorded service."""

    id: int
    asset_id: int
    transport: str
    port: int
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    first_seen: datetime
    last_seen: datetime

    @property
    def endpoint(self) -> str:
        return f"{self.transport.upper()}/{self.port}"


@dataclass(frozen=True, slots=True)
class AssetView:
    """A read-only view of one recorded asset and its services."""

    id: int
    asset_type: str
    identity: str
    display_name: str
    ip_address: str | None
    hostname: str | None
    first_seen: datetime
    last_seen: datetime
    services: tuple[ServiceView, ...] = ()


@dataclass(frozen=True, slots=True)
class ObservationView:
    """A read-only view of one recorded observation.

    `detail` is a read-only mapping so that a detector cannot mutate the
    snapshot it shares with every other detector in the run.
    """

    id: int
    discovery_run_id: int | None
    asset_id: int | None
    service_id: int | None
    adapter: str
    observation_type: str
    summary: str
    confidence: str
    observed_at: datetime
    detail: Mapping[str, object] = EMPTY_DETAIL


@dataclass(frozen=True, slots=True)
class CveReference:
    """One catalogue association for an observed product and version.

    This is enrichment. It records that a catalogue entry matched, where the
    entry came from and how exact the match was. It is never a statement that
    the service is exploitable.
    """

    cve_id: str
    source: str
    match_type: str
    matched_product: str
    matched_version: str
    source_version: str | None = None
    url: str | None = None

    def document(self) -> dict[str, str | None]:
        return {
            "cve_id": self.cve_id,
            "source": self.source,
            "source_version": self.source_version,
            "match_type": self.match_type,
            "matched_product": self.matched_product,
            "matched_version": self.matched_version,
            "url": self.url,
        }


class Enrichment(ABC):
    """The boundary behind which optional catalogue data is looked up."""

    id: str
    version: str | None
    available: bool

    @abstractmethod
    def lookup(self, product: str, version: str) -> tuple[CveReference, ...]:
        """Return catalogue associations for an exactly matching product and version."""


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Everything a detector is permitted to know.

    It is a snapshot of already-recorded state. There is no session, no
    connection and no target here, which is what makes a detector unable to
    reach anything.
    """

    dockyard_id: int
    generated_at: datetime
    assets: tuple[AssetView, ...] = ()
    observations: tuple[ObservationView, ...] = ()
    enrichment: Enrichment | None = None

    def asset(self, asset_id: int | None) -> AssetView | None:
        if asset_id is None:
            return None
        return next((asset for asset in self.assets if asset.id == asset_id), None)

    def service(self, service_id: int | None) -> ServiceView | None:
        if service_id is None:
            return None
        for asset in self.assets:
            for service in asset.services:
                if service.id == service_id:
                    return service
        return None

    def of_type(self, *observation_types: str) -> tuple[ObservationView, ...]:
        """Observations of the given types, oldest first."""
        wanted = frozenset(observation_types)
        return tuple(
            observation
            for observation in self.observations
            if observation.observation_type in wanted
        )

    def enrich(self, product: str | None, version: str | None) -> tuple[CveReference, ...]:
        """Look up catalogue associations, tolerating an absent catalogue."""
        if self.enrichment is None or not product or not version:
            return ()
        return self.enrichment.lookup(product, version)


@dataclass(frozen=True, slots=True)
class DetectedFinding:
    """What a detector concluded, before RedDock validates and stores it.

    `evidence_observation_ids` is not optional in practice: the runner refuses a
    finding that cites no observation from the snapshot it was given.
    """

    rule_id: str
    title: str
    description: str
    category: FindingCategory
    severity: Severity
    confidence: FindingConfidence
    evidence_observation_ids: tuple[int, ...]
    asset_id: int | None = None
    service_id: int | None = None
    #: A stable discriminator for a rule that can fire more than once on the
    #: same service. It is part of the fingerprint, so it must be derived from
    #: the data and never from a clock, a counter or a random value.
    scope_key: str = ""
    remediation: str | None = None
    detail: dict = field(default_factory=dict)
    cve_references: tuple[CveReference, ...] = ()


class Detector(ABC):
    """Base class for every detector RedDock is allowed to run."""

    id: str
    version: str
    title: str
    description: str
    #: The observation types and inventory facts this detector reads, declared
    #: so a reviewer can see what it consumes without reading its body.
    consumes: tuple[str, ...]

    @abstractmethod
    def detect(self, context: DetectionContext) -> tuple[DetectedFinding, ...]:
        """Inspect the snapshot and return zero or more findings."""
