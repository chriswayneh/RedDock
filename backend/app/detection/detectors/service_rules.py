"""Service rule detector.

A small, explicit table of rules over services RedDock actually identified. It
does not guess from a port number: the inventory only carries a service name,
product or version when an adapter probed for it and the target answered, and
this detector additionally requires the identification observation itself as
evidence. A service with no identification observation produces no finding.

Two kinds of rule live here.

Protocol rules state something true of the protocol itself, which is why they
are defensible without a version database: Telnet has no transport encryption,
and FTP's control channel is cleartext unless the server requires AUTH TLS.
RedDock cannot see whether AUTH TLS is required, so the FTP rule is reported at
medium confidence and says so, rather than asserting a fact it did not check.

The version rule is the anchor for CVE enrichment. It records that a service
disclosed a product and version, at informational severity, because disclosure
is not a weakness. Any CVE identifiers a local catalogue associates with that
exact product and version are attached to it as references. They never change
its severity, and they are never a statement that this service is exploitable.
"""

from dataclasses import dataclass

from app.detection.base import (
    AssetView,
    DetectedFinding,
    DetectionContext,
    Detector,
    FindingCategory,
    FindingConfidence,
    ObservationView,
    ServiceView,
    Severity,
)

IDENTIFICATION = "service_identified"
_OPEN_STATES = frozenset({"open", "open|filtered"})


@dataclass(frozen=True, slots=True)
class ProtocolRule:
    """One deterministic statement about an identified protocol."""

    service_name: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: FindingConfidence
    remediation: str


#: Ordered so that detection output does not depend on dictionary insertion.
PROTOCOL_RULES: tuple[ProtocolRule, ...] = (
    ProtocolRule(
        service_name="telnet",
        rule_id="cleartext-remote-administration",
        title="Telnet is reachable on {endpoint}",
        description=(
            "{asset} answered on {endpoint} as Telnet{identified}. Telnet has no transport "
            "encryption at all, so the credentials used to log in and everything typed during "
            "the session cross the network in the clear and can be read or altered by anything "
            "on the path."
        ),
        severity=Severity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        remediation=(
            "Replace Telnet with SSH and close the Telnet port once no client depends on it."
        ),
    ),
    ProtocolRule(
        service_name="ftp",
        rule_id="cleartext-file-transfer",
        title="FTP is reachable on {endpoint}",
        description=(
            "{asset} answered on {endpoint} as FTP{identified}. FTP authenticates over a "
            "cleartext control channel unless the server requires AUTH TLS. RedDock did not "
            "authenticate and did not test whether AUTH TLS is required, so this reports an "
            "exposed FTP service rather than confirmed cleartext authentication."
        ),
        severity=Severity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        remediation=(
            "Require FTPS or replace the service with SFTP, and confirm the server refuses "
            "an unencrypted login."
        ),
    ),
)

VERSION_DISCLOSURE = "service-version-disclosed"


class ServiceRuleDetector(Detector):
    id = "service.rules"
    version = "1.0.0"
    title = "Service rules"
    description = (
        "Applies a fixed table of protocol rules to services RedDock identified, and records "
        "disclosed product versions as the anchor for optional CVE enrichment."
    )
    consumes = ("service_identified", "service inventory")

    def detect(self, context: DetectionContext) -> tuple[DetectedFinding, ...]:
        identifications = _identifications(context)
        findings: list[DetectedFinding] = []
        for asset in context.assets:
            for service in asset.services:
                if service.state not in _OPEN_STATES:
                    continue
                observation = identifications.get(service.id)
                if observation is None:
                    # Nothing identified this service, so there is nothing to
                    # conclude and nothing to prove it with.
                    continue
                findings.extend(self._for_service(context, asset, service, observation))
        return tuple(findings)

    def _for_service(
        self,
        context: DetectionContext,
        asset: AssetView,
        service: ServiceView,
        observation: ObservationView,
    ) -> list[DetectedFinding]:
        findings = []
        name = (service.service_name or "").strip().lower()
        for rule in PROTOCOL_RULES:
            if name == rule.service_name:
                findings.append(self._protocol(rule, asset, service, observation))
        if service.product and service.version:
            findings.append(self._version(context, asset, service, observation))
        return findings

    def _protocol(
        self,
        rule: ProtocolRule,
        asset: AssetView,
        service: ServiceView,
        observation: ObservationView,
    ) -> DetectedFinding:
        identified = f" ({service.product} {service.version})".rstrip() if service.product else ""
        return DetectedFinding(
            rule_id=rule.rule_id,
            title=rule.title.format(endpoint=service.endpoint, asset=asset.display_name),
            description=rule.description.format(
                asset=asset.display_name, endpoint=service.endpoint, identified=identified
            ),
            category=FindingCategory.TRANSPORT,
            severity=rule.severity,
            confidence=rule.confidence,
            evidence_observation_ids=(observation.id,),
            asset_id=asset.id,
            service_id=service.id,
            remediation=rule.remediation,
            detail={
                "service_name": service.service_name,
                "product": service.product,
                "version": service.version,
                "discovery_run_id": observation.discovery_run_id,
            },
        )

    def _version(
        self,
        context: DetectionContext,
        asset: AssetView,
        service: ServiceView,
        observation: ObservationView,
    ) -> DetectedFinding:
        references = context.enrich(service.product, service.version)
        association = ""
        if references:
            catalogue = references[0].source
            association = (
                f" A local catalogue ({catalogue}) associates this exact product and version with "
                f"{len(references)} published CVE identifier(s). That is an association drawn "
                "from a version string the service reported about itself, not a test result: "
                "RedDock did not check whether this service is affected or exploitable."
            )
        return DetectedFinding(
            rule_id=VERSION_DISCLOSURE,
            title=f"{service.endpoint} on {asset.display_name} discloses its version",
            description=(
                f"{asset.display_name} identified the service on {service.endpoint} as "
                f"{service.product} {service.version}. A version banner is useful to a reviewer "
                "and equally useful to anyone else who can reach the port, because it narrows "
                f"down what to try.{association}"
            ),
            category=FindingCategory.INFORMATION_DISCLOSURE,
            severity=Severity.INFORMATIONAL,
            confidence=FindingConfidence.MEDIUM,
            evidence_observation_ids=(observation.id,),
            asset_id=asset.id,
            service_id=service.id,
            remediation=(
                "Decide whether this endpoint needs to publish its version. If it does not, "
                "suppress the banner; if it does, keep the version current."
            ),
            detail={
                "product": service.product,
                "version": service.version,
                "discovery_run_id": observation.discovery_run_id,
            },
            cve_references=references,
        )


def _identifications(context: DetectionContext) -> dict[int, ObservationView]:
    """The most recent identification observation for each service."""
    latest: dict[int, ObservationView] = {}
    for observation in context.of_type(IDENTIFICATION):
        if observation.service_id is None:
            continue
        current = latest.get(observation.service_id)
        if current is None or (observation.observed_at, observation.id) >= (
            current.observed_at,
            current.id,
        ):
            latest[observation.service_id] = observation
    return latest
