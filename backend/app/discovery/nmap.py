"""Nmap adapter: bounded host and service discovery.

Nmap is used here as a discovery mechanism and nothing else. The argument
vector is generated from a fixed table of safe options; no operator-supplied
flag ever reaches it, the process is started without a shell, and the only
variable values are targets that `app.targets` has already normalized to a
character set that cannot form an option.
"""

import re
import shutil
import subprocess
from xml.etree import ElementTree

from app.config import get_settings
from app.discovery.base import (
    AdapterError,
    AdapterRequest,
    AdapterResult,
    AssetType,
    Confidence,
    DiscoveredAsset,
    DiscoveredObservation,
    DiscoveredService,
    DiscoveryAdapter,
    Profile,
    RawArtifact,
)
from app.targets import TargetKind, is_safe_token

HOST_DISCOVERY = "host_discovery"
SERVICE_DISCOVERY = "service_discovery"

# States worth persisting as a service. Anything else is recorded as an
# observation only, so the inventory never fills with ports that answered
# nothing.
_SERVICE_STATES = frozenset({"open", "open|filtered"})
_MAX_STDERR = 500
_VERSION_TEXT = re.compile(r"Nmap version ([0-9][0-9A-Za-z.\-]*)")


class NmapAdapter(DiscoveryAdapter):
    name = "nmap"
    version = "1.0.0"
    title = "Nmap"
    description = "Non-invasive host and TCP service discovery."
    profiles = (
        Profile(
            name=HOST_DISCOVERY,
            title="Host discovery",
            description="Determine which hosts respond. No ports are scanned.",
        ),
        Profile(
            name=SERVICE_DISCOVERY,
            title="Service discovery",
            description="TCP connect scan of the 100 most common ports with light "
            "version detection.",
        ),
    )

    supported_kinds = (
        TargetKind.IPV4,
        TargetKind.IPV4_NETWORK,
        TargetKind.IPV6,
        TargetKind.IPV6_NETWORK,
        TargetKind.HOSTNAME,
    )

    def run(self, request: AdapterRequest) -> AdapterResult:
        arguments = self.prepare(request)
        stdout = self.execute(arguments, request.timeout_seconds)
        document = self.parse(stdout)
        assets, observations = self.normalize(document, request)
        return AdapterResult(
            assets=assets,
            observations=observations,
            artifacts=(RawArtifact(name="nmap.xml", media_type="application/xml", content=stdout),),
            tool_version=self.tool_version(),
            invocation=tuple(arguments),
        )

    def prepare(self, request: AdapterRequest) -> list[str]:
        """Build the argument vector from approved options only."""
        arguments = [
            self._binary(),
            "-n",  # RedDock resolves names itself so the scanned address is recorded
            "-oX",
            "-",
            "-T3",
            "--max-retries",
            "2",
            "--host-timeout",
            "120s",
        ]
        if request.profile == HOST_DISCOVERY:
            arguments += ["-sn", "--disable-arp-ping"]
        elif request.profile == SERVICE_DISCOVERY:
            arguments += [
                "-Pn",
                "-sT",
                "--top-ports",
                "100",
                "-sV",
                "--version-intensity",
                "2",
            ]
        else:
            raise AdapterError(f"Unknown nmap profile: {request.profile}")

        if request.excluded_addresses:
            _assert_scan_values(request.excluded_addresses)
            arguments += ["--exclude", ",".join(request.excluded_addresses)]

        scan_targets = self.scan_targets(request)
        _assert_scan_values(scan_targets)
        arguments += list(scan_targets)
        return arguments

    def scan_targets(self, request: AdapterRequest) -> tuple[str, ...]:
        """The addresses nmap is asked to touch.

        A named target is scanned by the addresses DockGuard resolved and
        checked, never by the name, so the host that was authorized is the host
        that is contacted and recorded.
        """
        if request.target.is_named:
            if not request.resolved_addresses:
                raise AdapterError(f"{request.target.host} was not resolved before execution")
            return request.resolved_addresses
        return (request.target.value,)

    def execute(self, arguments: list[str], timeout_seconds: int) -> bytes:
        try:
            completed = subprocess.run(  # argv is fixed, shell=False, no operator-supplied flags
                arguments,
                shell=False,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except FileNotFoundError as error:
            raise AdapterError(
                "The nmap executable is not available in this RedDock container"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise AdapterError(f"Nmap exceeded the {timeout_seconds}s run limit") from error

        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()[:_MAX_STDERR]
            raise AdapterError(f"Nmap exited with status {completed.returncode}: {detail}")
        return completed.stdout

    def parse(self, stdout: bytes) -> ElementTree.Element:
        # The XML is produced locally by nmap, which escapes target-supplied
        # text; ElementTree does not resolve external entities.
        try:
            return ElementTree.fromstring(stdout)
        except ElementTree.ParseError as error:
            raise AdapterError(f"Nmap XML output could not be parsed: {error}") from error

    def normalize(
        self, document: ElementTree.Element, request: AdapterRequest
    ) -> tuple[tuple[DiscoveredAsset, ...], tuple[DiscoveredObservation, ...]]:
        hostname = request.target.host if request.target.is_named else None
        assets: list[DiscoveredAsset] = []
        observations: list[DiscoveredObservation] = []

        for host in document.findall("host"):
            address = _host_address(host)
            if address is None:
                continue
            status = host.find("status")
            state = status.get("state", "unknown") if status is not None else "unknown"
            if state != "up":
                continue

            services, port_observations = _normalize_ports(host, address)
            assets.append(
                DiscoveredAsset(
                    asset_type=AssetType.HOST,
                    identity=address,
                    display_name=hostname or address,
                    ip_address=address,
                    hostname=hostname,
                    services=services,
                )
            )
            reason = status.get("reason", "response") if status is not None else "response"
            observations.append(
                DiscoveredObservation(
                    observation_type="host_responded",
                    summary=f"Host {address} responded ({reason})",
                    confidence=Confidence.OBSERVED,
                    asset_identity=address,
                    detail={"reason": reason},
                )
            )
            observations.extend(port_observations)

        return tuple(assets), tuple(observations)

    def tool_version(self) -> str | None:
        try:
            completed = subprocess.run(  # argv is fixed, shell=False
                [self._binary(), "--version"],
                shell=False,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        match = _VERSION_TEXT.search(completed.stdout.decode("utf-8", "replace"))
        return f"nmap {match.group(1)}" if match else None

    def _binary(self) -> str:
        configured = get_settings().nmap_path
        if configured:
            return configured
        return shutil.which("nmap") or "nmap"


def _assert_scan_values(values: tuple[str, ...]) -> None:
    """Defence in depth: nothing that could be read as an option gets through."""
    for value in values:
        if not is_safe_token(value):
            raise AdapterError(f"Refusing to pass unsafe value to nmap: {value!r}")


def _host_address(host: ElementTree.Element) -> str | None:
    for address in host.findall("address"):
        if address.get("addrtype") in ("ipv4", "ipv6"):
            return address.get("addr")
    return None


def _normalize_ports(
    host: ElementTree.Element, address: str
) -> tuple[tuple[DiscoveredService, ...], list[DiscoveredObservation]]:
    services: list[DiscoveredService] = []
    observations: list[DiscoveredObservation] = []

    for port in host.findall("./ports/port"):
        state_element = port.find("state")
        if state_element is None:
            continue
        transport = port.get("protocol", "tcp")
        port_number = _port_number(port.get("portid"))
        if port_number is None:
            continue
        state = state_element.get("state", "unknown")
        if state not in _SERVICE_STATES:
            continue

        identified = _identified_service(port)
        services.append(
            DiscoveredService(
                transport=transport,
                port=port_number,
                state=state,
                service_name=identified.get("name"),
                product=identified.get("product"),
                version=identified.get("version"),
            )
        )
        observations.append(
            DiscoveredObservation(
                observation_type="port_state",
                summary=f"{transport.upper()}/{port_number} {state} on {address}",
                confidence=Confidence.OBSERVED,
                asset_identity=address,
                service_port=(transport, port_number),
                detail={"reason": state_element.get("reason", "")},
            )
        )
        if identified:
            observations.append(
                DiscoveredObservation(
                    observation_type="service_identified",
                    summary=(
                        f"{transport.upper()}/{port_number} identified as "
                        f"{_describe(identified)}"
                    ),
                    confidence=Confidence.REPORTED,
                    asset_identity=address,
                    service_port=(transport, port_number),
                    detail=identified,
                )
            )

    return tuple(services), observations


def _identified_service(port: ElementTree.Element) -> dict[str, str]:
    """Return service details only when nmap probed for them.

    Without version detection nmap still emits a `service` element populated
    from its port-number table. That is a convention, not evidence, so a
    table-derived name is discarded: TCP/22 open is TCP/22 open.
    """
    service = port.find("service")
    if service is None or service.get("method") != "probed":
        return {}
    return {
        key: value
        for key in ("name", "product", "version")
        if (value := service.get(key))
    }


def _describe(identified: dict[str, str]) -> str:
    parts = [identified.get("product") or identified.get("name", ""), identified.get("version", "")]
    return " ".join(part for part in parts if part)


def _port_number(raw: str | None) -> int | None:
    if raw is None or not raw.isdigit():
        return None
    number = int(raw)
    return number if 1 <= number <= 65535 else None
