"""HTTP probe adapter: one request against one authorized origin.

This adapter performs a single, non-authenticated request to the origin the
operator scoped. It does not crawl, follow redirects, submit anything, guess
paths or read response bodies. It records what the endpoint answered, which is
an observation about the endpoint and never a judgement about it.
"""

import http.client
import json
import platform
import socket
import ssl
from dataclasses import dataclass
from hashlib import sha256

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
from app.targets import Target, TargetKind

HTTP_PROBE = "http_probe"
USER_AGENT = "RedDock/0.2.1 (+https://github.com/chriswayneh/RedDock)"

# Headers worth retaining. Everything else is dropped so that cookies and other
# session material a target may return are never written to evidence.
_RECORDED_HEADERS = (
    "server",
    "content-type",
    "content-length",
    "location",
    "x-powered-by",
    "strict-transport-security",
)
_CONNECT_TIMEOUT = 10
_MAX_HEADER_LENGTH = 255


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """The raw result of a single request, before normalization."""

    status: int | None = None
    reason: str | None = None
    headers: dict[str, str] | None = None
    tls: dict[str, object] | None = None
    error: str | None = None


class HttpProbeAdapter(DiscoveryAdapter):
    name = "http"
    version = "1.0.0"
    title = "HTTP probe"
    description = "Single non-invasive request to a scoped HTTP or HTTPS origin."
    profiles = (
        Profile(
            name=HTTP_PROBE,
            title="HTTP probe",
            description="Record the status line, selected response headers and TLS "
            "session details for one origin.",
        ),
    )

    supported_kinds = (TargetKind.URL,)

    def run(self, request: AdapterRequest) -> AdapterResult:
        if request.profile != HTTP_PROBE:
            raise AdapterError(f"Unknown HTTP profile: {request.profile}")
        address = self.prepare(request)
        outcome = self.execute(request.target, address, request.timeout_seconds)
        assets, observations = self.normalize(request.target, address, outcome)
        return AdapterResult(
            assets=assets,
            observations=observations,
            artifacts=(_transcript(request.target, address, outcome),),
            tool_version=f"python {platform.python_version()}",
            invocation=(f"{request.target.value} via {address}",),
        )

    def prepare(self, request: AdapterRequest) -> str:
        """The single address this probe is allowed to contact."""
        if not request.target.is_named:
            return request.target.host
        if not request.resolved_addresses:
            raise AdapterError(f"{request.target.host} was not resolved before execution")
        return request.resolved_addresses[0]

    def execute(self, target: Target, address: str, timeout_seconds: int) -> ProbeOutcome:
        timeout = min(timeout_seconds, _CONNECT_TIMEOUT)
        outcome = _probe(target, address, timeout, "HEAD")
        if outcome.status in (405, 501):
            # A server that refuses HEAD is asked once with GET. The body is
            # still never read, so this stays a bounded, two-request exchange.
            outcome = _probe(target, address, timeout, "GET")
        return outcome

    def normalize(
        self, target: Target, address: str, outcome: ProbeOutcome
    ) -> tuple[tuple[DiscoveredAsset, ...], tuple[DiscoveredObservation, ...]]:
        if outcome.status is None:
            return (), (
                DiscoveredObservation(
                    observation_type="endpoint_unreachable",
                    summary=f"{target.value} did not answer: {outcome.error}",
                    confidence=Confidence.OBSERVED,
                    detail={"address": address, "error": outcome.error},
                ),
            )

        port = _port(target)
        asset = DiscoveredAsset(
            asset_type=AssetType.WEB,
            identity=target.value,
            display_name=target.value,
            ip_address=address,
            hostname=target.host if target.is_named else None,
            services=(
                DiscoveredService(
                    transport="tcp",
                    port=port,
                    state="open",
                    # The scheme is observed, not assumed: an HTTP exchange
                    # completed on this port.
                    service_name=target.scheme,
                ),
            ),
        )
        status_line = f"HTTP {outcome.status} {outcome.reason or ''}".strip()
        observations = [
            DiscoveredObservation(
                observation_type="http_response",
                summary=f"{target.value} returned {status_line}",
                confidence=Confidence.OBSERVED,
                asset_identity=target.value,
                service_port=("tcp", port),
                detail={"status": outcome.status, "address": address},
            )
        ]
        for header, value in (outcome.headers or {}).items():
            observations.append(
                DiscoveredObservation(
                    observation_type="http_header",
                    summary=f"{target.value} reported {header}: {value}",
                    confidence=Confidence.REPORTED,
                    asset_identity=target.value,
                    service_port=("tcp", port),
                    detail={"header": header, "value": value},
                )
            )
        if outcome.tls:
            verified = "verified" if outcome.tls.get("verified") else "unverified"
            observations.append(
                DiscoveredObservation(
                    observation_type="tls_session",
                    summary=(
                        f"{target.value} presented a {outcome.tls.get('version')} session "
                        f"with a {verified} certificate"
                    ),
                    confidence=Confidence.OBSERVED,
                    asset_identity=target.value,
                    service_port=("tcp", port),
                    detail=dict(outcome.tls),
                )
            )
        return (asset,), tuple(observations)


def _port(target: Target) -> int:
    return target.port or (443 if target.scheme == "https" else 80)


def _probe(target: Target, address: str, timeout: int, method: str) -> ProbeOutcome:
    endpoint = (address, _port(target))
    connected: socket.socket | None = None
    tls: dict[str, object] | None = None
    try:
        connected = socket.create_connection(endpoint, timeout=timeout)
        if target.scheme == "https":
            connected, tls = _start_tls(connected, target.host, endpoint, timeout)
        status, reason, headers = _request(connected, target, method)
        return ProbeOutcome(status=status, reason=reason, headers=headers, tls=tls)
    except (OSError, http.client.HTTPException) as error:
        return ProbeOutcome(tls=tls, error=_describe_error(error))
    finally:
        if connected is not None:
            connected.close()


def _request(
    connected: socket.socket, target: Target, method: str
) -> tuple[int, str, dict[str, str]]:
    authority = target.value.split("://", 1)[1]
    connection = http.client.HTTPConnection(authority)
    connection.sock = connected
    connection.request(
        method,
        "/",
        headers={
            "Host": authority,
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
        },
    )
    response = connection.getresponse()
    headers = {
        name: (response.headers.get(name) or "")[:_MAX_HEADER_LENGTH]
        for name in _RECORDED_HEADERS
        if response.headers.get(name)
    }
    return response.status, response.reason, headers


def _start_tls(
    raw_socket: socket.socket,
    hostname: str,
    endpoint: tuple[str, int],
    timeout: int,
) -> tuple[socket.socket, dict[str, object]]:
    """Complete a TLS handshake, tolerating lab certificates but reporting them.

    Verification is attempted first. When it fails the handshake is retried
    without verification so a self-signed lab endpoint can still be observed,
    and the recorded evidence states that the certificate was not verified.
    """
    try:
        secure = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=hostname)
        return secure, _tls_details(secure, verified=True)
    except ssl.SSLError:
        raw_socket.close()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    retry = socket.create_connection(endpoint, timeout=timeout)
    try:
        secure = context.wrap_socket(retry, server_hostname=hostname)
    except OSError:
        retry.close()
        raise
    return secure, _tls_details(secure, verified=False)


def _tls_details(secure: ssl.SSLSocket, *, verified: bool) -> dict[str, object]:
    details: dict[str, object] = {"verified": verified, "version": secure.version()}
    cipher = secure.cipher()
    if cipher:
        details["cipher"] = cipher[0]
    binary = secure.getpeercert(binary_form=True)
    if binary:
        details["certificate_sha256"] = sha256(binary).hexdigest()
    certificate = secure.getpeercert()
    if certificate:
        details["subject"] = _distinguished_name(certificate.get("subject", ()))
        details["issuer"] = _distinguished_name(certificate.get("issuer", ()))
        details["not_after"] = certificate.get("notAfter")
    return details


def _distinguished_name(parts: object) -> str:
    if not isinstance(parts, tuple):
        return ""
    return ", ".join(
        f"{key}={value}" for entry in parts if isinstance(entry, tuple) for key, value in entry
    )


def _transcript(target: Target, address: str, outcome: ProbeOutcome) -> RawArtifact:
    body = {
        "origin": target.value,
        "address": address,
        "status": outcome.status,
        "reason": outcome.reason,
        "headers": outcome.headers or {},
        "tls": outcome.tls,
        "error": outcome.error,
    }
    return RawArtifact(
        name="http-probe.json",
        media_type="application/json",
        content=json.dumps(body, indent=2, sort_keys=True).encode(),
    )


def _describe_error(error: Exception) -> str:
    if isinstance(error, OSError) and error.strerror:
        return f"{type(error).__name__}: {error.strerror}"
    return f"{type(error).__name__}: {error}"
