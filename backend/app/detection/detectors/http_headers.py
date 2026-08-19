"""HTTP security-header detector.

This detector reads the response RedDock already recorded for an origin and
reports the response-level protections that were not in place. It contacts
nothing and re-requests nothing.

Three things keep it from producing the usual noise:

- It only speaks about headers the probe actually examined. Every response
  observation records the header set that was looked for, and a header outside
  that set produces no finding, because "RedDock did not look" is not the same
  statement as "the server did not send it".
- It accounts for the scheme. Strict-Transport-Security is only meaningful over
  HTTPS, so its absence over plaintext HTTP is not reported as a gap; the
  plaintext transport itself is the finding there.
- It only judges a response that represents how the endpoint normally answers.
  Redirects and server errors are skipped for content-level headers, because a
  301 to HTTPS carrying no Content-Security-Policy is a correct configuration
  and reporting it would be a false positive.

Severity is deliberately restrained. A missing hardening header is a
defence-in-depth gap, not a demonstrated weakness, so these are `low` with high
confidence rather than the inflated ratings that make a findings list useless.
"""

from collections.abc import Mapping, Sequence

from app.detection.base import (
    DetectedFinding,
    DetectionContext,
    Detector,
    FindingCategory,
    FindingConfidence,
    ObservationView,
    Severity,
)

HSTS = "strict-transport-security"
CONTENT_TYPE_OPTIONS = "x-content-type-options"
CONTENT_SECURITY_POLICY = "content-security-policy"
FRAME_OPTIONS = "x-frame-options"
LOCATION = "location"

_NOSNIFF = "nosniff"
_FRAME_ANCESTORS = "frame-ancestors"


class HttpSecurityHeaderDetector(Detector):
    id = "http.security_headers"
    version = "1.0.0"
    title = "HTTP security headers"
    description = (
        "Reports response-level protections that the recorded HTTP response did not carry, "
        "for the headers the probe examined."
    )
    consumes = ("http_response", "http_header")

    def detect(self, context: DetectionContext) -> tuple[DetectedFinding, ...]:
        findings: list[DetectedFinding] = []
        for response in _latest_responses(context):
            findings.extend(self._for_response(context, response))
        return tuple(findings)

    def _for_response(
        self, context: DetectionContext, response: ObservationView
    ) -> list[DetectedFinding]:
        examined = _examined(response)
        if not examined:
            # A response recorded before RedDock stated what it looked for
            # cannot support an absence claim.
            return []

        scheme = _scheme(context, response)
        if scheme is None:
            return []
        status = response.detail.get("status")
        if not isinstance(status, int):
            return []

        headers = _headers_for(context, response)
        origin = _origin(context, response)
        findings: list[DetectedFinding] = []

        if scheme == "http":
            finding = self._plaintext(response, headers, status, origin)
            if finding is not None:
                findings.append(finding)
        elif HSTS in examined and HSTS not in headers:
            findings.append(self._missing_hsts(response, status, origin))

        if not _is_content_response(status):
            return findings

        if CONTENT_TYPE_OPTIONS in examined:
            finding = self._content_type_options(response, headers, status, origin)
            if finding is not None:
                findings.append(finding)
        if CONTENT_SECURITY_POLICY in examined and CONTENT_SECURITY_POLICY not in headers:
            findings.append(self._missing_csp(response, status, origin))
        if FRAME_OPTIONS in examined:
            finding = self._frame_protection(response, headers, status, origin)
            if finding is not None:
                findings.append(finding)
        return findings

    def _plaintext(
        self,
        response: ObservationView,
        headers: Mapping[str, tuple[str, int]],
        status: int,
        origin: str,
    ) -> DetectedFinding | None:
        location = headers.get(LOCATION)
        if 300 <= status < 400 and location and location[0].lower().startswith("https://"):
            # A redirect to HTTPS is the correct answer on a plaintext port.
            return None
        return self._finding(
            response,
            headers,
            rule_id="plaintext-http",
            title=f"{origin} answers over plaintext HTTP",
            description=(
                f"RedDock completed an HTTP exchange with {origin} over plaintext and received "
                f"HTTP {status}. Anything sent to this origin, including credentials and session "
                "cookies, travels the network unprotected and can be read or altered in transit. "
                "This severity describes the transport itself and does not account for how "
                "exposed the network path is."
            ),
            category=FindingCategory.TRANSPORT,
            severity=Severity.MEDIUM,
            confidence=FindingConfidence.HIGH,
            remediation=(
                "Serve this origin over HTTPS and redirect plaintext requests to it, then set "
                "Strict-Transport-Security on the HTTPS origin."
            ),
            status=status,
            scheme="http",
            related=(LOCATION,),
        )

    def _missing_hsts(
        self, response: ObservationView, status: int, origin: str
    ) -> DetectedFinding:
        return self._finding(
            response,
            {},
            rule_id="hsts-not-set",
            title=f"{origin} does not set Strict-Transport-Security",
            description=(
                f"The HTTPS response from {origin} (HTTP {status}) carried no "
                "Strict-Transport-Security header. Without it a browser will still attempt a "
                "plaintext request to this origin, which leaves the first request of a session "
                "open to interception or downgrade."
            ),
            category=FindingCategory.HARDENING,
            severity=Severity.LOW,
            confidence=FindingConfidence.HIGH,
            remediation=(
                "Send Strict-Transport-Security with a max-age the operator is prepared to "
                "commit to, once every path on the origin is served over HTTPS."
            ),
            status=status,
            scheme="https",
        )

    def _content_type_options(
        self,
        response: ObservationView,
        headers: Mapping[str, tuple[str, int]],
        status: int,
        origin: str,
    ) -> DetectedFinding | None:
        present = headers.get(CONTENT_TYPE_OPTIONS)
        if present is not None and present[0].strip().lower() == _NOSNIFF:
            return None
        observed = (
            f"sent X-Content-Type-Options: {present[0]}"
            if present is not None
            else "sent no X-Content-Type-Options header"
        )
        return self._finding(
            response,
            headers,
            rule_id="content-type-options-not-nosniff",
            title=f"{origin} does not set X-Content-Type-Options: nosniff",
            description=(
                f"The response from {origin} (HTTP {status}) {observed}. A browser may then "
                "infer a content type other than the one declared, so a response intended as "
                "data can be treated as script or markup."
            ),
            category=FindingCategory.HARDENING,
            severity=Severity.LOW,
            confidence=FindingConfidence.HIGH,
            remediation="Send X-Content-Type-Options: nosniff on every response.",
            status=status,
            scheme=None,
            related=(CONTENT_TYPE_OPTIONS,),
        )

    def _missing_csp(self, response: ObservationView, status: int, origin: str) -> DetectedFinding:
        return self._finding(
            response,
            {},
            rule_id="content-security-policy-not-set",
            title=f"{origin} does not set a Content-Security-Policy",
            description=(
                f"The response from {origin} (HTTP {status}) carried no Content-Security-Policy "
                "header. The browser therefore applies no restriction on where scripts, styles "
                "and frames may be loaded from, which removes a control that limits the impact "
                "of an injection flaw elsewhere in the application. RedDock has not tested this "
                "origin for injection flaws."
            ),
            category=FindingCategory.HARDENING,
            severity=Severity.LOW,
            confidence=FindingConfidence.HIGH,
            remediation=(
                "Define a Content-Security-Policy for this origin, starting in report-only mode "
                "so the policy can be validated before it is enforced."
            ),
            status=status,
            scheme=None,
        )

    def _frame_protection(
        self,
        response: ObservationView,
        headers: Mapping[str, tuple[str, int]],
        status: int,
        origin: str,
    ) -> DetectedFinding | None:
        if FRAME_OPTIONS in headers:
            return None
        policy = headers.get(CONTENT_SECURITY_POLICY)
        if policy is not None and _FRAME_ANCESTORS in policy[0].lower():
            # Content-Security-Policy frame-ancestors supersedes X-Frame-Options.
            return None
        return self._finding(
            response,
            headers,
            rule_id="frame-protection-not-set",
            title=f"{origin} does not restrict framing",
            description=(
                f"The response from {origin} (HTTP {status}) carried neither an X-Frame-Options "
                "header nor a Content-Security-Policy frame-ancestors directive, so another "
                "site may embed this origin in a frame."
            ),
            category=FindingCategory.HARDENING,
            severity=Severity.LOW,
            confidence=FindingConfidence.HIGH,
            remediation=(
                "Add a Content-Security-Policy frame-ancestors directive naming the origins "
                "allowed to frame this one, or none at all."
            ),
            status=status,
            scheme=None,
            related=(CONTENT_SECURITY_POLICY,),
        )

    def _finding(
        self,
        response: ObservationView,
        headers: Mapping[str, tuple[str, int]],
        *,
        rule_id: str,
        title: str,
        description: str,
        category: FindingCategory,
        severity: Severity,
        confidence: FindingConfidence,
        remediation: str,
        status: int,
        scheme: str | None,
        related: Sequence[str] = (),
    ) -> DetectedFinding:
        evidence = [response.id]
        detail: dict[str, object] = {
            "status": status,
            "discovery_run_id": response.discovery_run_id,
        }
        if scheme is not None:
            detail["scheme"] = scheme
        for header in related:
            found = headers.get(header)
            if found is None:
                continue
            detail[header] = found[0]
            evidence.append(found[1])
        return DetectedFinding(
            rule_id=rule_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            evidence_observation_ids=tuple(dict.fromkeys(evidence)),
            asset_id=response.asset_id,
            service_id=response.service_id,
            remediation=remediation,
            detail=detail,
        )


def _latest_responses(context: DetectionContext) -> list[ObservationView]:
    """The most recent recorded response for each endpoint, in a stable order.

    Observations accumulate as history, so an endpoint probed three times has
    three responses. Only the newest describes how it answers now.
    """
    latest: dict[tuple[int | None, int | None], ObservationView] = {}
    for observation in context.of_type("http_response"):
        key = (observation.asset_id, observation.service_id)
        current = latest.get(key)
        if current is None or (observation.observed_at, observation.id) >= (
            current.observed_at,
            current.id,
        ):
            latest[key] = observation
    return sorted(latest.values(), key=lambda observation: observation.id)


def _headers_for(
    context: DetectionContext, response: ObservationView
) -> dict[str, tuple[str, int]]:
    """Header values recorded by the same discovery run, with their observation."""
    headers: dict[str, tuple[str, int]] = {}
    for observation in context.of_type("http_header"):
        if observation.discovery_run_id != response.discovery_run_id:
            continue
        if (observation.asset_id, observation.service_id) != (
            response.asset_id,
            response.service_id,
        ):
            continue
        name = observation.detail.get("header")
        value = observation.detail.get("value")
        if isinstance(name, str) and isinstance(value, str):
            headers[name.lower()] = (value, observation.id)
    return headers


def _is_content_response(status: int) -> bool:
    """Whether this response represents how the endpoint normally answers.

    A redirect is a routing instruction and a server error is a failure; neither
    is the application's normal response, so neither is evidence that a
    content-level header is missing from it.
    """
    return status < 300 or 400 <= status < 500


def _examined(response: ObservationView) -> frozenset[str]:
    raw = response.detail.get("headers_examined")
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(item.lower() for item in raw if isinstance(item, str))


def _scheme(context: DetectionContext, response: ObservationView) -> str | None:
    """The scheme of the exchange, taken from the response or the origin."""
    recorded = response.detail.get("scheme")
    if recorded in ("http", "https"):
        return str(recorded)
    asset = context.asset(response.asset_id)
    if asset is None:
        return None
    for scheme in ("https", "http"):
        if asset.identity.startswith(f"{scheme}://"):
            return scheme
    return None


def _origin(context: DetectionContext, response: ObservationView) -> str:
    asset = context.asset(response.asset_id)
    return asset.identity if asset is not None else "this origin"
