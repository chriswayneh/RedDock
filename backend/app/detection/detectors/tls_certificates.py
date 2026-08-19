"""TLS certificate detector.

This detector reads the TLS session RedDock already recorded and reports what
certificate verification objected to. It performs no handshake of its own and no
cipher or protocol enumeration.

The scope is deliberately narrow, because the honest scope is narrow. The HTTP
probe connects with a default client, so it can only ever record a protocol
version that a current client was willing to negotiate; a rule about obsolete
protocol versions would therefore never be able to fire from RedDock's own data,
and shipping one would suggest a capability that does not exist. What RedDock
does establish is the verification outcome, so that is what this detector
reports.
"""

from app.detection.base import (
    DetectedFinding,
    DetectionContext,
    Detector,
    FindingCategory,
    FindingConfidence,
    ObservationView,
    Severity,
)

#: OpenSSL X509_V_ERR_CERT_HAS_EXPIRED. A verification failure is generic until
#: the code says which check failed, so the code is what the rules key on.
CERT_HAS_EXPIRED = 10


class TlsCertificateDetector(Detector):
    id = "tls.certificates"
    version = "1.0.0"
    title = "TLS certificate validation"
    description = (
        "Reports the outcome of certificate verification for TLS sessions RedDock recorded."
    )
    consumes = ("tls_session",)

    def detect(self, context: DetectionContext) -> tuple[DetectedFinding, ...]:
        findings = []
        for session in _latest_sessions(context):
            finding = self._for_session(context, session)
            if finding is not None:
                findings.append(finding)
        return tuple(findings)

    def _for_session(
        self, context: DetectionContext, session: ObservationView
    ) -> DetectedFinding | None:
        verified = session.detail.get("verified")
        if verified is not False:
            # Either verification succeeded, or the record predates RedDock
            # stating the outcome. Neither supports a claim.
            return None

        origin = _origin(context, session)
        code = session.detail.get("verify_code")
        message = session.detail.get("verify_message")
        reason = str(message) if isinstance(message, str) and message else None
        detail: dict[str, object] = {
            "verify_code": code if isinstance(code, int) else None,
            "verify_message": reason,
            "tls_version": session.detail.get("version"),
            "certificate_sha256": session.detail.get("certificate_sha256"),
            "discovery_run_id": session.discovery_run_id,
        }

        if code == CERT_HAS_EXPIRED:
            return DetectedFinding(
                rule_id="certificate-expired",
                title=f"{origin} presents an expired TLS certificate",
                description=(
                    f"Certificate verification for {origin} failed because the certificate has "
                    "expired. A client that checks certificates will refuse this endpoint or "
                    "warn about it, and operators who click past that warning lose the "
                    "protection the certificate was there to provide."
                ),
                category=FindingCategory.TRANSPORT,
                severity=Severity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                evidence_observation_ids=(session.id,),
                asset_id=session.asset_id,
                service_id=session.service_id,
                remediation=(
                    "Reissue the certificate for this endpoint and renew it automatically "
                    "before expiry."
                ),
                detail=detail,
            )

        explanation = f' OpenSSL reported: "{reason}".' if reason else ""
        return DetectedFinding(
            rule_id="certificate-not-trusted",
            title=f"{origin} presents a certificate that did not verify",
            description=(
                f"RedDock completed a TLS handshake with {origin}, but the certificate did not "
                f"verify against the trust store in the RedDock container.{explanation} A private "
                "certificate authority, a self-signed lab certificate or a name that does not "
                "match the endpoint are all legitimate causes, so this reports a verification "
                "outcome rather than a defect. The certificate SHA-256 is retained as evidence "
                "so the same certificate can be recognised later."
            ),
            category=FindingCategory.TRANSPORT,
            severity=Severity.LOW,
            confidence=FindingConfidence.HIGH,
            evidence_observation_ids=(session.id,),
            asset_id=session.asset_id,
            service_id=session.service_id,
            remediation=(
                "Confirm the certificate is the one intended for this endpoint. If a private "
                "authority issued it, add that authority to the trust store used to assess it; "
                "otherwise issue a certificate that a client can verify."
            ),
            detail=detail,
        )


def _latest_sessions(context: DetectionContext) -> list[ObservationView]:
    """The most recent recorded TLS session for each endpoint, in a stable order."""
    latest: dict[tuple[int | None, int | None], ObservationView] = {}
    for observation in context.of_type("tls_session"):
        key = (observation.asset_id, observation.service_id)
        current = latest.get(key)
        if current is None or (observation.observed_at, observation.id) >= (
            current.observed_at,
            current.id,
        ):
            latest[key] = observation
    return sorted(latest.values(), key=lambda observation: observation.id)


def _origin(context: DetectionContext, session: ObservationView) -> str:
    asset = context.asset(session.asset_id)
    return asset.identity if asset is not None else "this endpoint"
