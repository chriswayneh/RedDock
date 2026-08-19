"""The fixed set of detectors RedDock is allowed to run.

Detectors are listed here explicitly, exactly as discovery adapters are. Nothing
is imported by name from configuration, discovered on a path or loaded from a
plugin directory, so a detector cannot arrive at runtime and the set a reviewer
reads here is the set that runs.
"""

from app.detection.base import Detector
from app.detection.detectors.http_headers import HttpSecurityHeaderDetector
from app.detection.detectors.service_rules import ServiceRuleDetector
from app.detection.detectors.tls_certificates import TlsCertificateDetector

_DETECTORS: tuple[Detector, ...] = (
    HttpSecurityHeaderDetector(),
    ServiceRuleDetector(),
    TlsCertificateDetector(),
)


def available_detectors() -> tuple[Detector, ...]:
    return _DETECTORS


def get_detector(detector_id: str) -> Detector | None:
    return next((detector for detector in _DETECTORS if detector.id == detector_id), None)
