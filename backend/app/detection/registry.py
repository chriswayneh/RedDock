"""The reviewed built-ins plus bounded, data-only detector manifests.

Built-ins remain explicit. An optional deployment-owned directory may add only
declarative rules compiled by RedDock; no module name or executable code is
loaded. The set is frozen on first use and changes only after a process restart.
"""

from functools import lru_cache

from app.config import get_settings
from app.detection.base import Detector
from app.detection.detectors.http_headers import HttpSecurityHeaderDetector
from app.detection.detectors.service_rules import ServiceRuleDetector
from app.detection.detectors.tls_certificates import TlsCertificateDetector
from app.detector_plugins import PluginConfigurationError, load_declarative_detectors

_BUILT_INS: tuple[Detector, ...] = (
    HttpSecurityHeaderDetector(),
    ServiceRuleDetector(),
    TlsCertificateDetector(),
)


def available_detectors() -> tuple[Detector, ...]:
    detectors = _BUILT_INS + _configured(get_settings().detector_plugin_dir)
    ids = [detector.id for detector in detectors]
    if len(ids) != len(set(ids)):
        raise PluginConfigurationError("Configured detector IDs conflict with a built-in detector")
    return detectors


def get_detector(detector_id: str) -> Detector | None:
    return next(
        (detector for detector in available_detectors() if detector.id == detector_id), None
    )


@lru_cache(maxsize=16)
def _configured(directory: str | None) -> tuple[Detector, ...]:
    return load_declarative_detectors(directory)


def clear_plugin_cache() -> None:
    """Tests and controlled process setup may rebuild the frozen registry."""
    _configured.cache_clear()
