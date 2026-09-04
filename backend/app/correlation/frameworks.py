"""The fixed, reviewable CWE mappings shipped with RedDock.

Mappings classify the detector's conclusion; they are not extra evidence and
never change severity, confidence, status, or validation outcome.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Mapping:
    external_id: str
    title: str


VERSION = "1.0.0"
FRAMEWORK = "CWE"

RULE_MAPPINGS: dict[str, Mapping] = {
    "plaintext-http": Mapping("CWE-319", "Cleartext Transmission of Sensitive Information"),
    "hsts-not-set": Mapping("CWE-319", "Cleartext Transmission of Sensitive Information"),
    "content-type-options-not-nosniff": Mapping(
        "CWE-693", "Protection Mechanism Failure"
    ),
    "content-security-policy-not-set": Mapping("CWE-693", "Protection Mechanism Failure"),
    "frame-protection-not-set": Mapping("CWE-1021", "Improper Restriction of Rendered UI Layers"),
    "cleartext-remote-administration": Mapping(
        "CWE-319", "Cleartext Transmission of Sensitive Information"
    ),
    "cleartext-file-transfer": Mapping(
        "CWE-319", "Cleartext Transmission of Sensitive Information"
    ),
    "service-version-disclosed": Mapping(
        "CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"
    ),
    "certificate-expired": Mapping("CWE-295", "Improper Certificate Validation"),
    "certificate-not-trusted": Mapping("CWE-295", "Improper Certificate Validation"),
}
