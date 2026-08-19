"""HTTP security-header detector tests.

These assert as hard on what the detector refuses to say as on what it says. A
header detector that reports every absent header on every response is easy to
write and useless to read.
"""

from fastapi.testclient import TestClient

from app.detection.detectors.http_headers import HttpSecurityHeaderDetector
from app.detection.registry import available_detectors
from tests.phase1 import Recorder

SECURE_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
}


def rules(recorder: Recorder) -> set[str]:
    context = _context(recorder)
    return {finding.rule_id for finding in HttpSecurityHeaderDetector().detect(context)}


def _context(recorder: Recorder):
    from app.detection.context import build_context

    recorder.session.commit()
    return build_context(recorder.session, recorder.dockyard_id)


def test_a_fully_protected_https_response_produces_no_finding(
    client: TestClient, recorder: Recorder
):
    recorder.http_endpoint("https://127.0.0.1:8443", headers=SECURE_HEADERS)
    assert rules(recorder) == set()


def test_one_missing_header_produces_exactly_one_finding(
    client: TestClient, recorder: Recorder
):
    headers = dict(SECURE_HEADERS)
    del headers["x-content-type-options"]
    recorder.http_endpoint("https://127.0.0.1:8443", headers=headers)

    assert rules(recorder) == {"content-type-options-not-nosniff"}


def test_several_missing_headers_produce_one_finding_each(
    client: TestClient, recorder: Recorder
):
    recorder.http_endpoint("https://127.0.0.1:8443", headers={})

    assert rules(recorder) == {
        "hsts-not-set",
        "content-type-options-not-nosniff",
        "content-security-policy-not-set",
        "frame-protection-not-set",
    }


def test_plaintext_http_is_the_finding_and_hsts_is_not(client: TestClient, recorder: Recorder):
    """HSTS over plaintext is meaningless, so its absence is not reported there."""
    recorder.http_endpoint("http://127.0.0.1:8080", headers={})
    found = rules(recorder)

    assert "plaintext-http" in found
    assert "hsts-not-set" not in found


def test_https_is_not_reported_as_plaintext(client: TestClient, recorder: Recorder):
    recorder.http_endpoint("https://127.0.0.1:8443", headers=SECURE_HEADERS)
    assert "plaintext-http" not in rules(recorder)


def test_a_plaintext_redirect_to_https_is_not_a_finding(client: TestClient, recorder: Recorder):
    """Redirecting HTTP to HTTPS is the correct configuration, not a defect."""
    recorder.http_endpoint(
        "http://127.0.0.1:8080",
        status=301,
        headers={"location": "https://127.0.0.1:8443/"},
    )
    assert rules(recorder) == set()


def test_a_redirect_is_not_evidence_that_content_headers_are_missing(
    client: TestClient, recorder: Recorder
):
    recorder.http_endpoint("https://127.0.0.1:8443", status=302, headers=SECURE_HEADERS | {})
    assert rules(recorder) == set()

    recorder.http_endpoint(
        "https://127.0.0.1:9443", status=302, headers={"location": "https://elsewhere.local/"}
    )
    # Only the header that still applies to a redirect is reported.
    assert rules(recorder) == {"hsts-not-set"}


def test_a_server_error_is_not_judged_for_content_headers(client: TestClient, recorder: Recorder):
    recorder.http_endpoint(
        "https://127.0.0.1:8443",
        status=503,
        headers={"strict-transport-security": "max-age=63072000"},
    )
    assert rules(recorder) == set()


def test_a_client_error_is_still_a_real_response(client: TestClient, recorder: Recorder):
    recorder.http_endpoint("https://127.0.0.1:8443", status=404, headers=SECURE_HEADERS)
    assert rules(recorder) == set()

    recorder.http_endpoint("https://127.0.0.1:9443", status=404, headers={})
    assert "content-security-policy-not-set" in rules(recorder)


def test_a_header_the_probe_never_examined_is_never_reported(
    client: TestClient, recorder: Recorder
):
    """Absence of evidence is not evidence of absence, and RedDock says so."""
    recorder.http_endpoint(
        "https://127.0.0.1:8443",
        headers={},
        examined=["server", "content-type"],
    )
    assert rules(recorder) == set()


def test_a_response_recorded_without_an_examined_set_produces_nothing(
    client: TestClient, recorder: Recorder
):
    recorder.http_endpoint("https://127.0.0.1:8443", headers={}, examined=[])
    assert rules(recorder) == set()


def test_content_security_policy_frame_ancestors_replaces_x_frame_options(
    client: TestClient, recorder: Recorder
):
    headers = dict(SECURE_HEADERS)
    del headers["x-frame-options"]
    recorder.http_endpoint("https://127.0.0.1:8443", headers=headers)

    assert "frame-protection-not-set" not in rules(recorder)


def test_a_policy_without_frame_ancestors_does_not_replace_x_frame_options(
    client: TestClient, recorder: Recorder
):
    headers = dict(SECURE_HEADERS)
    del headers["x-frame-options"]
    headers["content-security-policy"] = "default-src 'self'"
    recorder.http_endpoint("https://127.0.0.1:8443", headers=headers)

    assert "frame-protection-not-set" in rules(recorder)


def test_a_wrong_content_type_options_value_is_reported_with_what_was_seen(
    client: TestClient, recorder: Recorder
):
    headers = dict(SECURE_HEADERS) | {"x-content-type-options": "sniff"}
    recorder.http_endpoint("https://127.0.0.1:8443", headers=headers)

    findings = HttpSecurityHeaderDetector().detect(_context(recorder))
    finding = next(item for item in findings if item.rule_id == "content-type-options-not-nosniff")
    assert "sniff" in finding.description
    assert finding.detail["x-content-type-options"] == "sniff"


def test_only_the_most_recent_response_for_an_endpoint_is_judged(
    client: TestClient, recorder: Recorder
):
    """An endpoint that was fixed stops being reported without deleting history."""
    asset, service, first = recorder.http_endpoint("https://127.0.0.1:8443", headers={})
    assert rules(recorder) == {
        "hsts-not-set",
        "content-type-options-not-nosniff",
        "content-security-policy-not-set",
        "frame-protection-not-set",
    }

    later = recorder.discovery_run()
    recorder.observation(
        later,
        "http_response",
        "https://127.0.0.1:8443 returned HTTP 200",
        asset=asset,
        service=service,
        detail={
            "status": 200,
            "scheme": "https",
            "headers_examined": list(SECURE_HEADERS) + ["location"],
            "headers_present": sorted(SECURE_HEADERS),
        },
    )
    for name, value in SECURE_HEADERS.items():
        recorder.observation(
            later,
            "http_header",
            f"https://127.0.0.1:8443 reported {name}: {value}",
            asset=asset,
            service=service,
            detail={"header": name, "value": value},
            confidence="reported",
        )
    recorder.session.commit()

    assert rules(recorder) == set()


def test_severity_stays_restrained_for_hardening_headers(client: TestClient, recorder: Recorder):
    recorder.http_endpoint("https://127.0.0.1:8443", headers={})
    findings = HttpSecurityHeaderDetector().detect(_context(recorder))

    assert {str(finding.severity) for finding in findings} == {"low"}
    assert {str(finding.confidence) for finding in findings} == {"high"}


def test_every_finding_cites_the_response_it_was_drawn_from(
    client: TestClient, recorder: Recorder
):
    recorder.http_endpoint("https://127.0.0.1:8443", headers={})
    for finding in HttpSecurityHeaderDetector().detect(_context(recorder)):
        assert finding.evidence_observation_ids


def test_the_detector_is_registered_and_declares_what_it_reads():
    detector = next(item for item in available_detectors() if item.id == "http.security_headers")
    assert detector.consumes == ("http_response", "http_header")
