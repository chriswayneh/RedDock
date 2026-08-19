"""Service rule and TLS certificate detector tests."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.detection.context import build_context
from app.detection.detectors.service_rules import ServiceRuleDetector
from app.detection.detectors.tls_certificates import TlsCertificateDetector
from app.detection.enrichment import CATALOG_SCHEMA, load_enrichment
from tests.phase1 import Recorder


def context(recorder: Recorder, enrichment=None):
    recorder.session.commit()
    return build_context(recorder.session, recorder.dockyard_id, enrichment=enrichment)


def service_findings(recorder: Recorder, enrichment=None):
    return ServiceRuleDetector().detect(context(recorder, enrichment))


class TestServiceRules:
    def test_telnet_is_reported_as_cleartext_administration(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.identified_service("192.168.1.10", 23, service_name="telnet")
        findings = service_findings(recorder)

        assert [finding.rule_id for finding in findings] == ["cleartext-remote-administration"]
        assert str(findings[0].severity) == "high"
        # The identification came from a banner, so this is not stated as certain.
        assert str(findings[0].confidence) == "medium"

    def test_ftp_is_reported_without_claiming_auth_tls_was_tested(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.identified_service("192.168.1.10", 21, service_name="ftp")
        finding = service_findings(recorder)[0]

        assert finding.rule_id == "cleartext-file-transfer"
        assert str(finding.severity) == "medium"
        assert "did not test whether AUTH TLS is required" in finding.description

    def test_a_service_with_no_rule_produces_no_finding(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.identified_service("192.168.1.10", 22, service_name="ssh")
        assert service_findings(recorder) == ()

    def test_a_port_number_alone_is_never_enough(self, client: TestClient, recorder: Recorder):
        """TCP/23 open is TCP/23 open. Without an identification it says nothing."""
        asset = recorder.asset("192.168.1.10", asset_type="host")
        recorder.service(asset, 23)
        recorder.session.commit()

        assert service_findings(recorder) == ()

    def test_a_service_identified_without_an_observation_produces_nothing(
        self, client: TestClient, recorder: Recorder
    ):
        """Evidence is required, not preferred."""
        asset = recorder.asset("192.168.1.10", asset_type="host")
        recorder.service(asset, 23, service_name="telnet")
        recorder.session.commit()

        assert service_findings(recorder) == ()

    def test_a_disclosed_version_is_informational_not_a_vulnerability(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.identified_service(
            "192.168.1.10", 22, service_name="ssh", product="OpenSSH", version="7.2p2"
        )
        finding = service_findings(recorder)[0]

        assert finding.rule_id == "service-version-disclosed"
        assert str(finding.severity) == "informational"
        assert finding.cve_references == ()

    def test_a_product_without_a_version_discloses_nothing_to_report(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.identified_service(
            "192.168.1.10", 22, service_name="ssh", product="OpenSSH", version=None
        )
        assert service_findings(recorder) == ()


class TestCveEnrichment:
    @pytest.fixture()
    def catalog(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        path = tmp_path / "catalog.json"
        path.write_text(
            json.dumps(
                {
                    "schema": CATALOG_SCHEMA,
                    "source": "lab-catalogue",
                    "version": "2026-08-01",
                    "entries": [
                        {
                            "product": "OpenSSH",
                            "version": "7.2p2",
                            "cve": ["CVE-2016-6515", "CVE-2016-6210"],
                            "url": "https://example.invalid/openssh-7.2p2",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("REDDOCK_CVE_CATALOG", str(path))
        import app.config

        app.config.get_settings.cache_clear()
        yield path
        app.config.get_settings.cache_clear()

    def test_no_catalogue_means_no_enrichment_and_no_error(self, client: TestClient):
        enrichment, warning = load_enrichment()
        assert enrichment.available is False
        assert warning is None
        assert enrichment.lookup("OpenSSH", "7.2p2") == ()

    def test_an_exact_product_and_version_match_is_attached_with_provenance(
        self, client: TestClient, recorder: Recorder, catalog: Path
    ):
        recorder.identified_service(
            "192.168.1.10", 22, service_name="ssh", product="OpenSSH", version="7.2p2"
        )
        enrichment, warning = load_enrichment()
        assert warning is None

        finding = service_findings(recorder, enrichment)[0]
        assert [reference.cve_id for reference in finding.cve_references] == [
            "CVE-2016-6210",
            "CVE-2016-6515",
        ]
        assert finding.cve_references[0].source == "lab-catalogue"
        assert finding.cve_references[0].source_version == "2026-08-01"
        assert finding.cve_references[0].match_type == "exact_version"

    def test_enrichment_never_changes_severity(
        self, client: TestClient, recorder: Recorder, catalog: Path
    ):
        """A CVE association is not a test result, so it cannot raise a rating."""
        recorder.identified_service(
            "192.168.1.10", 22, service_name="ssh", product="OpenSSH", version="7.2p2"
        )
        enrichment, _ = load_enrichment()

        enriched = service_findings(recorder, enrichment)[0]
        plain = service_findings(recorder)[0]
        assert str(enriched.severity) == str(plain.severity) == "informational"
        assert str(enriched.confidence) == str(plain.confidence)

    def test_the_description_says_an_association_is_not_a_test_result(
        self, client: TestClient, recorder: Recorder, catalog: Path
    ):
        recorder.identified_service(
            "192.168.1.10", 22, service_name="ssh", product="OpenSSH", version="7.2p2"
        )
        enrichment, _ = load_enrichment()
        finding = service_findings(recorder, enrichment)[0]

        assert "not a test result" in finding.description
        assert "did not check whether this service is affected" in finding.description

    def test_a_different_version_is_not_matched(
        self, client: TestClient, recorder: Recorder, catalog: Path
    ):
        recorder.identified_service(
            "192.168.1.10", 22, service_name="ssh", product="OpenSSH", version="9.6p1"
        )
        enrichment, _ = load_enrichment()

        assert service_findings(recorder, enrichment)[0].cve_references == ()

    def test_matching_ignores_casing_and_spacing_only(self, client: TestClient, catalog: Path):
        enrichment, _ = load_enrichment()
        assert enrichment.lookup("openssh", "7.2P2")
        assert enrichment.lookup("OpenSSH", "7.2") == ()

    def test_a_missing_catalogue_is_a_warning_not_a_failure(
        self, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("REDDOCK_CVE_CATALOG", str(tmp_path / "absent.json"))
        import app.config

        app.config.get_settings.cache_clear()
        try:
            enrichment, warning = load_enrichment()
        finally:
            app.config.get_settings.cache_clear()

        assert enrichment.available is False
        assert warning is not None and "does not exist" in warning

    def test_a_malformed_catalogue_is_a_warning_not_a_failure(
        self, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        broken = tmp_path / "broken.json"
        broken.write_text("{ not json", encoding="utf-8")
        monkeypatch.setenv("REDDOCK_CVE_CATALOG", str(broken))
        import app.config

        app.config.get_settings.cache_clear()
        try:
            enrichment, warning = load_enrichment()
        finally:
            app.config.get_settings.cache_clear()

        assert enrichment.available is False
        assert warning is not None and "was not loaded" in warning

    def test_a_catalogue_without_the_expected_schema_is_refused(
        self, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        wrong = tmp_path / "wrong.json"
        wrong.write_text(json.dumps({"entries": []}), encoding="utf-8")
        monkeypatch.setenv("REDDOCK_CVE_CATALOG", str(wrong))
        import app.config

        app.config.get_settings.cache_clear()
        try:
            enrichment, warning = load_enrichment()
        finally:
            app.config.get_settings.cache_clear()

        assert enrichment.available is False
        assert "schema" in (warning or "")


class TestTlsCertificates:
    def test_a_verified_certificate_produces_no_finding(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.tls_endpoint(
            "https://127.0.0.1:8443",
            tls={"verified": True, "version": "TLSv1.3", "certificate_sha256": "b" * 64},
        )
        assert TlsCertificateDetector().detect(context(recorder)) == ()

    def test_an_expired_certificate_is_reported_specifically(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.tls_endpoint(
            "https://127.0.0.1:8443",
            tls={
                "verified": False,
                "version": "TLSv1.3",
                "verify_code": 10,
                "verify_message": "certificate has expired",
                "certificate_sha256": "c" * 64,
            },
        )
        findings = TlsCertificateDetector().detect(context(recorder))

        assert [finding.rule_id for finding in findings] == ["certificate-expired"]
        assert str(findings[0].severity) == "medium"

    def test_another_verification_failure_reports_the_reason_it_was_given(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.tls_endpoint(
            "https://127.0.0.1:8443",
            tls={
                "verified": False,
                "version": "TLSv1.3",
                "verify_code": 18,
                "verify_message": "self signed certificate",
                "certificate_sha256": "d" * 64,
            },
        )
        finding = TlsCertificateDetector().detect(context(recorder))[0]

        assert finding.rule_id == "certificate-not-trusted"
        assert str(finding.severity) == "low"
        assert "self signed certificate" in finding.description
        assert finding.detail["certificate_sha256"] == "d" * 64

    def test_a_session_recorded_without_a_verification_outcome_says_nothing(
        self, client: TestClient, recorder: Recorder
    ):
        recorder.tls_endpoint("https://127.0.0.1:8443", tls={"version": "TLSv1.3"})
        assert TlsCertificateDetector().detect(context(recorder)) == ()
