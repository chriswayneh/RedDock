"""Phase 2 API tests, exercised through the real detectors."""

import pytest
from fastapi.testclient import TestClient

from tests.phase1 import Recorder


@pytest.fixture()
def detected(client: TestClient, recorder: Recorder, dockyard_id: int) -> dict:
    """One Dockyard with an unprotected HTTPS origin and one detection run."""
    recorder.http_endpoint("https://127.0.0.1:8443", headers={})
    response = client.post(f"/api/dockyards/{dockyard_id}/detections", json={})
    assert response.status_code == 201, response.text
    return response.json()


def findings(client: TestClient, dockyard_id: int, **params) -> list[dict]:
    response = client.get(f"/api/dockyards/{dockyard_id}/findings", params=params)
    assert response.status_code == 200, response.text
    return response.json()


class TestDetectors:
    def test_the_registered_detectors_are_published_with_what_they_read(
        self, client: TestClient
    ):
        published = client.get("/api/detectors").json()
        assert {detector["id"] for detector in published} == {
            "http.security_headers",
            "service.rules",
            "tls.certificates",
        }
        assert all(detector["consumes"] for detector in published)


class TestDetectionRuns:
    def test_a_detection_run_completes_within_the_request(self, detected: dict):
        assert detected["status"] == "completed"
        assert detected["completed_at"] is not None
        assert detected["finding_count"] >= 1
        assert detected["new_finding_count"] == detected["finding_count"]

    def test_a_detection_request_accepts_no_operator_parameters(
        self, client: TestClient, dockyard_id: int
    ):
        """There is no target, no detector selection and no option to pass."""
        for body in (
            {"target": "10.0.0.5"},
            {"detector": "http.security_headers"},
            {"severity": "critical"},
            {"command": "nmap -A"},
        ):
            response = client.post(f"/api/dockyards/{dockyard_id}/detections", json=body)
            assert response.status_code == 422, body

    def test_runs_are_listed_and_readable(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        listed = client.get(f"/api/dockyards/{dockyard_id}/detections").json()
        assert [run["id"] for run in listed] == [detected["id"]]

        single = client.get(f"/api/dockyards/{dockyard_id}/detections/{detected['id']}")
        assert single.status_code == 200
        assert single.json()["result_sha256"] == detected["result_sha256"]

    def test_a_run_states_which_detectors_ran(self, detected: dict):
        statuses = {entry["id"]: entry["status"] for entry in detected["detectors"]}
        assert statuses == {
            "http.security_headers": "completed",
            "service.rules": "completed",
            "tls.certificates": "completed",
        }

    def test_a_run_states_that_cve_enrichment_was_unavailable(self, detected: dict):
        assert detected["enrichment"]["available"] is False
        assert detected["enrichment"]["id"] == "none"

    def test_an_unknown_run_is_not_found(self, client: TestClient, dockyard_id: int):
        assert client.get(f"/api/dockyards/{dockyard_id}/detections/9999").status_code == 404

    def test_detection_on_an_unknown_dockyard_is_not_found(self, client: TestClient):
        assert client.post("/api/dockyards/9999/detections", json={}).status_code == 404


class TestFindings:
    def test_findings_carry_severity_and_confidence_separately(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        rows = findings(client, dockyard_id)
        assert rows
        for finding in rows:
            assert finding["severity"] in {"informational", "low", "medium", "high", "critical"}
            assert finding["confidence"] in {"low", "medium", "high"}
            assert finding["status"] == "open"
            assert finding["detector"] and finding["rule_id"]
            assert finding["evidence_count"] >= 1

    def test_findings_name_the_asset_and_service_they_are_about(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        finding = findings(client, dockyard_id)[0]
        assert finding["asset_label"] == "https://127.0.0.1:8443"
        assert finding["service_endpoint"] == "TCP/443"

    def test_a_finding_detail_carries_its_evidence_and_the_hash_behind_it(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        listed = findings(client, dockyard_id)[0]
        detail = client.get(f"/api/dockyards/{dockyard_id}/findings/{listed['id']}").json()

        assert detail["description"] and detail["remediation"]
        assert detail["evidence"]
        evidence = detail["evidence"][0]
        assert evidence["observation_id"] and evidence["summary"]
        assert evidence["discovery_run_id"] == 1
        assert evidence["detection_run_id"] == detected["id"]
        assert len(evidence["sha256"]) == 64
        assert evidence["evidence_path"] == "normalized/result.json"

    def test_an_unknown_finding_is_not_found(self, client: TestClient, dockyard_id: int):
        assert client.get(f"/api/dockyards/{dockyard_id}/findings/9999").status_code == 404


class TestFilters:
    def test_findings_can_be_filtered_by_severity_status_and_detector(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        assert findings(client, dockyard_id, severity="low")
        assert findings(client, dockyard_id, severity="critical") == []
        assert findings(client, dockyard_id, status="open")
        assert findings(client, dockyard_id, status="resolved") == []
        assert findings(client, dockyard_id, detector="http.security_headers")
        assert findings(client, dockyard_id, detector="service.rules") == []

    def test_findings_can_be_filtered_by_asset_and_service(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        finding = findings(client, dockyard_id)[0]
        assert findings(client, dockyard_id, asset_id=finding["asset_id"])
        assert findings(client, dockyard_id, asset_id=finding["asset_id"] + 100) == []
        assert findings(client, dockyard_id, service_id=finding["service_id"])

    @pytest.mark.parametrize(
        "params",
        [
            {"severity": "catastrophic"},
            {"status": "ignored"},
            {"limit": 0},
            {"limit": 501},
            {"asset_id": 0},
            {"asset_id": "all"},
            {"service_id": -1},
        ],
    )
    def test_an_invalid_filter_is_refused(
        self, client: TestClient, dockyard_id: int, detected: dict, params: dict
    ):
        response = client.get(f"/api/dockyards/{dockyard_id}/findings", params=params)
        assert response.status_code == 422, params

    def test_findings_are_returned_most_severe_first(
        self, client: TestClient, dockyard_id: int, recorder: Recorder
    ):
        recorder.http_endpoint("http://127.0.0.1:8080", headers={})
        recorder.identified_service("192.168.1.10", 23, service_name="telnet")
        client.post(f"/api/dockyards/{dockyard_id}/detections", json={})

        severities = [finding["severity"] for finding in findings(client, dockyard_id)]
        order = ["critical", "high", "medium", "low", "informational"]
        assert severities == sorted(severities, key=order.index)


class TestOperatorDecisions:
    def test_a_finding_can_be_suppressed_and_keeps_its_evidence(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        finding = findings(client, dockyard_id)[0]
        response = client.patch(
            f"/api/dockyards/{dockyard_id}/findings/{finding['id']}",
            json={"status": "suppressed", "note": "Accepted for the lab network"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "suppressed"
        assert body["status_note"] == "Accepted for the lab network"
        assert body["evidence"]

    def test_a_finding_can_be_accepted_and_reopened(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        finding = findings(client, dockyard_id)[0]
        path = f"/api/dockyards/{dockyard_id}/findings/{finding['id']}"

        assert client.patch(path, json={"status": "accepted"}).json()["status"] == "accepted"
        assert client.patch(path, json={"status": "open"}).json()["status"] == "open"

    def test_an_operator_cannot_declare_a_finding_resolved(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        """Resolution is a fact about the data, so RedDock sets it."""
        finding = findings(client, dockyard_id)[0]
        response = client.patch(
            f"/api/dockyards/{dockyard_id}/findings/{finding['id']}",
            json={"status": "resolved"},
        )
        assert response.status_code == 422

    def test_an_unknown_status_is_refused(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        finding = findings(client, dockyard_id)[0]
        path = f"/api/dockyards/{dockyard_id}/findings/{finding['id']}"
        assert client.patch(path, json={"status": "fixed"}).status_code == 422
        assert client.patch(path, json={"status": "open", "extra": 1}).status_code == 422

    def test_updating_an_unknown_finding_is_not_found(
        self, client: TestClient, dockyard_id: int
    ):
        assert (
            client.patch(
                f"/api/dockyards/{dockyard_id}/findings/9999", json={"status": "open"}
            ).status_code
            == 404
        )


class TestDockyardIsolation:
    def test_a_finding_is_not_reachable_from_another_dockyard(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        finding = findings(client, dockyard_id)[0]
        other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]

        assert client.get(f"/api/dockyards/{other}/findings").json() == []
        assert client.get(f"/api/dockyards/{other}/findings/{finding['id']}").status_code == 404
        assert (
            client.patch(
                f"/api/dockyards/{other}/findings/{finding['id']}", json={"status": "suppressed"}
            ).status_code
            == 404
        )

    def test_a_detection_run_is_not_reachable_from_another_dockyard(
        self, client: TestClient, detected: dict
    ):
        other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
        assert client.get(f"/api/dockyards/{other}/detections").json() == []
        assert (
            client.get(f"/api/dockyards/{other}/detections/{detected['id']}").status_code == 404
        )


class TestPhase1RemainsIntact:
    def test_an_observation_still_carries_no_severity_or_verdict(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        observations = client.get(f"/api/dockyards/{dockyard_id}/observations").json()
        assert observations
        for observation in observations:
            assert "severity" not in observation
            assert "status" not in observation
            assert observation["confidence"] in {"observed", "reported"}

    def test_detection_adds_nothing_to_the_discovery_evidence_ledger(
        self, client: TestClient, dockyard_id: int, detected: dict
    ):
        records = client.get(f"/api/dockyards/{dockyard_id}/evidence").json()
        assert {record["kind"] for record in records} == {"normalized"}
