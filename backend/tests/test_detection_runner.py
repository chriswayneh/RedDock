"""Detection run orchestration tests.

The rules these protect are the ones that separate a findings list from a
guess: a finding must come from a detector and be supported by observations, the
same issue must stay one record, and nothing is ever removed because it stopped
being reproduced.
"""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.detection import registry as detection_registry
from app.detection import runner as detection_runner
from app.detection.base import (
    DetectedFinding,
    DetectionContext,
    Detector,
    FindingCategory,
    FindingConfidence,
    FindingStatus,
    Severity,
)
from app.detection.fingerprint import fingerprint
from app.models import Finding, FindingEvidence, Observation
from tests.phase1 import Recorder


class StubDetector(Detector):
    """A detector whose output the test decides, so orchestration is what is tested."""

    id = "stub.detector"
    version = "1.0.0"
    title = "Stub detector"
    description = "Deterministic detector used by the test suite."
    consumes = ("http_response",)

    def __init__(self, produce=None, failure: Exception | None = None) -> None:
        self.produce = produce if produce is not None else _one_finding
        self.failure = failure
        self.contexts: list[DetectionContext] = []

    def detect(self, context: DetectionContext) -> tuple[DetectedFinding, ...]:
        self.contexts.append(context)
        if self.failure is not None:
            raise self.failure
        return self.produce(context)


class SecondDetector(StubDetector):
    id = "stub.second"


def _one_finding(context: DetectionContext) -> tuple[DetectedFinding, ...]:
    observation = context.observations[0]
    return (
        DetectedFinding(
            rule_id="stub-rule",
            title="Stub finding",
            description="A deterministic finding produced by the test suite.",
            category=FindingCategory.HARDENING,
            severity=Severity.LOW,
            confidence=FindingConfidence.HIGH,
            evidence_observation_ids=(observation.id,),
            asset_id=observation.asset_id,
            service_id=observation.service_id,
            remediation="Nothing; this exists so orchestration can be tested.",
            detail={"stub": True},
        ),
    )


def _no_findings(context: DetectionContext) -> tuple[DetectedFinding, ...]:
    return ()


def install(monkeypatch: pytest.MonkeyPatch, *detectors: Detector) -> None:
    monkeypatch.setattr(detection_registry, "available_detectors", lambda: tuple(detectors))
    monkeypatch.setattr(detection_runner.registry, "available_detectors", lambda: tuple(detectors))


def detect(recorder: Recorder):
    return detection_runner.start_detection(recorder.session, recorder.dockyard_id)


def findings_of(recorder: Recorder) -> list[Finding]:
    return list(
        recorder.session.scalars(
            select(Finding)
            .where(Finding.dockyard_id == recorder.dockyard_id)
            .order_by(Finding.id)
        )
    )


@pytest.fixture()
def endpoint(client: TestClient, recorder: Recorder):
    recorder.http_endpoint("https://127.0.0.1:8443", headers={})
    return recorder


class TestTheObservationFindingBoundary:
    def test_discovery_alone_never_produces_a_finding(self, endpoint: Recorder):
        """Observations exist the moment discovery runs. Findings do not."""
        assert endpoint.session.scalars(select(Observation)).all()
        assert findings_of(endpoint) == []

    def test_a_finding_is_only_created_by_a_detection_run(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        run = detect(endpoint)

        assert run.status == "completed"
        assert len(findings_of(endpoint)) == 1
        assert findings_of(endpoint)[0].detector == "stub.detector"

    def test_detection_never_alters_an_observation(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        before = [
            (row.id, row.summary, row.observation_type, row.confidence)
            for row in endpoint.session.scalars(select(Observation).order_by(Observation.id))
        ]
        install(monkeypatch, StubDetector())
        detect(endpoint)

        after = [
            (row.id, row.summary, row.observation_type, row.confidence)
            for row in endpoint.session.scalars(select(Observation).order_by(Observation.id))
        ]
        assert after == before

    def test_a_finding_that_cites_no_observation_is_refused(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        def unsupported(context):
            return (
                DetectedFinding(
                    rule_id="unsupported",
                    title="Nothing supports this",
                    description="A conclusion with no evidence behind it.",
                    category=FindingCategory.HARDENING,
                    severity=Severity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence_observation_ids=(),
                ),
            )

        install(monkeypatch, StubDetector(produce=unsupported))
        run = detect(endpoint)

        assert run.status == "failed"
        assert "cites no observation" in run.error
        assert findings_of(endpoint) == []


class TestDetectorOutputValidation:
    def test_a_detector_that_finds_nothing_completes_cleanly(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector(produce=_no_findings))
        run = detect(endpoint)

        assert (run.status, run.finding_count, run.error) == ("completed", 0, None)
        assert findings_of(endpoint) == []

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("severity", "catastrophic", "unknown severity"),
            ("confidence", "certain", "unknown confidence"),
            ("category", "vibes", "unknown category"),
            ("rule_id", "Not A Rule Id", "Unusable rule id"),
            ("title", "", "unusable title"),
            ("description", "  ", "unusable description"),
        ],
    )
    def test_invalid_output_fails_the_detector_and_stores_nothing(
        self,
        endpoint: Recorder,
        monkeypatch: pytest.MonkeyPatch,
        field: str,
        value: str,
        message: str,
    ):
        def malformed(context):
            base = _one_finding(context)[0]
            return (
                base,
                DetectedFinding(
                    **{
                        **{
                            "rule_id": "second-rule",
                            "title": "Second",
                            "description": "Another finding in the same batch.",
                            "category": FindingCategory.HARDENING,
                            "severity": Severity.LOW,
                            "confidence": FindingConfidence.HIGH,
                            "evidence_observation_ids": base.evidence_observation_ids,
                        },
                        field: value,
                    }
                ),
            )

        install(monkeypatch, StubDetector(produce=malformed))
        run = detect(endpoint)

        assert run.status == "failed"
        assert message in run.error
        # The valid finding in the same batch is discarded too: a detector that
        # is wrong about its own output is not half-trusted.
        assert findings_of(endpoint) == []

    def test_a_finding_about_another_dockyard_is_refused(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, client: TestClient
    ):
        other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
        outsider = Recorder(endpoint.session, other)
        outsider.http_endpoint("https://10.0.0.5:8443", headers={})
        stolen = outsider.session.scalars(
            select(Observation).where(Observation.dockyard_id == other)
        ).first()

        def cross_dockyard(context):
            return (
                DetectedFinding(
                    rule_id="cross-dockyard",
                    title="Evidence from elsewhere",
                    description="Cites an observation from another workspace.",
                    category=FindingCategory.HARDENING,
                    severity=Severity.LOW,
                    confidence=FindingConfidence.HIGH,
                    evidence_observation_ids=(stolen.id,),
                ),
            )

        install(monkeypatch, StubDetector(produce=cross_dockyard))
        run = detect(endpoint)

        assert run.status == "failed"
        assert "outside this Dockyard" in run.error

    def test_a_detector_returning_the_wrong_shape_entirely_is_refused(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector(produce=lambda context: "not findings"))
        run = detect(endpoint)

        assert run.status == "failed"
        assert findings_of(endpoint) == []

    def test_more_findings_than_the_limit_fails_rather_than_truncating(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        def flood(context):
            base = _one_finding(context)[0]
            limit = 501
            return tuple(
                DetectedFinding(
                    rule_id=f"flood-{index}",
                    title=f"Flood {index}",
                    description="One of very many.",
                    category=FindingCategory.HARDENING,
                    severity=Severity.LOW,
                    confidence=FindingConfidence.HIGH,
                    evidence_observation_ids=base.evidence_observation_ids,
                )
                for index in range(limit)
            )

        install(monkeypatch, StubDetector(produce=flood))
        run = detect(endpoint)

        assert run.status == "failed"
        assert "at most" in run.error
        assert findings_of(endpoint) == []


class TestFingerprintAndDeduplication:
    def test_a_fingerprint_is_a_sha256_over_stable_concepts(self):
        arguments = {
            "detector": "http.security_headers",
            "rule_id": "hsts-not-set",
            "asset_type": "web",
            "asset_identity": "https://127.0.0.1:8443",
            "transport": "tcp",
            "port": 8443,
        }
        value = fingerprint(**arguments)

        assert len(value) == 64 and int(value, 16) >= 0
        assert fingerprint(**arguments) == value
        assert fingerprint(**{**arguments, "port": 9443}) != value
        assert fingerprint(**{**arguments, "rule_id": "other"}) != value

    def test_a_fingerprint_is_identical_across_processes(self):
        """Python's randomized hash() would make a finding look new after a restart."""
        script = (
            "from app.detection.fingerprint import fingerprint;"
            "print(fingerprint(detector='d', rule_id='r', asset_type='web',"
            " asset_identity='https://a', transport='tcp', port=443))"
        )
        values = set()
        for seed in ("0", "1", "random"):
            environment = {**os.environ, "PYTHONHASHSEED": seed}
            result = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                check=True,
                env=environment,
                cwd=str(Path(__file__).resolve().parents[1]),
            )
            values.add(result.stdout.strip())
        assert len(values) == 1

    def test_a_repeated_detection_updates_rather_than_duplicating(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        first = detect(endpoint)
        original = findings_of(endpoint)[0]
        first_seen, first_id = original.first_seen, original.id

        second = detect(endpoint)
        rows = findings_of(endpoint)

        assert len(rows) == 1
        assert rows[0].id == first_id
        assert rows[0].first_seen == first_seen
        assert rows[0].last_seen >= first_seen
        assert rows[0].first_detection_run_id == first.id
        assert rows[0].last_detection_run_id == second.id
        assert (second.finding_count, second.new_finding_count) == (1, 0)

    def test_the_second_run_reports_no_new_findings(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        assert detect(endpoint).new_finding_count == 1
        assert detect(endpoint).new_finding_count == 0

    def test_the_same_issue_in_two_dockyards_stays_two_findings(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, client: TestClient
    ):
        install(monkeypatch, StubDetector())
        detect(endpoint)

        other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
        outsider = Recorder(endpoint.session, other)
        outsider.http_endpoint("https://127.0.0.1:8443", headers={})
        detection_runner.start_detection(outsider.session, other)

        rows = list(endpoint.session.scalars(select(Finding).order_by(Finding.id)))
        assert len(rows) == 2
        # Identical issue, identical fingerprint, isolated by Dockyard.
        assert rows[0].fingerprint == rows[1].fingerprint
        assert {row.dockyard_id for row in rows} == {endpoint.dockyard_id, other}


class TestEvidence:
    def test_a_finding_is_linked_to_the_observation_it_came_from(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        detect(endpoint)
        finding = findings_of(endpoint)[0]

        evidence = list(
            endpoint.session.scalars(
                select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)
            )
        )
        assert len(evidence) == 1
        observation = endpoint.session.get(Observation, evidence[0].observation_id)
        assert observation is not None
        assert evidence[0].discovery_run_id == observation.discovery_run_id
        # And through to the hashed RedLedger artifact that observation came from.
        assert evidence[0].evidence_record_id is not None

    def test_repeated_detection_over_unchanged_data_adds_no_evidence_rows(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        detect(endpoint)
        detect(endpoint)

        assert len(list(endpoint.session.scalars(select(FindingEvidence)))) == 1

    def test_a_detection_run_writes_hashed_evidence(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, environment: Path
    ):
        from hashlib import sha256

        install(monkeypatch, StubDetector())
        run = detect(endpoint)

        directory = environment / "evidence" / str(endpoint.dockyard_id) / "detection" / str(run.id)
        result = directory / "normalized" / "result.json"
        metadata = directory / "metadata.json"

        assert run.evidence_path == f"{endpoint.dockyard_id}/detection/{run.id}"
        assert sha256(result.read_bytes()).hexdigest() == run.result_sha256
        assert sha256(metadata.read_bytes()).hexdigest() == run.metadata_sha256

        document = json.loads(metadata.read_text())
        assert document["kind"] == "detection"
        assert document["detectors"][0]["id"] == "stub.detector"
        assert document["counts"] == {"findings": 1, "new": 1, "resolved": 0}

    def test_detection_evidence_never_collides_with_discovery_evidence(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, environment: Path
    ):
        install(monkeypatch, StubDetector())
        run = detect(endpoint)
        root = environment / "evidence" / str(endpoint.dockyard_id)

        assert (root / "detection" / str(run.id)).is_dir()
        # Discovery run 1 keeps the original layout.
        assert not (root / str(run.id) / "metadata.json").exists()

    def test_the_normalized_result_is_byte_identical_for_identical_input(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, environment: Path
    ):
        install(monkeypatch, StubDetector())
        first = detect(endpoint)
        second = detect(endpoint)
        root = environment / "evidence" / str(endpoint.dockyard_id) / "detection"

        assert (root / str(first.id) / "normalized" / "result.json").read_bytes() == (
            root / str(second.id) / "normalized" / "result.json"
        ).read_bytes()


class TestLifecycle:
    def test_a_finding_no_longer_reproduced_is_resolved_and_kept(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        detector = StubDetector()
        install(monkeypatch, detector)
        detect(endpoint)
        finding_id = findings_of(endpoint)[0].id

        detector.produce = _no_findings
        run = detect(endpoint)
        rows = findings_of(endpoint)

        assert len(rows) == 1 and rows[0].id == finding_id
        assert rows[0].status == "resolved"
        assert rows[0].resolved_at is not None
        assert run.resolved_finding_count == 1

    def test_history_survives_resolution(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        detector = StubDetector()
        install(monkeypatch, detector)
        detect(endpoint)
        first_seen = findings_of(endpoint)[0].first_seen

        detector.produce = _no_findings
        detect(endpoint)
        resolved = findings_of(endpoint)[0]

        assert resolved.first_seen == first_seen
        assert resolved.last_seen is not None
        assert list(
            endpoint.session.scalars(
                select(FindingEvidence).where(FindingEvidence.finding_id == resolved.id)
            )
        )

    def test_a_resolved_finding_that_returns_is_reopened_not_duplicated(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        detector = StubDetector()
        install(monkeypatch, detector)
        detect(endpoint)
        detector.produce = _no_findings
        detect(endpoint)
        detector.produce = _one_finding
        detect(endpoint)

        rows = findings_of(endpoint)
        assert len(rows) == 1
        assert rows[0].status == "open"
        assert rows[0].resolved_at is None

    @pytest.mark.parametrize("decision", ["suppressed", "accepted"])
    def test_an_operator_decision_survives_a_run_that_no_longer_reproduces_it(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, decision: str
    ):
        detector = StubDetector()
        install(monkeypatch, detector)
        detect(endpoint)
        finding = findings_of(endpoint)[0]
        finding.status = decision
        endpoint.session.commit()

        detector.produce = _no_findings
        run = detect(endpoint)

        assert findings_of(endpoint)[0].status == decision
        assert run.resolved_finding_count == 0

    def test_an_operator_decision_survives_the_issue_reappearing(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        detect(endpoint)
        finding = findings_of(endpoint)[0]
        finding.status = str(FindingStatus.SUPPRESSED)
        endpoint.session.commit()

        detect(endpoint)
        refreshed = findings_of(endpoint)[0]
        assert refreshed.status == "suppressed"
        # It was still seen; only the operator changes what counts as open.
        assert refreshed.last_seen is not None


class TestDetectorFailureIsolation:
    def test_one_failing_detector_does_not_stop_the_others(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector(failure=RuntimeError("boom")), SecondDetector())
        run = detect(endpoint)

        assert run.status == "partial"
        assert "boom" in run.error
        statuses = {entry["id"]: entry["status"] for entry in run.detectors}
        assert statuses == {"stub.detector": "failed", "stub.second": "completed"}
        assert [finding.detector for finding in findings_of(endpoint)] == ["stub.second"]

    def test_a_failed_detector_resolves_nothing(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        """Not running is not evidence that an issue went away."""
        detector = StubDetector()
        install(monkeypatch, detector)
        detect(endpoint)

        detector.failure = RuntimeError("boom")
        run = detect(endpoint)

        assert run.status == "failed"
        assert run.resolved_finding_count == 0
        assert findings_of(endpoint)[0].status == "open"

    def test_a_run_where_every_detector_fails_is_failed(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(
            monkeypatch,
            StubDetector(failure=RuntimeError("one")),
            SecondDetector(failure=RuntimeError("two")),
        )
        run = detect(endpoint)

        assert run.status == "failed"
        assert findings_of(endpoint) == []


class TestIsolationAndReach:
    def test_a_detector_only_sees_its_own_dockyard(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch, client: TestClient
    ):
        other = client.post("/api/dockyards", json={"name": "Other"}).json()["id"]
        Recorder(endpoint.session, other).http_endpoint("https://10.0.0.5:8443", headers={})

        detector = StubDetector()
        install(monkeypatch, detector)
        detect(endpoint)

        context = detector.contexts[0]
        assert context.dockyard_id == endpoint.dockyard_id
        assert [asset.identity for asset in context.assets] == ["https://127.0.0.1:8443"]

    def test_a_detection_run_starts_no_process_and_opens_no_socket(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        import socket

        def refuse(*args, **kwargs):
            raise AssertionError("Detection must not reach outside the database")

        monkeypatch.setattr(subprocess, "run", refuse)
        monkeypatch.setattr(subprocess, "Popen", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(os, "system", refuse)

        install(monkeypatch, StubDetector())
        run = detect(endpoint)
        assert run.status == "completed"

    def test_a_detection_run_asks_dockguard_for_nothing(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        """Detection needs no scope decision because it reaches no target."""
        import app.dockguard

        def refuse(*args, **kwargs):
            raise AssertionError("Detection must not evaluate scope; it contacts nothing")

        monkeypatch.setattr(app.dockguard, "evaluate", refuse)
        monkeypatch.setattr(app.dockguard, "system_resolver", refuse)

        install(monkeypatch, StubDetector())
        assert detect(endpoint).status == "completed"


class TestRunRecord:
    def test_a_run_records_what_it_read(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        run = detect(endpoint)

        assert run.asset_count == 1
        assert run.service_count == 1
        assert run.observation_count >= 1
        assert run.started_at is not None and run.completed_at is not None

    def test_a_run_records_that_enrichment_was_unavailable(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        install(monkeypatch, StubDetector())
        run = detect(endpoint)

        assert run.enrichment == {
            "id": "none",
            "version": None,
            "available": False,
            "warning": None,
        }

    def test_an_overlapping_run_is_refused(
        self, endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
    ):
        from app.models import DetectionRun

        endpoint.session.add(
            DetectionRun(dockyard_id=endpoint.dockyard_id, status="running")
        )
        endpoint.session.commit()

        install(monkeypatch, StubDetector())
        with pytest.raises(detection_runner.RunRejected):
            detect(endpoint)


def test_detection_uses_the_snapshot_time_for_seen_timestamps(
    endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
):
    """One run has one clock, so every finding it stores agrees about when."""
    install(monkeypatch, StubDetector())
    before = datetime.now(UTC)
    detect(endpoint)
    finding = findings_of(endpoint)[0]

    # SQLite hands timestamps back without a zone; the stored value is UTC.
    stored = finding.first_seen.replace(tzinfo=UTC)
    assert finding.first_seen == finding.last_seen
    assert stored >= before.replace(microsecond=0)


def test_a_detection_run_interrupted_by_a_restart_is_marked_and_unblocks_the_next(
    endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
):
    """An overlapping run is refused, so a stale active run must not be permanent."""
    from app.models import DetectionRun

    stale = DetectionRun(dockyard_id=endpoint.dockyard_id, status="running")
    endpoint.session.add(stale)
    endpoint.session.commit()

    assert detection_runner.recover_interrupted_runs(endpoint.session) == 1
    endpoint.session.refresh(stale)
    assert stale.status == "failed"
    assert "restart" in stale.error

    install(monkeypatch, StubDetector())
    assert detect(endpoint).status == "completed"


def test_two_findings_claiming_one_identity_fail_the_detector(
    endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
):
    """Deduplication keys on the fingerprint, so a collision is a detector bug."""

    def collide(context):
        base = _one_finding(context)[0]
        return (base, base)

    install(monkeypatch, StubDetector(produce=collide))
    run = detect(endpoint)

    assert run.status == "failed"
    assert "same identity" in run.error
    assert findings_of(endpoint) == []


def test_a_scope_key_lets_one_rule_fire_twice_for_one_service(
    endpoint: Recorder, monkeypatch: pytest.MonkeyPatch
):
    """The discriminator exists for rules that legitimately repeat."""
    import dataclasses

    def twice(context):
        base = _one_finding(context)[0]
        return (
            dataclasses.replace(base, scope_key="first"),
            dataclasses.replace(base, scope_key="second"),
        )

    install(monkeypatch, StubDetector(produce=twice))
    run = detect(endpoint)

    assert run.status == "completed"
    assert len(findings_of(endpoint)) == 2
