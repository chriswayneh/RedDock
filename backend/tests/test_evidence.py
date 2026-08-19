from hashlib import sha256
from pathlib import Path

import pytest

from app.evidence import DETECTION_SCOPE, EvidenceError, EvidenceStore


def test_artifacts_are_written_under_the_run_directory_and_hashed(environment: Path):
    store = EvidenceStore()
    artifact = store.write_raw(3, 7, "nmap.xml", "application/xml", b"<nmaprun/>")

    stored = environment / "evidence" / "3" / "7" / "raw" / "nmap.xml"
    assert stored.read_bytes() == b"<nmaprun/>"
    assert artifact.sha256 == sha256(b"<nmaprun/>").hexdigest()
    assert artifact.relative_path == "raw/nmap.xml"
    assert artifact.truncated is False


@pytest.mark.parametrize(
    "name", ["../../escape.xml", "/etc/passwd", "..", "nmap.xml/../../x", "NMAP.xml", ""]
)
def test_unsafe_artifact_names_are_refused(environment: Path, name: str):
    with pytest.raises(EvidenceError):
        EvidenceStore().write_raw(1, 1, name, "application/xml", b"data")


def test_oversized_raw_output_is_truncated_and_marked(environment: Path):
    store = EvidenceStore(max_bytes=64)
    artifact = store.write_raw(1, 1, "big.xml", "application/xml", b"x" * 4096)

    assert artifact.truncated is True
    assert artifact.size_bytes == 64
    stored = environment / "evidence" / "1" / "1" / "raw" / "big.xml"
    assert len(stored.read_bytes()) == 64


def test_metadata_and_normalized_documents_are_json(environment: Path):
    store = EvidenceStore()
    metadata = store.write_metadata(2, 5, {"schema": "reddock.evidence/1"})
    normalized = store.write_normalized(2, 5, {"assets": []})

    assert metadata.relative_path == "metadata.json"
    assert normalized.relative_path == "normalized/result.json"
    assert (environment / "evidence" / "2" / "5" / "metadata.json").exists()
    assert (environment / "evidence" / "2" / "5" / "normalized" / "result.json").exists()


def test_run_directories_are_isolated_by_dockyard_and_run(environment: Path):
    store = EvidenceStore()
    assert store.relative_run_path(4, 9) == "4/9"
    assert store.run_directory(4, 9) == (environment / "evidence" / "4" / "9").resolve()


def test_detection_evidence_is_written_under_its_own_scope(environment: Path):
    """A detection run and a discovery run may share an id but never a directory."""
    store = EvidenceStore()
    store.write_metadata(1, 4, {"kind": "discovery"})
    detection = store.write_metadata(1, 4, {"kind": "detection"}, DETECTION_SCOPE)

    assert store.relative_run_path(1, 4, DETECTION_SCOPE) == "1/detection/4"
    assert detection.sha256 != store.write_metadata(1, 4, {"kind": "discovery"}).sha256
    assert (environment / "evidence" / "1" / "4" / "metadata.json").exists()
    assert (environment / "evidence" / "1" / "detection" / "4" / "metadata.json").exists()


def test_an_unknown_evidence_scope_is_refused(environment: Path):
    with pytest.raises(EvidenceError):
        EvidenceStore().write_metadata(1, 1, {}, "../../escape")


def test_a_document_hashes_the_same_every_time(environment: Path):
    store = EvidenceStore()
    document = {"b": 2, "a": [3, 1]}
    assert store.write_normalized(9, 1, document).sha256 == store.write_normalized(
        9, 2, dict(reversed(list(document.items())))
    ).sha256
