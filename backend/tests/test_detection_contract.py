"""Structural guarantees about what a detector is able to do.

These are not behaviour tests. They read the detection package itself and assert
that a detector has no way to reach a network, a process, the filesystem or the
database, so the claim in the architecture is checked rather than asserted. A
comment saying "detectors do not execute anything" is worth what a test makes it
worth.
"""

import ast
import dataclasses
from pathlib import Path

import pytest

from app.detection import registry
from app.detection.base import (
    DetectedFinding,
    DetectionContext,
    Detector,
    ObservationView,
)

DETECTION = Path(__file__).resolve().parents[1] / "app" / "detection"

#: Anything that could reach outside the process, plus the database itself.
#: A detector reasons about a snapshot; it does not go and get one.
FORBIDDEN_MODULES = frozenset(
    {
        "asyncio",
        "ctypes",
        "http",
        "importlib",
        "multiprocessing",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "sqlalchemy",
        "ssl",
        "subprocess",
        "urllib",
        "app.database",
        "app.models",
        "app.discovery",
        "app.dockguard",
        "app.evidence",
    }
)

FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "__import__", "open", "globals"})


def modules_under(directory: Path) -> list[Path]:
    return sorted(path for path in directory.rglob("*.py") if path.stat().st_size)


def imported_modules(source: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
    return names


def roots(names: set[str]) -> set[str]:
    """Both `socket` and `app.models` shapes, so neither form slips through."""
    expanded = set()
    for name in names:
        parts = name.split(".")
        expanded.update({parts[0], ".".join(parts[:2])})
    return expanded


@pytest.mark.parametrize(
    "module", modules_under(DETECTION / "detectors"), ids=lambda path: path.name
)
def test_a_detector_cannot_reach_a_network_a_process_or_the_database(module: Path):
    forbidden = roots(imported_modules(module.read_text(encoding="utf-8"))) & FORBIDDEN_MODULES
    assert not forbidden, f"{module.name} imports {sorted(forbidden)}"


@pytest.mark.parametrize("module", modules_under(DETECTION), ids=lambda path: path.name)
def test_no_part_of_detection_evaluates_or_executes_text(module: Path):
    tree = ast.parse(module.read_text(encoding="utf-8"))
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & FORBIDDEN_CALLS, f"{module.name} calls {sorted(called & FORBIDDEN_CALLS)}"


def test_the_detector_contract_itself_reaches_nothing():
    forbidden = roots(imported_modules((DETECTION / "base.py").read_text(encoding="utf-8")))
    assert not forbidden & FORBIDDEN_MODULES


def test_enrichment_reads_a_local_file_and_never_the_network():
    """CVE enrichment is a local catalogue. There is no client to switch on."""
    imported = roots(imported_modules((DETECTION / "enrichment.py").read_text(encoding="utf-8")))
    assert not imported & {"socket", "ssl", "http", "urllib", "requests", "subprocess"}
    assert "pathlib" in imported


def test_detectors_are_registered_explicitly_and_not_discovered():
    source = (DETECTION / "registry.py").read_text(encoding="utf-8")
    assert not roots(imported_modules(source)) & {"importlib", "pkgutil", "os", "pathlib"}
    assert isinstance(registry.available_detectors(), tuple)


def test_every_registered_detector_declares_its_contract():
    detectors = registry.available_detectors()
    assert detectors
    for detector in detectors:
        assert isinstance(detector, Detector)
        assert detector.id and detector.version and detector.title and detector.description
        assert detector.consumes


def test_detector_identifiers_are_unique():
    identifiers = [detector.id for detector in registry.available_detectors()]
    assert len(identifiers) == len(set(identifiers))


def test_an_unknown_detector_is_not_conjured_into_existence():
    assert registry.get_detector("metasploit") is None
    assert registry.get_detector("http.security_headers") is not None


def test_the_snapshot_a_detector_receives_is_immutable():
    context = DetectionContext(dockyard_id=1, generated_at=None)
    assert dataclasses.is_dataclass(context)
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.dockyard_id = 2


def test_an_observation_detail_cannot_be_edited_by_a_detector():
    observation = ObservationView(
        id=1,
        discovery_run_id=1,
        asset_id=1,
        service_id=1,
        adapter="http",
        observation_type="http_response",
        summary="",
        confidence="observed",
        observed_at=None,
        detail={"status": 200},
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        observation.summary = "rewritten"


def test_a_detected_finding_is_a_value_not_a_row():
    """A detector produces values. Only the runner decides what is stored."""
    assert dataclasses.is_dataclass(DetectedFinding)
    fields = {field.name for field in dataclasses.fields(DetectedFinding)}
    assert "evidence_observation_ids" in fields
    assert not fields & {"id", "fingerprint", "status", "first_seen", "last_seen"}
