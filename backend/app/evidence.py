"""RedLedger: retained, hashed evidence.

RedDock keeps what is needed to re-read a run later: the raw tool output, the
normalized result and a metadata record describing how they were produced. Every
path is derived from integer identifiers, a fixed scope name and a validated
artifact name, so no operator input can direct a write outside the evidence
root.

Detection and validation use the same store rather than separate writers. Their
documents sit under fixed scopes so that runs from different domains that happen
to share an identifier cannot share a directory:

    evidence/<dockyard-id>/<discovery-run-id>/
    evidence/<dockyard-id>/detection/<detection-run-id>/
    evidence/<dockyard-id>/validation/<validation-run-id>/
"""

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from app.config import get_settings

METADATA_FILE = "metadata.json"
NORMALIZED_FILE = "normalized/result.json"
EVIDENCE_SCHEMA = "reddock.evidence/1"

#: Discovery keeps the original layout so existing evidence stays where it is.
DISCOVERY_SCOPE = ""
DETECTION_SCOPE = "detection"
VALIDATION_SCOPE = "validation"

_ARTIFACT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
#: A closed set, so a scope can never become a path fragment an operator chose.
_SCOPES = frozenset({DISCOVERY_SCOPE, DETECTION_SCOPE, VALIDATION_SCOPE})


class EvidenceError(RuntimeError):
    """Raised when evidence cannot be stored safely."""


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    kind: str
    relative_path: str
    media_type: str
    size_bytes: int
    sha256: str
    truncated: bool


class EvidenceStore:
    """Writes evidence beneath a single application-owned root."""

    def __init__(self, root: Path | None = None, max_bytes: int | None = None) -> None:
        settings = get_settings()
        self.root = (root or Path(settings.evidence_dir)).resolve()
        self.max_bytes = max_bytes or settings.max_evidence_bytes

    def run_directory(self, dockyard_id: int, run_id: int, scope: str = DISCOVERY_SCOPE) -> Path:
        base = self.root / str(int(dockyard_id))
        if _checked_scope(scope):
            base = base / scope
        return base / str(int(run_id))

    def relative_run_path(self, dockyard_id: int, run_id: int, scope: str = DISCOVERY_SCOPE) -> str:
        prefix = f"{scope}/" if _checked_scope(scope) else ""
        return f"{int(dockyard_id)}/{prefix}{int(run_id)}"

    def write_raw(
        self,
        dockyard_id: int,
        run_id: int,
        name: str,
        media_type: str,
        content: bytes,
        scope: str = DISCOVERY_SCOPE,
    ) -> StoredArtifact:
        if not _ARTIFACT_NAME.match(name):
            raise EvidenceError(f"Unsafe evidence artifact name: {name!r}")
        truncated = len(content) > self.max_bytes
        payload = content[: self.max_bytes] if truncated else content
        return self._write(
            dockyard_id, run_id, "raw", f"raw/{name}", media_type, payload, truncated, scope
        )

    def write_normalized(
        self, dockyard_id: int, run_id: int, document: dict, scope: str = DISCOVERY_SCOPE
    ) -> StoredArtifact:
        payload = _document(document)
        return self._write(
            dockyard_id,
            run_id,
            "normalized",
            NORMALIZED_FILE,
            "application/json",
            payload,
            False,
            scope,
        )

    def write_metadata(
        self, dockyard_id: int, run_id: int, document: dict, scope: str = DISCOVERY_SCOPE
    ) -> StoredArtifact:
        payload = _document(document)
        return self._write(
            dockyard_id,
            run_id,
            "metadata",
            METADATA_FILE,
            "application/json",
            payload,
            False,
            scope,
        )

    def _write(
        self,
        dockyard_id: int,
        run_id: int,
        kind: str,
        relative_path: str,
        media_type: str,
        payload: bytes,
        truncated: bool,
        scope: str = DISCOVERY_SCOPE,
    ) -> StoredArtifact:
        directory = self.run_directory(dockyard_id, run_id, scope)
        destination = (directory / relative_path).resolve()
        if not destination.is_relative_to(directory.resolve()):
            raise EvidenceError(f"Evidence path escapes its run directory: {relative_path}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        return StoredArtifact(
            kind=kind,
            relative_path=relative_path,
            media_type=media_type,
            size_bytes=len(payload),
            sha256=sha256(payload).hexdigest(),
            truncated=truncated,
        )


def _checked_scope(scope: str) -> str:
    if scope not in _SCOPES:
        raise EvidenceError(f"Unknown evidence scope: {scope!r}")
    return scope


def _document(document: dict) -> bytes:
    """Serialize deterministically, so the same result always hashes the same."""
    return json.dumps(document, indent=2, sort_keys=True, default=str).encode()
