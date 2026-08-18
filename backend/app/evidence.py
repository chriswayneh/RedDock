"""RedLedger foundation: retained, hashed discovery evidence.

Phase 1 keeps only what is needed to re-read a discovery run later: the raw
tool output, the normalized result and a metadata record describing how they
were produced. Every path is derived from integer identifiers and a validated
artifact name, so no operator input can direct a write outside the evidence
root.
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

_ARTIFACT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


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
    """Writes discovery evidence beneath a single application-owned root."""

    def __init__(self, root: Path | None = None, max_bytes: int | None = None) -> None:
        settings = get_settings()
        self.root = (root or Path(settings.evidence_dir)).resolve()
        self.max_bytes = max_bytes or settings.max_evidence_bytes

    def run_directory(self, dockyard_id: int, run_id: int) -> Path:
        return self.root / str(int(dockyard_id)) / str(int(run_id))

    def relative_run_path(self, dockyard_id: int, run_id: int) -> str:
        return f"{int(dockyard_id)}/{int(run_id)}"

    def write_raw(
        self, dockyard_id: int, run_id: int, name: str, media_type: str, content: bytes
    ) -> StoredArtifact:
        if not _ARTIFACT_NAME.match(name):
            raise EvidenceError(f"Unsafe evidence artifact name: {name!r}")
        truncated = len(content) > self.max_bytes
        payload = content[: self.max_bytes] if truncated else content
        return self._write(
            dockyard_id, run_id, "raw", f"raw/{name}", media_type, payload, truncated
        )

    def write_normalized(self, dockyard_id: int, run_id: int, document: dict) -> StoredArtifact:
        payload = json.dumps(document, indent=2, sort_keys=True, default=str).encode()
        return self._write(
            dockyard_id, run_id, "normalized", NORMALIZED_FILE, "application/json", payload, False
        )

    def write_metadata(self, dockyard_id: int, run_id: int, document: dict) -> StoredArtifact:
        payload = json.dumps(document, indent=2, sort_keys=True, default=str).encode()
        return self._write(
            dockyard_id, run_id, "metadata", METADATA_FILE, "application/json", payload, False
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
    ) -> StoredArtifact:
        directory = self.run_directory(dockyard_id, run_id)
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
