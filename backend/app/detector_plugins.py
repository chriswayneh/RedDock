"""Load bounded detector manifests without granting detectors filesystem access."""

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import get_settings
from app.detection.declarative import DeclarativeDetector, DeclarativeRule

_PLUGIN_ID = re.compile(r"^plugin\.[a-z0-9][a-z0-9._-]{0,55}$")
_VERSION = re.compile(r"^[0-9][0-9A-Za-z._-]{0,15}$")


class PluginConfigurationError(ValueError):
    """A configured plugin set is unsafe, ambiguous, or malformed."""


class RuleDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    observation_type: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$")
    detail_key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    equals: str | int | bool
    title: str = Field(min_length=1, max_length=180)
    description: str = Field(min_length=1, max_length=3_000)
    category: Literal["transport", "hardening", "information_disclosure"]
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    remediation: str | None = Field(default=None, max_length=1_500)

    def compiled(self) -> DeclarativeRule:
        return DeclarativeRule(**self.model_dump())


class ManifestDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_id: Literal["reddock.detector-plugin/1"] = Field(alias="schema")
    id: str
    version: str
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=500)
    rules: list[RuleDocument]


def load_declarative_detectors(directory: str | None) -> tuple[DeclarativeDetector, ...]:
    if not directory:
        return ()
    settings = get_settings()
    root = Path(directory).expanduser()
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise PluginConfigurationError(
            "The configured detector plugin directory is unavailable"
        ) from error
    if not resolved_root.is_dir():
        raise PluginConfigurationError("The configured detector plugin path is not a directory")

    paths = sorted(resolved_root.glob("*.json"), key=lambda item: item.name)
    if len(paths) > settings.max_detector_plugins:
        raise PluginConfigurationError(
            f"At most {settings.max_detector_plugins} detector plugin manifests may be installed"
        )
    detectors = tuple(_load_manifest(path, resolved_root) for path in paths)
    ids = [detector.id for detector in detectors]
    if len(ids) != len(set(ids)):
        raise PluginConfigurationError("Detector plugin IDs must be unique")
    return tuple(sorted(detectors, key=lambda item: item.id))


def _load_manifest(path: Path, root: Path) -> DeclarativeDetector:
    if path.is_symlink():
        raise PluginConfigurationError(f"Detector plugin {path.name} may not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PluginConfigurationError(f"Detector plugin {path.name} is unavailable") from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise PluginConfigurationError(
            f"Detector plugin {path.name} escapes its configured directory"
        )

    limit = get_settings().max_detector_plugin_bytes
    try:
        with resolved.open("rb") as source:
            raw = source.read(limit + 1)
    except OSError as error:
        raise PluginConfigurationError(f"Detector plugin {path.name} could not be read") from error
    if len(raw) > limit:
        raise PluginConfigurationError(
            f"Detector plugin {path.name} exceeds the {limit}-byte manifest limit"
        )
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
        manifest = ManifestDocument.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
        raise PluginConfigurationError(
            f"Detector plugin {path.name} is invalid: {error}"
        ) from error

    if not _PLUGIN_ID.fullmatch(manifest.id):
        raise PluginConfigurationError(
            f"Detector plugin {path.name} must use an ID beginning with plugin."
        )
    if not _VERSION.fullmatch(manifest.version):
        raise PluginConfigurationError(f"Detector plugin {path.name} has an invalid version")
    rule_limit = get_settings().max_detector_plugin_rules
    if not manifest.rules or len(manifest.rules) > rule_limit:
        raise PluginConfigurationError(
            f"Detector plugin {path.name} must contain 1–{rule_limit} rules"
        )
    rule_ids = [rule.id for rule in manifest.rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise PluginConfigurationError(f"Detector plugin {path.name} has duplicate rule IDs")
    digest = sha256(raw).hexdigest()
    return DeclarativeDetector(
        detector_id=manifest.id,
        version=manifest.version,
        title=manifest.title,
        description=manifest.description,
        rules=tuple(rule.compiled() for rule in manifest.rules),
        manifest_sha256=digest,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"Duplicate JSON key: {key}")
        document[key] = value
    return document
