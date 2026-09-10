"""Fail closed when a release tag and RedDock's public version metadata disagree."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from pathlib import Path

import tomllib

TAG_PATTERN = re.compile(
    r"v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
)


class ReleaseVerificationError(RuntimeError):
    """The proposed release does not match the reviewed repository state."""


def _settings_strings(config_path: Path) -> tuple[str, str]:
    tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            values: dict[str, str] = {}
            for statement in node.body:
                if (
                    isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    and statement.target.id in {"version", "phase"}
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)
                ):
                    values[statement.target.id] = statement.value.value
            if values.keys() >= {"version", "phase"}:
                return values["version"], values["phase"]
    raise ReleaseVerificationError("Settings.version and Settings.phase must be string literals")


def verify_files(repository: Path, version: str) -> str:
    """Verify every user-visible and packaged version source; return the phase name."""
    backend = tomllib.loads(
        (repository / "backend" / "pyproject.toml").read_text(encoding="utf-8")
    )
    frontend = json.loads(
        (repository / "frontend" / "package.json").read_text(encoding="utf-8")
    )
    lockfile = json.loads(
        (repository / "frontend" / "package-lock.json").read_text(encoding="utf-8")
    )
    settings_version, phase = _settings_strings(repository / "backend" / "app" / "config.py")

    actual = {
        "backend/pyproject.toml": backend["project"]["version"],
        "backend/app/config.py": settings_version,
        "frontend/package.json": frontend["version"],
        "frontend/package-lock.json": lockfile["version"],
        "frontend/package-lock.json root package": lockfile["packages"][""]["version"],
    }
    mismatches = [
        f"{source} contains {value!r}"
        for source, value in actual.items()
        if value != version
    ]
    if mismatches:
        raise ReleaseVerificationError(
            f"Release v{version} has inconsistent package metadata: " + "; ".join(mismatches)
        )

    changelog = (repository / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\](?:\s|$)", changelog, re.MULTILINE):
        raise ReleaseVerificationError(f"CHANGELOG.md has no v{version} release section")

    roadmap = (repository / "ROADMAP.md").read_text(encoding="utf-8")
    if f"The latest release is **v{version}" not in roadmap:
        raise ReleaseVerificationError(
            f"ROADMAP.md does not identify v{version} as the latest release"
        )

    readme = (repository / "README.md").read_text(encoding="utf-8")
    if f"**Current release:** [v{version}]" not in readme:
        raise ReleaseVerificationError(
            f"README.md does not identify v{version} as the current release"
        )
    return phase


def _git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=check,
        capture_output=True,
        text=True,
    )


def verify_git(repository: Path, tag: str) -> None:
    """Require an annotated tag on the checked-out commit and on master history."""
    if _git(repository, "cat-file", "-t", tag).stdout.strip() != "tag":
        raise ReleaseVerificationError(f"{tag} must be an annotated Git tag")
    tagged_commit = _git(repository, "rev-list", "-n", "1", tag).stdout.strip()
    head = _git(repository, "rev-parse", "HEAD").stdout.strip()
    if tagged_commit != head:
        raise ReleaseVerificationError(f"{tag} does not point to the checked-out commit")
    ancestry = _git(
        repository, "merge-base", "--is-ancestor", head, "origin/master", check=False
    )
    if ancestry.returncode:
        raise ReleaseVerificationError(f"{tag} is not on origin/master history")
    if _git(repository, "status", "--porcelain").stdout:
        raise ReleaseVerificationError("release checkout is not clean")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", help="annotated release tag, for example v0.9.0")
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args()

    match = TAG_PATTERN.fullmatch(arguments.tag)
    if match is None:
        raise ReleaseVerificationError("release tag must use vMAJOR.MINOR.PATCH")
    version = match.group("version")
    repository = Path(__file__).resolve().parents[1]
    phase = verify_files(repository, version)
    verify_git(repository, arguments.tag)

    if arguments.github_output:
        title_phase = phase.replace("—", "-")
        with arguments.github_output.open("a", encoding="utf-8", newline="\n") as output:
            output.write(f"version={version}\n")
            output.write(f"phase={title_phase}\n")
    print(f"Verified annotated release {arguments.tag}: {phase}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
