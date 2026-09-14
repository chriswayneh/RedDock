import importlib.util
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_release", REPOSITORY / "scripts" / "verify_release.py"
)
assert SPEC and SPEC.loader
verify_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_release)


def test_current_release_metadata_agrees() -> None:
    phase = verify_release.verify_files(REPOSITORY, "0.8.1")

    assert phase == "Phase 8: Production hardening checkpoint"


def test_roadmap_latest_release_row_is_version_specific() -> None:
    roadmap = (
        "| **Latest release** | "
        "[`v0.8.1`](https://example.invalid/releases/tag/v0.8.1) |\n"
    )

    assert verify_release._roadmap_identifies_latest_release(roadmap, "0.8.1")
    assert not verify_release._roadmap_identifies_latest_release(roadmap, "0.9.0")


def test_release_source_extraction_uses_immutable_platform_digests() -> None:
    workflow = (REPOSITORY / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    extraction = workflow.split(
        "- name: Extract matching Nmap source from each published architecture",
        maxsplit=1,
    )[1].split("- name: Publish the GitHub release", maxsplit=1)[0]

    assert "docker buildx imagetools inspect --raw" in extraction
    assert 'docker pull "$platform_ref"' in extraction
    assert "platform_manifest=%s" in extraction
    assert 'docker pull --platform "linux/$architecture"' not in extraction


def test_inconsistent_release_version_is_rejected() -> None:
    with pytest.raises(
        verify_release.ReleaseVerificationError, match="inconsistent package metadata"
    ):
        verify_release.verify_files(REPOSITORY, "99.0.0")


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=repository, check=True, capture_output=True)


def _release_repository(repository: Path) -> None:
    _git(repository, "init", "--initial-branch=master")
    _git(repository, "config", "user.name", "RedDock test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "tracked.txt").write_text("reviewed\n", encoding="utf-8")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", "Reviewed release")
    _git(repository, "update-ref", "refs/remotes/origin/master", "HEAD")


def test_annotated_tag_on_clean_master_history_is_accepted(tmp_path: Path) -> None:
    _release_repository(tmp_path)
    _git(tmp_path, "tag", "-a", "v1.2.3", "-m", "RedDock v1.2.3")

    verify_release.verify_git(tmp_path, "v1.2.3")


def test_lightweight_release_tag_is_rejected(tmp_path: Path) -> None:
    _release_repository(tmp_path)
    _git(tmp_path, "tag", "v1.2.3")

    with pytest.raises(verify_release.ReleaseVerificationError, match="annotated Git tag"):
        verify_release.verify_git(tmp_path, "v1.2.3")


def test_dirty_release_checkout_is_rejected(tmp_path: Path) -> None:
    _release_repository(tmp_path)
    _git(tmp_path, "tag", "-a", "v1.2.3", "-m", "RedDock v1.2.3")
    (tmp_path / "tracked.txt").write_text("changed\n", encoding="utf-8")

    with pytest.raises(verify_release.ReleaseVerificationError, match="not clean"):
        verify_release.verify_git(tmp_path, "v1.2.3")
