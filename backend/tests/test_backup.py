import hashlib
import io
import json
import os
import sqlite3
import stat
import zipfile
from collections.abc import Callable
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine

from app import backup
from app.backup import BackupError, verify_backup
from app.database import Base


def create_backup(data_dir: Path, output: Path, *, confirm_overwrite: bool = False) -> str:
    return backup.create_backup(
        data_dir,
        output,
        confirm_offline=True,
        confirm_overwrite=confirm_overwrite,
    )


def restore_backup(data_dir: Path, archive: Path, *, confirm_replace: bool) -> None:
    backup.restore_backup(
        data_dir,
        archive,
        confirm_offline=True,
        confirm_replace=confirm_replace,
    )


def _write_database(path: Path, value: str) -> None:
    # Build the actual current application schema rather than a permissive
    # stamp-only fixture: backup validation must reject such fake databases.
    import app.models  # noqa: F401

    engine = create_engine(f"sqlite:///{path.resolve().as_posix()}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        connection.execute("INSERT INTO alembic_version VALUES ('0003_security_audit')")
        connection.execute("CREATE TABLE state (value TEXT NOT NULL)")
        connection.execute("INSERT INTO state VALUES (?)", (value,))
        connection.execute(
            "INSERT INTO organizations (id, slug, name) VALUES (1, 'local', 'Local RedDock')"
        )
        connection.execute(
            "INSERT INTO users (id, oidc_issuer, oidc_subject, display_name, status) "
            "VALUES (1, 'urn:reddock:local', 'single-operator', 'Local operator', 'active')"
        )
        connection.execute(
            "INSERT INTO memberships (id, organization_id, user_id, role, status) "
            "VALUES (1, 1, 1, 'owner', 'active')"
        )
        connection.commit()


def _add_evidence_record(
    database: Path,
    *,
    relative_path: str,
    payload: bytes,
    size: int | None = None,
    digest: str | None = None,
) -> None:
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO dockyards (id, organization_id, name, status) "
            "VALUES (1, 1, 'Test', 'draft')"
        )
        connection.execute(
            "INSERT INTO discovery_runs "
            "(id, dockyard_id, adapter, adapter_version, profile, requested_target, "
            "status, decision, decision_reason, asset_count, service_count, observation_count) "
            "VALUES (2, 1, 'test', '1', 'host-discovery', '127.0.0.1', "
            "'completed', 'allow', 'test', 0, 0, 0)"
        )
        connection.execute(
            "INSERT INTO evidence_records "
            "(dockyard_id, discovery_run_id, kind, relative_path, media_type, size_bytes, "
            "sha256, truncated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                1,
                2,
                "raw",
                relative_path,
                "application/json",
                len(payload) if size is None else size,
                hashlib.sha256(payload).hexdigest() if digest is None else digest,
                False,
            ),
        )
        connection.commit()


def _add_validation_package(data_dir: Path) -> dict[str, bytes]:
    base = data_dir / "evidence" / "1" / "validation" / "3"
    artifacts = {
        "raw/http-recheck.json": b'{"status": 200}',
        "normalized/result.json": b'{"outcome": "confirmed"}',
        "metadata.json": b'{"validator": "test"}',
    }
    manifest_artifacts = []
    for relative, payload in artifacts.items():
        destination = base.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        kind = (
            "raw"
            if relative.startswith("raw/")
            else "normalized"
            if relative.startswith("normalized/")
            else "metadata"
        )
        manifest_artifacts.append(
            {
                "kind": kind,
                "path": relative,
                "media_type": "application/json",
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "truncated": False,
            }
        )
    manifest = json.dumps(
        {
            "schema": "reddock.validation-package/1",
            "artifacts": manifest_artifacts,
        },
        sort_keys=True,
    ).encode()
    manifest_path = base / "raw" / "manifest.json"
    manifest_path.write_bytes(manifest)
    with closing(sqlite3.connect(data_dir / "reddock.db")) as connection:
        connection.execute(
            "INSERT INTO dockyards (id, organization_id, name, status) "
            "VALUES (1, 1, 'Test', 'draft')"
        )
        connection.execute(
            "INSERT INTO findings "
            "(id, dockyard_id, fingerprint, detector, detector_version, rule_id, title, "
            "description, category, severity, confidence, status, first_seen, last_seen) "
            "VALUES (1, 1, ?, 'test', '1', 'test-rule', 'Test', 'Test', 'service', "
            "'low', 'high', 'open', '2026-01-01', '2026-01-01')",
            ("a" * 64,),
        )
        connection.execute(
            "INSERT INTO validation_runs "
            "(id, dockyard_id, finding_id, validator, validator_version, target, status, "
            "evidence_path, metadata_sha256, result_sha256, manifest_sha256) "
            "VALUES (3, 1, 1, 'test', '1', 'http://127.0.0.1', 'completed', ?, ?, ?, ?)",
            (
                "1/validation/3",
                hashlib.sha256(artifacts["metadata.json"]).hexdigest(),
                hashlib.sha256(artifacts["normalized/result.json"]).hexdigest(),
                hashlib.sha256(manifest).hexdigest(),
            ),
        )
        connection.commit()
    return {**artifacts, "raw/manifest.json": manifest}


def _read_database(path: Path) -> str:
    with closing(sqlite3.connect(path)) as connection:
        return str(connection.execute("SELECT value FROM state").fetchone()[0])


def _make_data(root: Path, value: str, evidence: bytes = b"evidence") -> Path:
    root.mkdir()
    _write_database(root / "reddock.db", value)
    evidence_file = root / "evidence" / "dockyard" / "artifact.json"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_bytes(evidence)
    return root


def _archive_parts(path: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read(backup.MANIFEST_NAME))
        members = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if info.filename != backup.MANIFEST_NAME
        }
    return manifest, members


def _write_archive(
    path: Path,
    manifest: dict[str, object],
    members: dict[str, bytes],
    *,
    manifest_bytes: bytes | None = None,
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            backup._private_zip_info(backup.MANIFEST_NAME),
            manifest_bytes
            if manifest_bytes is not None
            else json.dumps(manifest, sort_keys=True).encode(),
        )
        for name, payload in members.items():
            archive.writestr(backup._private_zip_info(name), payload)


def test_create_verify_and_restore_round_trip(tmp_path: Path) -> None:
    source = _make_data(tmp_path / "source", "before", b'{"proof": true}')
    archive = tmp_path / "backups" / "reddock.zip"

    digest = create_backup(source, archive)
    manifest = verify_backup(archive)

    assert digest == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert manifest["schema"] == backup.BACKUP_SCHEMA
    assert [record["path"] for record in manifest["files"]] == [
        backup.DATABASE_MEMBER,
        "evidence/dockyard/artifact.json",
    ]

    target = _make_data(tmp_path / "target", "replacement", b"stale")
    (target / "evidence" / "stale.txt").write_text("remove me")
    restore_backup(target, archive, confirm_replace=True)

    assert _read_database(target / "reddock.db") == "before"
    assert (target / "evidence" / "dockyard" / "artifact.json").read_bytes() == b'{"proof": true}'
    assert not (target / "evidence" / "stale.txt").exists()
    assert not list(target.glob(".restore-*"))
    assert not list(target.glob(".*.rollback-*"))


def test_backup_without_evidence_restores_an_empty_evidence_directory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_database(source / "reddock.db", "database-only")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = _make_data(tmp_path / "target", "old")

    restore_backup(target, archive, confirm_replace=True)

    assert _read_database(target / "reddock.db") == "database-only"
    assert (target / "evidence").is_dir()
    assert not list((target / "evidence").iterdir())


def test_verify_and_restore_accept_bounded_standard_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    payload = archive.read_bytes()
    monkeypatch.setattr(backup.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))

    assert verify_backup(Path("-"))["schema"] == backup.BACKUP_SCHEMA

    target = _make_data(tmp_path / "target", "target")
    monkeypatch.setattr(backup.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    restore_backup(target, Path("-"), confirm_replace=True)
    assert _read_database(target / "reddock.db") == "source"


def test_standard_input_archive_is_bounded_before_zip_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backup, "MAX_ARCHIVE_BYTES", 4)
    monkeypatch.setattr(
        backup.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(b"12345")),
    )

    with pytest.raises(BackupError, match="archive size limit"):
        verify_backup(Path("-"))


def test_standard_input_archive_is_staged_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    monkeypatch.setattr(
        backup.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(archive.read_bytes())),
    )
    real_open_archive = backup._open_archive
    observed: list[int] = []

    @contextmanager
    def inspect_open(path: Path):
        observed.append(stat.S_IMODE(path.stat().st_mode))
        with real_open_archive(path) as opened:
            yield opened

    monkeypatch.setattr(backup, "_open_archive", inspect_open)

    verify_backup(Path("-"))

    if os.name == "posix":
        assert observed == [0o600]


def test_create_refuses_to_replace_an_existing_output(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    archive.write_bytes(b"keep")

    with pytest.raises(BackupError, match="already exists"):
        create_backup(data, archive)

    assert archive.read_bytes() == b"keep"


def test_create_replaces_existing_output_only_with_confirmation(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    archive.write_bytes(b"replace only when confirmed")

    create_backup(data, archive, confirm_overwrite=True)

    assert verify_backup(archive)["schema"] == backup.BACKUP_SCHEMA


def test_create_requires_an_explicit_offline_confirmation(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")

    with pytest.raises(BackupError, match="confirm-offline"):
        backup.create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_output_inside_data_directory(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")

    with pytest.raises(BackupError, match="outside"):
        create_backup(data, data / "backup.zip")


@pytest.mark.parametrize("suffix", ["-journal", "-shm", "-wal"])
def test_create_refuses_sqlite_sidecars(tmp_path: Path, suffix: str) -> None:
    data = _make_data(tmp_path / "data", "current")
    Path(f"{data / 'reddock.db'}{suffix}").touch()

    with pytest.raises(BackupError, match="sidecar"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_a_corrupt_database(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "reddock.db").write_bytes(b"not sqlite")

    with pytest.raises(BackupError, match="integrity check"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_a_stamp_only_database(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        connection.execute("INSERT INTO alembic_version VALUES ('0003_security_audit')")
        connection.commit()

    with pytest.raises(BackupError, match="schema is incomplete"):
        create_backup(data, tmp_path / "backup.zip")


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("DROP TABLE security_audit_events", "schema is incomplete"),
        ("ALTER TABLE security_audit_events DROP COLUMN request_id", "schema semantics"),
        ("DROP INDEX ix_security_audit_org_time", "schema semantics"),
    ],
)
def test_create_refuses_a_database_with_an_incomplete_production_schema(
    tmp_path: Path, statement: str, message: str
) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute(statement)
        connection.commit()

    with pytest.raises(BackupError, match=message):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_changed_column_nullability(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        original = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()[0]
        changed = original.replace(
            "display_name VARCHAR(120) NOT NULL",
            "display_name VARCHAR(120)",
        )
        assert changed != original
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = 'users'",
            (changed,),
        )
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version = {schema_version + 1}")
        connection.commit()

    with pytest.raises(BackupError, match="schema semantics"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_changed_foreign_key_behavior(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        original = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'security_audit_events'"
        ).fetchone()[0]
        changed = original.replace("ON DELETE RESTRICT", "ON DELETE CASCADE")
        assert changed != original
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? "
            "WHERE type = 'table' AND name = 'security_audit_events'",
            (changed,),
        )
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version = {schema_version + 1}")
        connection.commit()

    with pytest.raises(BackupError, match="schema semantics"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_changed_column_default(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        original = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'organizations'"
        ).fetchone()[0]
        changed = original.replace("DEFAULT CURRENT_TIMESTAMP", "DEFAULT CURRENT_DATE")
        assert changed != original
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? "
            "WHERE type = 'table' AND name = 'organizations'",
            (changed,),
        )
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute(f"PRAGMA schema_version = {schema_version + 1}")
        connection.commit()

    with pytest.raises(BackupError, match="schema semantics"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_unexpected_database_trigger(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute(
            "CREATE TRIGGER unexpected_state_write AFTER INSERT ON state "
            "BEGIN SELECT 1; END"
        )
        connection.commit()

    with pytest.raises(BackupError, match="schema semantics"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_unexpected_generated_column(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute(
            "ALTER TABLE organizations ADD COLUMN folded_slug TEXT "
            "GENERATED ALWAYS AS (lower(slug)) VIRTUAL"
        )
        connection.commit()

    with pytest.raises(BackupError, match="schema semantics"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_changed_index_collation_and_direction(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute("DROP INDEX ix_security_audit_org_time")
        connection.execute(
            "CREATE INDEX ix_security_audit_org_time ON security_audit_events "
            "(organization_id COLLATE NOCASE DESC, created_at)"
        )
        connection.commit()

    with pytest.raises(BackupError, match="schema semantics"):
        create_backup(data, tmp_path / "backup.zip")


def test_check_scanner_ignores_quoted_and_commented_spoofs() -> None:
    sql = """
    CREATE TABLE example (
      'CHECK(fake_single)' TEXT,
      "CHECK(fake_double)" TEXT,
      `CHECK(fake_backtick)` TEXT,
      [CHECK(fake_bracket)] TEXT,
      value INTEGER CHECK/* interstitial CHECK(fake) */(value > 0),
      -- CHECK(fake_line)
      CHECK (value < 10) /* CHECK(fake_block) */
    )
    """

    assert backup._check_clauses(sql) == ("value < 10", "value > 0")


def test_create_refuses_missing_local_identity_seed(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute("DELETE FROM memberships")
        connection.execute("DELETE FROM users")
        connection.execute("DELETE FROM organizations")
        connection.commit()

    with pytest.raises(BackupError, match="local identity seed"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_refuses_foreign_key_corruption(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    with closing(sqlite3.connect(data / "reddock.db")) as connection:
        connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))"
        )
        connection.execute("INSERT INTO child VALUES (99)")
        connection.commit()

    with pytest.raises(BackupError, match="foreign-key"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_enforces_total_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _make_data(tmp_path / "data", "current")
    monkeypatch.setattr(backup, "MAX_UNCOMPRESSED_BYTES", 1)

    with pytest.raises(BackupError, match="size limit"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_enforces_database_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _make_data(tmp_path / "data", "current")
    monkeypatch.setattr(backup, "MAX_DATABASE_BYTES", 1)

    with pytest.raises(BackupError, match="database size limit"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_enforces_file_count_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _make_data(tmp_path / "data", "current")
    monkeypatch.setattr(backup, "MAX_ARCHIVE_ENTRIES", 1)

    with pytest.raises(BackupError, match="too many files"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_enforces_evidence_directory_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _make_data(tmp_path / "data", "current")
    monkeypatch.setattr(backup, "MAX_EVIDENCE_DIRECTORIES", 1)

    with pytest.raises(BackupError, match="too many directories"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_enforces_evidence_depth_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _make_data(tmp_path / "data", "current")
    monkeypatch.setattr(backup, "MAX_EVIDENCE_DEPTH", 0)

    with pytest.raises(BackupError, match="directory depth"):
        create_backup(data, tmp_path / "backup.zip")


def test_create_enforces_database_evidence_reference_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _make_data(tmp_path / "data", "current")
    referenced = data / "evidence" / "1" / "2" / "raw" / "result.json"
    referenced.parent.mkdir(parents=True)
    referenced.write_bytes(b"retained")
    _add_evidence_record(
        data / "reddock.db",
        relative_path="raw/result.json",
        payload=b"retained",
    )
    monkeypatch.setattr(backup, "MAX_DATABASE_EVIDENCE_REFERENCES", 0)

    with pytest.raises(BackupError, match="too many evidence references"):
        create_backup(data, tmp_path / "backup.zip")


def test_verify_rejects_a_tampered_member(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    members["evidence/dockyard/artifact.json"] = b"changed"
    tampered = tmp_path / "tampered.zip"
    _write_archive(tampered, manifest, members)

    with pytest.raises(BackupError, match="(size|hash) does not match"):
        verify_backup(tampered)


def test_verify_checks_the_archived_sqlite_database(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    corrupt = b"not a SQLite database"
    members[backup.DATABASE_MEMBER] = corrupt
    database_record = manifest["files"][0]
    database_record["size_bytes"] = len(corrupt)
    database_record["sha256"] = hashlib.sha256(corrupt).hexdigest()
    malformed = tmp_path / "malformed.zip"
    _write_archive(malformed, manifest, members)

    with pytest.raises(BackupError, match="integrity check"):
        verify_backup(malformed)


def test_verify_accepts_a_backup_created_by_an_older_release(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    manifest["application"]["version"] = "0.7.0"
    older = tmp_path / "older.zip"
    _write_archive(older, manifest, members)

    assert verify_backup(older)["application"]["version"] == "0.7.0"


def test_create_rejects_missing_database_referenced_evidence(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    _add_evidence_record(
        data / "reddock.db",
        relative_path="raw/result.json",
        payload=b"missing",
    )

    with pytest.raises(BackupError, match="missing backup evidence"):
        create_backup(data, tmp_path / "backup.zip")

    assert not (tmp_path / "backup.zip").exists()


def test_create_validates_database_referenced_evidence_hash_and_size(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    referenced = data / "evidence" / "1" / "2" / "raw" / "result.json"
    referenced.parent.mkdir(parents=True)
    referenced.write_bytes(b"retained")
    _add_evidence_record(
        data / "reddock.db",
        relative_path="raw/result.json",
        payload=b"retained",
    )

    archive = tmp_path / "backup.zip"
    create_backup(data, archive)

    assert verify_backup(archive)["schema"] == backup.BACKUP_SCHEMA


def test_create_reconciles_every_validation_manifest_artifact(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    _add_validation_package(data)
    archive = tmp_path / "backup.zip"

    create_backup(data, archive)

    assert verify_backup(archive)["schema"] == backup.BACKUP_SCHEMA


def test_verify_rejects_validation_raw_artifact_not_matching_nested_manifest(
    tmp_path: Path,
) -> None:
    data = _make_data(tmp_path / "data", "current")
    _add_validation_package(data)
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    member = "evidence/1/validation/3/raw/http-recheck.json"
    members[member] = b'{"status": 500}'
    record = next(item for item in manifest["files"] if item["path"] == member)
    record["size_bytes"] = len(members[member])
    record["sha256"] = hashlib.sha256(members[member]).hexdigest()
    tampered = tmp_path / "tampered.zip"
    _write_archive(tampered, manifest, members)

    with pytest.raises(BackupError, match="hash does not match"):
        verify_backup(tampered)


def test_verify_rejects_undeclared_archive_members(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    members["evidence/undeclared.txt"] = b"surprise"
    tampered = tmp_path / "tampered.zip"
    _write_archive(tampered, manifest, members)

    with pytest.raises(BackupError, match="do not match"):
        verify_backup(tampered)


def test_verify_enforces_archive_size_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    create_backup(data, archive)
    monkeypatch.setattr(backup, "MAX_ARCHIVE_BYTES", archive.stat().st_size - 1)

    with pytest.raises(BackupError, match="bounded regular file"):
        verify_backup(archive)


def test_verify_preflights_entry_count_before_zipfile_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    create_backup(data, archive)
    monkeypatch.setattr(backup, "MAX_ARCHIVE_ENTRIES", 1)

    def unexpected_zipfile(*args, **kwargs):
        raise AssertionError("ZipFile parsed the central directory before the entry cap")

    monkeypatch.setattr(backup.zipfile, "ZipFile", unexpected_zipfile)
    with pytest.raises(BackupError, match="too many entries"):
        verify_backup(archive)


def test_verify_preflights_central_directory_size(tmp_path: Path, monkeypatch) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    create_backup(data, archive)
    monkeypatch.setattr(backup, "MAX_CENTRAL_DIRECTORY_BYTES", 1)

    with pytest.raises(BackupError, match="central directory"):
        verify_backup(archive)


def test_created_archive_uses_private_portable_member_modes(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive_path = tmp_path / "backup.zip"
    create_backup(data, archive_path)

    with zipfile.ZipFile(archive_path) as archive:
        assert all(info.create_system == 3 for info in archive.infolist())
        assert all(stat.S_IMODE(info.external_attr >> 16) == 0o600 for info in archive.infolist())
    if os.name == "posix":
        assert stat.S_IMODE(archive_path.stat().st_mode) == 0o600


def test_verify_rejects_duplicate_archive_members(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr(backup._private_zip_info(backup.MANIFEST_NAME), json.dumps(manifest))
        for name, payload in members.items():
            archive.writestr(backup._private_zip_info(name), payload)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr(
                backup._private_zip_info("evidence/dockyard/artifact.json"), b"duplicate"
            )
    with pytest.raises(BackupError, match="duplicate entries"):
        verify_backup(duplicate)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda manifest: manifest.update({"unexpected": True}), "structure"),
        (lambda manifest: manifest.update({"created_at": "yesterday"}), "creation time"),
        (
            lambda manifest: manifest.update(
                {"application": {"name": "Other", "version": "0.8.0"}}
            ),
            "application declaration",
        ),
        (lambda manifest: manifest["files"][0].update({"mode": "rw"}), "file record"),
        (lambda manifest: manifest["files"].reverse(), "canonical order"),
    ],
)
def test_verify_rejects_noncanonical_manifests(
    tmp_path: Path,
    mutate: Callable[[dict[str, object]], None],
    message: str,
) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    mutate(manifest)
    malformed = tmp_path / "malformed.zip"
    _write_archive(malformed, manifest, members)

    with pytest.raises(BackupError, match=message):
        verify_backup(malformed)


def test_verify_rejects_non_utf8_json(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.zip"
    _write_archive(malformed, {}, {}, manifest_bytes="{}".encode("utf-16"))

    with pytest.raises(BackupError, match="UTF-8 JSON"):
        verify_backup(malformed)


@pytest.mark.parametrize(
    "name",
    [
        "evidence/CON.txt",
        "evidence/CONIN$.txt",
        "evidence/CONOUT$",
        "evidence/COM¹.txt",
        "evidence/com²",
        "evidence/Com³.log",
        "evidence/LPT¹.txt",
        "evidence/lpt²",
        "evidence/Lpt³.log",
        "evidence/name. ",
        "evidence/name.",
        "evidence/a:b",
        'evidence/a<b>c"d|e?f*g',
        "evidence/control\x01",
        "evidence/../escape",
        "evidence//alias.txt",
        "evidence/./alias.txt",
        "evidence\\windows",
    ],
)
def test_portable_member_policy_rejects_cross_platform_aliases(name: str) -> None:
    assert not backup._safe_member(name)


def test_verify_rejects_path_traversal(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    record = manifest["files"][1]
    record["path"] = "evidence/../../outside.txt"
    payload = members.pop("evidence/dockyard/artifact.json")
    members["evidence/../../outside.txt"] = payload
    malicious = tmp_path / "malicious.zip"
    _write_archive(malicious, manifest, members)

    with pytest.raises(BackupError, match="unsafe"):
        verify_backup(malicious)

    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(BackupError, match="unsafe"):
        backup._extract_verified(malicious, staging)
    assert not (tmp_path / "outside.txt").exists()


def test_verify_rejects_a_zip_symlink_member(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    original = tmp_path / "original.zip"
    create_backup(data, original)
    manifest, members = _archive_parts(original)
    malicious = tmp_path / "symlink.zip"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr(backup._private_zip_info(backup.MANIFEST_NAME), json.dumps(manifest))
        archive.writestr(
            backup._private_zip_info(backup.DATABASE_MEMBER), members[backup.DATABASE_MEMBER]
        )
        info = zipfile.ZipInfo("evidence/dockyard/artifact.json")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"../../outside")

    with pytest.raises(BackupError, match="non-regular"):
        verify_backup(malicious)


def test_restore_requires_explicit_confirmation_without_changes(tmp_path: Path) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = _make_data(tmp_path / "target", "target")

    with pytest.raises(BackupError, match="confirm-replace"):
        restore_backup(target, archive, confirm_replace=False)

    assert _read_database(target / "reddock.db") == "target"


def test_restore_requires_an_explicit_offline_confirmation(tmp_path: Path) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = _make_data(tmp_path / "target", "target")

    with pytest.raises(BackupError, match="confirm-offline"):
        backup.restore_backup(target, archive, confirm_replace=True)

    assert _read_database(target / "reddock.db") == "target"


def test_restore_refuses_archive_inside_data_directory(tmp_path: Path) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = _make_data(tmp_path / "target", "target")
    inside = target / "backup.zip"
    inside.write_bytes(archive.read_bytes())

    with pytest.raises(BackupError, match="outside"):
        restore_backup(target, inside, confirm_replace=True)


def test_restore_rejects_evidence_only_target_before_creating_a_marker(
    tmp_path: Path,
) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = tmp_path / "target"
    (target / "evidence").mkdir(parents=True)
    (target / "evidence" / "keep.txt").write_text("keep")

    with pytest.raises(BackupError, match="evidence without its SQLite database"):
        restore_backup(target, archive, confirm_replace=True)

    assert not (target / backup.RESTORE_MARKER).exists()
    assert (target / "evidence" / "keep.txt").read_text() == "keep"


def test_restore_rolls_back_both_paths_when_replacement_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _make_data(tmp_path / "source", "source", b"source evidence")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = _make_data(tmp_path / "target", "target", b"target evidence")
    real_replace = backup.os.replace
    calls = 0

    def fail_install_evidence(source_path: Path, destination_path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("simulated replacement failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(backup.os, "replace", fail_install_evidence)

    with pytest.raises(BackupError, match="original data was restored"):
        restore_backup(target, archive, confirm_replace=True)

    assert _read_database(target / "reddock.db") == "target"
    assert (target / "evidence" / "dockyard" / "artifact.json").read_bytes() == b"target evidence"
    assert not list(target.glob(".*.rollback-*"))


def test_restore_orders_tree_and_directory_durability_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _make_data(tmp_path / "source", "source")
    archive = tmp_path / "backup.zip"
    create_backup(source, archive)
    target = _make_data(tmp_path / "target", "target")
    events: list[tuple[str, str]] = []
    real_replace = backup.os.replace

    def record_replace(source_path: Path, destination_path: Path) -> None:
        events.append(("replace", Path(destination_path).name))
        real_replace(source_path, destination_path)

    monkeypatch.setattr(backup.os, "replace", record_replace)
    monkeypatch.setattr(
        backup,
        "_fsync_directory",
        lambda path: events.append(("directory", Path(path).name)),
    )
    monkeypatch.setattr(
        backup,
        "_fsync_tree",
        lambda path: events.append(("tree", Path(path).name)),
    )

    restore_backup(target, archive, confirm_replace=True)

    tree_index = next(index for index, event in enumerate(events) if event[0] == "tree")
    replacement_indexes = [
        index
        for index, event in enumerate(events)
        if event[0] == "replace"
        and (event[1] in {"reddock.db", "evidence"} or "rollback" in event[1])
    ]
    assert replacement_indexes and tree_index < min(replacement_indexes)
    for index in replacement_indexes:
        assert events[index + 1] == ("directory", target.name)


def test_recover_rolls_back_a_prepared_interrupted_restore(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "original", b"original evidence")
    token = "a" * 32
    staging = data / f".restore-{token}"
    (staging / "database").mkdir(parents=True)
    (staging / "evidence").mkdir()
    old_database = data / f".reddock.db.rollback-{token}"
    old_evidence = data / f".evidence.rollback-{token}"
    os.replace(data / "reddock.db", old_database)
    os.replace(data / "evidence", old_evidence)
    _write_database(data / "reddock.db", "partial new")
    (data / "evidence").mkdir()
    (data / "evidence" / "partial.txt").write_text("partial")
    backup._write_restore_marker(
        data / backup.RESTORE_MARKER,
        {
            "schema": "reddock.restore/1",
            "token": token,
            "state": "prepared",
            "had_database": True,
            "had_evidence": True,
        },
        create=True,
    )

    with pytest.raises(BackupError, match="interrupted"):
        backup.assert_no_incomplete_restore(data)
    assert backup.recover_restore(
        data,
        confirm_offline=True,
        confirm_rollback=True,
    )

    assert _read_database(data / "reddock.db") == "original"
    assert (data / "evidence" / "dockyard" / "artifact.json").read_bytes() == b"original evidence"
    assert not (data / backup.RESTORE_MARKER).exists()
    assert not staging.exists()


def test_recover_requires_an_explicit_offline_confirmation(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "original")
    backup._write_restore_marker(
        data / backup.RESTORE_MARKER,
        {
            "schema": "reddock.restore/1",
            "token": "c" * 32,
            "state": "prepared",
            "had_database": True,
            "had_evidence": True,
        },
        create=True,
    )

    with pytest.raises(BackupError, match="confirm-offline"):
        backup.recover_restore(data, confirm_rollback=True)

    assert (data / backup.RESTORE_MARKER).exists()


@pytest.mark.parametrize("suffix", ["-journal", "-shm", "-wal"])
def test_recover_refuses_sqlite_sidecars(tmp_path: Path, suffix: str) -> None:
    data = _make_data(tmp_path / "data", "original")
    Path(f"{data / 'reddock.db'}{suffix}").touch()
    backup._write_restore_marker(
        data / backup.RESTORE_MARKER,
        {
            "schema": "reddock.restore/1",
            "token": "d" * 32,
            "state": "prepared",
            "had_database": True,
            "had_evidence": True,
        },
        create=True,
    )

    with pytest.raises(BackupError, match="sidecar"):
        backup.recover_restore(
            data,
            confirm_offline=True,
            confirm_rollback=True,
        )

    assert (data / backup.RESTORE_MARKER).exists()


def test_recover_refuses_invalid_rollback_types(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "original")
    token = "f" * 32
    (data / f".reddock.db.rollback-{token}").mkdir()
    backup._write_restore_marker(
        data / backup.RESTORE_MARKER,
        {
            "schema": "reddock.restore/1",
            "token": token,
            "state": "prepared",
            "had_database": True,
            "had_evidence": True,
        },
        create=True,
    )

    with pytest.raises(BackupError, match="invalid type"):
        backup.recover_restore(
            data,
            confirm_offline=True,
            confirm_rollback=True,
        )

    assert (data / backup.RESTORE_MARKER).exists()


def test_recover_finalizes_a_committed_interrupted_restore(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "restored", b"restored evidence")
    token = "b" * 32
    staging = data / f".restore-{token}"
    staging.mkdir()
    old_database = data / f".reddock.db.rollback-{token}"
    old_evidence = data / f".evidence.rollback-{token}"
    _write_database(old_database, "old")
    old_evidence.mkdir()
    (old_evidence / "old.txt").write_text("old")
    backup._write_restore_marker(
        data / backup.RESTORE_MARKER,
        {
            "schema": "reddock.restore/1",
            "token": token,
            "state": "committed",
            "had_database": True,
            "had_evidence": True,
        },
        create=True,
    )

    assert backup.recover_restore(
        data,
        confirm_offline=True,
        confirm_rollback=True,
    )

    assert _read_database(data / "reddock.db") == "restored"
    assert not old_database.exists()
    assert not old_evidence.exists()
    assert not staging.exists()
    assert not (data / backup.RESTORE_MARKER).exists()


def test_committed_recovery_preserves_rollbacks_when_live_evidence_is_invalid(
    tmp_path: Path,
) -> None:
    data = _make_data(tmp_path / "data", "restored")
    referenced = data / "evidence" / "1" / "2" / "raw" / "result.json"
    referenced.parent.mkdir(parents=True)
    referenced.write_bytes(b"expected")
    _add_evidence_record(
        data / "reddock.db",
        relative_path="raw/result.json",
        payload=b"expected",
    )
    referenced.write_bytes(b"tampered")
    token = "e" * 32
    old_database = data / f".reddock.db.rollback-{token}"
    old_evidence = data / f".evidence.rollback-{token}"
    _write_database(old_database, "old")
    old_evidence.mkdir()
    (old_evidence / "old.txt").write_text("old")
    backup._write_restore_marker(
        data / backup.RESTORE_MARKER,
        {
            "schema": "reddock.restore/1",
            "token": token,
            "state": "committed",
            "had_database": True,
            "had_evidence": True,
        },
        create=True,
    )

    with pytest.raises(BackupError, match="(hash|size) does not match"):
        backup.recover_restore(
            data,
            confirm_offline=True,
            confirm_rollback=True,
        )

    assert old_database.exists()
    assert old_evidence.exists()
    assert (data / backup.RESTORE_MARKER).exists()


def test_database_startup_refuses_an_interrupted_restore(environment: Path) -> None:
    marker = environment / backup.RESTORE_MARKER
    marker.write_text("incomplete")
    import app.database

    try:
        with pytest.raises(BackupError, match="interrupted"):
            app.database.initialize_database()
    finally:
        marker.unlink()


def test_create_and_verify_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    monkeypatch.setattr(
        "sys.argv",
        [
            "backup",
            "create",
            "--data-dir",
            str(data),
            "--output",
            str(archive),
            "--confirm-offline",
        ],
    )
    assert backup.main() == 0
    assert "Created" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["backup", "verify", "--archive", str(archive)])
    assert backup.main() == 0
    assert "Verified" in capsys.readouterr().out


def test_cli_reports_a_safe_error_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["backup", "verify", "--archive", str(tmp_path / "missing.zip")],
    )

    assert backup.main() == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err.startswith("error:")


def test_create_refuses_evidence_links(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    link = data / "evidence" / "link.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this host")

    with pytest.raises(BackupError, match="cannot contain links"):
        create_backup(data, tmp_path / "backup.zip")


def test_verify_refuses_an_archive_link(tmp_path: Path) -> None:
    data = _make_data(tmp_path / "data", "current")
    archive = tmp_path / "backup.zip"
    create_backup(data, archive)
    link = tmp_path / "backup-link.zip"
    try:
        os.symlink(archive, link)
    except OSError:
        pytest.skip("creating symlinks is unavailable on this host")

    with pytest.raises(BackupError, match="non-link"):
        verify_backup(link)
