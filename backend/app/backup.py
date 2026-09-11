"""Offline, integrity-checked backup and restore for local SQLite deployments."""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import unicodedata
import uuid
import zipfile
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.config import get_settings

BACKUP_SCHEMA = "reddock.backup/1"
MANIFEST_NAME = "manifest.json"
DATABASE_MEMBER = "database/reddock.db"
RESTORE_MARKER = ".reddock-restore.json"
MAX_ARCHIVE_ENTRIES = 100_000
MAX_EVIDENCE_DIRECTORIES = 20_000
MAX_EVIDENCE_DEPTH = 24
MAX_DATABASE_EVIDENCE_REFERENCES = 100_000
MAX_DATABASE_SCHEMA_OBJECTS = 512
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_DATABASE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_UNCOMPRESSED_BYTES + (128 * 1024 * 1024)
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
_ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_MANIFEST_KEYS = {"schema", "application", "created_at", "database", "files"}
_FILE_KEYS = {"path", "sha256", "size_bytes"}
_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")
_WINDOWS_RESERVED = {
    "aux",
    "con",
    "nul",
    "prn",
    "conin$",
    "conout$",
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_SCHEMA_REVISIONS = {
    "0001_v080",
    "0002_identity",
    "0003_security_audit",
    "0004_oidc_attempts",
}
_CURRENT_SCHEMA_REVISION = "0004_oidc_attempts"


class BackupError(RuntimeError):
    """A backup cannot be safely created, verified, or restored."""


def _is_link(path: Path) -> bool:
    """Return true for symlinks and Windows directory junctions."""
    return path.is_symlink() or path.is_junction()


def _path_present(path: Path) -> bool:
    """Include dangling links when deciding whether a path exists."""
    return os.path.lexists(path)


def _hash_file(path: Path, *, max_bytes: int | None = None) -> tuple[int, str]:
    if _is_link(path):
        raise BackupError("A file changed to a link while it was being checked")
    digest = sha256()
    size = 0
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        current = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise BackupError("A file changed identity while it was being checked")
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise BackupError("A file exceeds the fixed size limit")
            digest.update(chunk)
        finished = os.fstat(source.fileno())
        if (opened.st_size, opened.st_mtime_ns) != (
            finished.st_size,
            finished.st_mtime_ns,
        ):
            raise BackupError("A file changed while it was being checked")
    return size, digest.hexdigest()


def _read_bounded_file(path: Path, max_bytes: int) -> bytes:
    if _is_link(path):
        raise BackupError("An evidence file changed to a link while it was being read")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_size > max_bytes
        ):
            raise BackupError("An evidence file is not a bounded regular file")
        payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise BackupError("An evidence file exceeds the fixed size limit")
    return payload


def _known_schema_revisions() -> set[str]:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).with_name("schema_migrations")))
    scripts = ScriptDirectory.from_config(config)
    packaged = {str(revision.revision) for revision in scripts.walk_revisions()}
    return packaged & _SCHEMA_REVISIONS


def _sqlite_affinity(declared_type: object) -> str:
    value = str(declared_type or "").upper()
    if "INT" in value:
        return "INTEGER"
    if any(token in value for token in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if not value or "BLOB" in value:
        return "BLOB"
    if any(token in value for token in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _skip_sql_quoted(sql: str, index: int) -> int:
    opening = sql[index]
    if opening == "[":
        closing = "]"
    else:
        closing = opening
    index += 1
    while index < len(sql):
        if sql[index] == closing:
            if index + 1 < len(sql) and sql[index + 1] == closing:
                index += 2
                continue
            return index + 1
        index += 1
    raise BackupError("SQLite schema contains unterminated quoted SQL")


def _skip_sql_comment(sql: str, index: int) -> int | None:
    if sql.startswith("--", index):
        newline = sql.find("\n", index + 2)
        return len(sql) if newline < 0 else newline + 1
    if sql.startswith("/*", index):
        closing = sql.find("*/", index + 2)
        if closing < 0:
            raise BackupError("SQLite schema contains an unterminated SQL comment")
        return closing + 2
    return None


def _canonical_sql_fragment(value: object) -> str | None:
    if value is None:
        return None
    sql = str(value).strip()
    tokens: list[str] = []
    index = 0
    while index < len(sql):
        comment_end = _skip_sql_comment(sql, index)
        if comment_end is not None:
            index = comment_end
            continue
        character = sql[index]
        if character in {"'", '"', "`", "["}:
            end = _skip_sql_quoted(sql, index)
            tokens.append(sql[index:end])
            index = end
            continue
        if character.isspace():
            index += 1
            continue
        word = re.match(r"[A-Za-z0-9_$]+", sql[index:])
        if word:
            tokens.append(word.group(0).casefold())
            index += word.end()
            continue
        operator = next(
            (
                candidate
                for candidate in ("->>", "<=", ">=", "<>", "!=", "||", "->")
                if sql.startswith(candidate, index)
            ),
            None,
        )
        if operator:
            tokens.append(operator)
            index += len(operator)
            continue
        tokens.append(character.casefold())
        index += 1
    return " ".join(tokens)


def _table_ddl_contract(create_sql: object) -> tuple[tuple[str, ...], str]:
    sql = str(create_sql or "")
    opening = -1
    index = 0
    while index < len(sql):
        comment_end = _skip_sql_comment(sql, index)
        if comment_end is not None:
            index = comment_end
            continue
        if sql[index] in {"'", '"', "`", "["}:
            index = _skip_sql_quoted(sql, index)
            continue
        if sql[index] == "(":
            opening = index
            break
        index += 1
    if opening < 0:
        raise BackupError("SQLite table declaration has no column list")

    clauses: list[str] = []
    depth = 1
    start = opening + 1
    cursor = start
    closing = -1
    while cursor < len(sql):
        comment_end = _skip_sql_comment(sql, cursor)
        if comment_end is not None:
            cursor = comment_end
            continue
        if sql[cursor] in {"'", '"', "`", "["}:
            cursor = _skip_sql_quoted(sql, cursor)
            continue
        if sql[cursor] == "(":
            depth += 1
        elif sql[cursor] == ")":
            depth -= 1
            if depth == 0:
                clause = _canonical_table_clause(sql[start:cursor])
                if clause:
                    clauses.append(clause)
                closing = cursor
                break
        elif sql[cursor] == "," and depth == 1:
            clause = _canonical_table_clause(sql[start:cursor])
            if not clause:
                raise BackupError("SQLite table declaration contains an empty clause")
            clauses.append(clause)
            start = cursor + 1
        cursor += 1
    if closing < 0:
        raise BackupError("SQLite table declaration has unbalanced parentheses")
    suffix = _canonical_sql_fragment(sql[closing + 1 :]) or ""
    return tuple(sorted(clauses)), suffix


def _canonical_table_clause(value: object) -> str | None:
    canonical = _canonical_sql_fragment(value)
    if canonical and canonical.startswith("constraint "):
        parts = canonical.split(" ", 2)
        if len(parts) == 3:
            return parts[2]
    return canonical


def _check_clauses(create_sql: object) -> tuple[str, ...]:
    sql = str(create_sql or "")
    clauses: list[str] = []
    index = 0
    while index < len(sql):
        comment_end = _skip_sql_comment(sql, index)
        if comment_end is not None:
            index = comment_end
            continue
        if sql[index] in {"'", '"', "`", "["}:
            index = _skip_sql_quoted(sql, index)
            continue
        match = re.match(r"check\b", sql[index:], re.IGNORECASE)
        if match and (index == 0 or not (sql[index - 1].isalnum() or sql[index - 1] == "_")):
            cursor = index + match.end()
            while cursor < len(sql):
                comment_end = _skip_sql_comment(sql, cursor)
                if comment_end is not None:
                    cursor = comment_end
                elif sql[cursor].isspace():
                    cursor += 1
                else:
                    break
            if cursor >= len(sql) or sql[cursor] != "(":
                raise BackupError("SQLite schema contains an invalid CHECK clause")
            start = cursor
            depth = 0
            while cursor < len(sql):
                comment_end = _skip_sql_comment(sql, cursor)
                if comment_end is not None:
                    cursor = comment_end
                    continue
                if sql[cursor] in {"'", '"', "`", "["}:
                    cursor = _skip_sql_quoted(sql, cursor)
                    continue
                if sql[cursor] == "(":
                    depth += 1
                elif sql[cursor] == ")":
                    depth -= 1
                    if depth == 0:
                        expression = _canonical_sql_fragment(sql[start + 1 : cursor])
                        clauses.append(str(expression))
                        cursor += 1
                        break
                cursor += 1
            else:
                raise BackupError("SQLite schema contains an unterminated CHECK clause")
            index = cursor
            continue
        index += 1
    return tuple(sorted(clauses))


def _canonical_default(value: object) -> str | None:
    canonical = _canonical_sql_fragment(value)
    if canonical is None:
        return None
    while canonical.startswith("(") and canonical.endswith(")"):
        inner = canonical[1:-1]
        depth = 0
        balanced = True
        for character in inner:
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
        if not balanced or depth:
            break
        canonical = inner.strip()
    return canonical


def _schema_contract(
    connection: sqlite3.Connection,
    tables: set[str],
) -> dict[str, tuple[object, ...]]:
    contract: dict[str, tuple[object, ...]] = {}
    for table in sorted(tables):
        quoted_table = table.replace('"', '""')
        columns = []
        for index, row in enumerate(
            connection.execute(f'PRAGMA table_xinfo("{quoted_table}")'),
            start=1,
        ):
            if index > MAX_DATABASE_SCHEMA_OBJECTS:
                raise BackupError("SQLite table contains too many columns")
            columns.append(
                (
                    str(row[1]),
                    _sqlite_affinity(row[2]),
                    bool(row[3]),
                    int(row[5]),
                    _canonical_default(row[4]),
                    int(row[6]),
                )
            )

        foreign_keys = []
        for index, row in enumerate(
            connection.execute(f'PRAGMA foreign_key_list("{quoted_table}")'),
            start=1,
        ):
            if index > MAX_DATABASE_SCHEMA_OBJECTS:
                raise BackupError("SQLite table contains too many foreign keys")
            foreign_keys.append(
                (str(row[2]), str(row[3]), str(row[4]), str(row[5]), str(row[6]), str(row[7]))
            )

        indexes = []
        for index, row in enumerate(
            connection.execute(f'PRAGMA index_list("{quoted_table}")'),
            start=1,
        ):
            if index > MAX_DATABASE_SCHEMA_OBJECTS:
                raise BackupError("SQLite table contains too many indexes")
            name = str(row[1])
            quoted_name = name.replace('"', '""')
            index_columns = tuple(
                (
                    int(item[1]),
                    None if item[2] is None else str(item[2]),
                    bool(item[3]),
                    None if item[4] is None else str(item[4]).casefold(),
                    bool(item[5]),
                )
                for item in connection.execute(f'PRAGMA index_xinfo("{quoted_name}")')
            )
            origin = str(row[3])
            stable_name = None if name.startswith("sqlite_autoindex_") else name
            indexes.append((stable_name, bool(row[2]), origin, bool(row[4]), index_columns))

        create_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        table_flags = connection.execute(
            "SELECT wr, strict FROM pragma_table_list WHERE schema = 'main' AND name = ?",
            (table,),
        ).fetchone()
        if table_flags is None:
            raise BackupError("SQLite table flags could not be inspected")
        contract[table] = (
            tuple(sorted(columns)),
            tuple(sorted(foreign_keys)),
            tuple(sorted(indexes, key=repr)),
            _check_clauses(create_sql[0] if create_sql else None),
            (bool(table_flags[0]), bool(table_flags[1])),
            _table_ddl_contract(create_sql[0] if create_sql else None),
        )
    return contract


def _trigger_contract(connection: sqlite3.Connection) -> tuple[tuple[str, str, str], ...]:
    triggers = []
    for index, row in enumerate(
        connection.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger'"
        ),
        start=1,
    ):
        if index > MAX_DATABASE_SCHEMA_OBJECTS:
            raise BackupError("SQLite schema contains too many triggers")
        triggers.append((str(row[0]), str(row[1]), str(_canonical_sql_fragment(row[2]))))
    return tuple(sorted(triggers))


@functools.lru_cache(maxsize=len(_SCHEMA_REVISIONS))
def _reference_schema_contract(
    revision: str,
) -> tuple[dict[str, tuple[object, ...]], tuple[tuple[str, str, str], ...]]:
    from sqlalchemy import create_engine

    import app.models  # noqa: F401
    from app.migration_runner import upgrade_database

    with tempfile.TemporaryDirectory(prefix="reddock-schema-") as temporary:
        database = Path(temporary) / "reference.db"
        engine = create_engine(f"sqlite:///{database.as_posix()}")
        try:
            upgrade_database(engine)
            if revision != _CURRENT_SCHEMA_REVISION:
                with engine.begin() as connection:
                    config = Config()
                    config.set_main_option(
                        "script_location",
                        str(Path(__file__).with_name("schema_migrations")),
                    )
                    config.attributes["connection"] = connection
                    command.downgrade(config, revision)
        finally:
            engine.dispose()
        with closing(sqlite3.connect(database)) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
                if row[0] != "alembic_version"
            }
            return _schema_contract(connection, tables), _trigger_contract(connection)


def _validate_local_identity(connection: sqlite3.Connection, revision: str) -> None:
    if revision == "0001_v080":
        return
    organization = connection.execute(
        "SELECT id, slug FROM organizations WHERE id = 1"
    ).fetchone()
    user = connection.execute(
        "SELECT id, oidc_issuer, oidc_subject FROM users WHERE id = 1"
    ).fetchone()
    membership = connection.execute(
        "SELECT id, organization_id, user_id, role, status FROM memberships WHERE id = 1"
    ).fetchone()
    if (
        organization != (1, "local")
        or user != (1, "urn:reddock:local", "single-operator")
        or membership != (1, 1, 1, "owner", "active")
    ):
        raise BackupError("SQLite local identity seed is missing or inconsistent")


def _validate_database_schema(connection: sqlite3.Connection, revision: str) -> None:
    present: set[str] = set()
    other_objects: list[tuple[str, str]] = []
    cursor = connection.execute(
        "SELECT type, name FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'view', 'trigger') AND name NOT LIKE 'sqlite_%'"
    )
    for index, row in enumerate(cursor, start=1):
        if index > MAX_DATABASE_SCHEMA_OBJECTS:
            raise BackupError("SQLite schema contains too many objects")
        object_type, name = str(row[0]), str(row[1])
        if object_type == "table" and name != "alembic_version":
            present.add(name)
        elif object_type != "table":
            other_objects.append((object_type, name))
    expected, expected_triggers = _reference_schema_contract(revision)
    if not set(expected).issubset(present):
        raise BackupError("SQLite schema is incomplete for its recorded migration revision")
    required_names = {name.casefold() for name in expected}
    if any(name.casefold() in required_names for _, name in other_objects):
        raise BackupError("SQLite schema object shadows a required table name")
    actual = _schema_contract(connection, set(expected))
    if actual != expected or _trigger_contract(connection) != expected_triggers:
        raise BackupError("SQLite schema semantics do not match its migration revision")
    _validate_local_identity(connection, revision)


def _check_database(database: Path) -> str:
    if _is_link(database) or not database.is_file():
        raise BackupError("SQLite database must be a regular, non-link file")
    if database.stat(follow_symlinks=False).st_size > MAX_DATABASE_BYTES:
        raise BackupError("SQLite database exceeds the fixed database size limit")
    for suffix in ("-journal", "-shm", "-wal"):
        if _path_present(Path(f"{database}{suffix}")):
            raise BackupError(
                "SQLite has an active or uncheckpointed sidecar; stop RedDock cleanly first"
            )
    try:
        uri = f"{database.resolve().as_uri()}?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            result = connection.execute("PRAGMA quick_check").fetchone()
            foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchone()
            revisions = connection.execute("SELECT version_num FROM alembic_version").fetchmany(2)
            if result != ("ok",):
                raise BackupError("SQLite integrity check failed")
            if foreign_key_errors is not None:
                raise BackupError("SQLite foreign-key integrity check failed")
            if (
                len(revisions) != 1
                or not isinstance(revisions[0][0], str)
                or revisions[0][0] not in _known_schema_revisions()
            ):
                raise BackupError("SQLite schema revision is missing or unsupported")
            revision = str(revisions[0][0])
            _validate_database_schema(connection, revision)
    except (OSError, sqlite3.Error) as error:
        raise BackupError("SQLite integrity check could not be completed") from error
    return revision


def _evidence_files(evidence: Path) -> list[tuple[str, Path]]:
    if _is_link(evidence):
        raise BackupError("Evidence root cannot be a link")
    if not evidence.exists():
        return []
    if not evidence.is_dir():
        raise BackupError("Evidence root must be a directory")

    members: list[tuple[str, Path]] = []
    directories = 1
    pending = [(evidence, 0)]
    while pending:
        root, depth = pending.pop()
        try:
            entries = os.scandir(root)
        except OSError as error:
            raise BackupError("Evidence directory could not be read") from error
        with entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_symlink() or _is_link(path):
                    raise BackupError("Evidence cannot contain links")
                if entry.is_dir(follow_symlinks=False):
                    if depth >= MAX_EVIDENCE_DEPTH:
                        raise BackupError("Evidence exceeds the fixed directory depth limit")
                    directories += 1
                    if directories > MAX_EVIDENCE_DIRECTORIES:
                        raise BackupError("Evidence contains too many directories")
                    pending.append((path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise BackupError("Evidence must contain only regular files")
                if len(members) >= MAX_ARCHIVE_ENTRIES - 1:
                    raise BackupError("Backup contains too many files")
                relative = path.relative_to(evidence).as_posix()
                member = f"evidence/{relative}"
                if not _safe_member(member):
                    raise BackupError("Evidence contains a path that is not portable")
                members.append((member, path))
    members.sort()
    if len({name.casefold() for name, _ in members}) != len(members):
        raise BackupError("Evidence contains portable path aliases")
    return members


def _safe_member(name: str) -> bool:
    if (
        not name
        or len(name) > 1024
        or "\\" in name
        or ":" in name
        or any(character in '<>"|?*' for character in name)
        or "\x00" in name
        or unicodedata.normalize("NFC", name) != name
    ):
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name:
        return False
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if (
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            or part[-1] in {" ", "."}
            or stem in _WINDOWS_RESERVED
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
        ):
            return False
    return True


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _manifest_bytes(files: list[dict[str, object]], schema_revision: str) -> bytes:
    document = {
        "schema": BACKUP_SCHEMA,
        "application": {"name": "RedDock", "version": get_settings().version},
        "created_at": datetime.now(UTC).isoformat(),
        "database": {
            "engine": "sqlite",
            "path": DATABASE_MEMBER,
            "schema_revision": schema_revision,
        },
        "files": files,
    }
    return json.dumps(document, indent=2, sort_keys=True).encode("utf-8")


def _validate_created_at(value: object) -> None:
    if not isinstance(value, str):
        raise BackupError("Backup creation time is invalid")
    try:
        created_at = datetime.fromisoformat(value)
    except ValueError as error:
        raise BackupError("Backup creation time is invalid") from error
    if created_at.tzinfo is None or created_at.utcoffset() != UTC.utcoffset(created_at):
        raise BackupError("Backup creation time must include a UTC offset")


def _read_manifest(archive: zipfile.ZipFile) -> tuple[dict[str, object], list[dict[str, object]]]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(infos) > MAX_ARCHIVE_ENTRIES + 1:
        raise BackupError("Backup archive contains too many entries")
    if len(names) != len(set(names)):
        raise BackupError("Backup archive contains duplicate entries")
    if len({name.casefold() for name in names}) != len(names):
        raise BackupError("Backup archive contains portable path aliases")
    if MANIFEST_NAME not in names:
        raise BackupError("Backup archive has no manifest")
    for info in infos:
        if not _safe_member(info.filename):
            raise BackupError("Backup archive contains an unsafe member name")
        if info.flag_bits & 0x1:
            raise BackupError("Encrypted backup members are unsupported")
        if info.compress_type not in _ALLOWED_COMPRESSION:
            raise BackupError("Backup archive uses unsupported compression")
        unix_mode = info.external_attr >> 16
        if info.is_dir() or stat.S_ISLNK(unix_mode):
            raise BackupError("Backup contains a non-regular entry")
        if (
            info.create_system != 3
            or stat.S_IFMT(unix_mode) != stat.S_IFREG
            or stat.S_IMODE(unix_mode) != 0o600
        ):
            raise BackupError("Backup members must use the private regular-file mode")

    manifest_info = archive.getinfo(MANIFEST_NAME)
    if manifest_info.file_size > MAX_MANIFEST_BYTES:
        raise BackupError("Backup manifest exceeds the fixed size limit")
    try:
        manifest = json.loads(archive.read(manifest_info).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BackupError("Backup manifest is not valid UTF-8 JSON") from error
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
        raise BackupError("Backup manifest structure is unsupported")
    if manifest.get("schema") != BACKUP_SCHEMA:
        raise BackupError("Backup manifest schema is unsupported")
    application = manifest.get("application")
    if (
        not isinstance(application, dict)
        or set(application) != {"name", "version"}
        or application.get("name") != "RedDock"
        or not isinstance(application.get("version"), str)
        or not _VERSION.fullmatch(str(application["version"]))
    ):
        raise BackupError("Backup application declaration is unsupported")
    _validate_created_at(manifest.get("created_at"))
    database = manifest.get("database")
    if (
        not isinstance(database, dict)
        or set(database) != {"engine", "path", "schema_revision"}
        or database.get("engine") != "sqlite"
        or database.get("path") != DATABASE_MEMBER
        or database.get("schema_revision") not in _known_schema_revisions()
    ):
        raise BackupError("Backup database declaration is unsupported")

    records = manifest.get("files")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_ARCHIVE_ENTRIES:
        raise BackupError("Backup manifest file list is invalid")
    expected_names: set[str] = set()
    ordered_names: list[str] = []
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != _FILE_KEYS:
            raise BackupError("Backup manifest contains an invalid file record")
        name = record.get("path")
        size = record.get("size_bytes")
        digest = record.get("sha256")
        if (
            not isinstance(name, str)
            or not _safe_member(name)
            or not (name == DATABASE_MEMBER or name.startswith("evidence/"))
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(digest, str)
            or not _valid_sha256(digest)
        ):
            raise BackupError("Backup manifest contains an unsafe file record")
        if name == DATABASE_MEMBER and size > MAX_DATABASE_BYTES:
            raise BackupError("Backup SQLite database exceeds the fixed database size limit")
        if name in expected_names:
            raise BackupError("Backup manifest contains duplicate file records")
        expected_names.add(name)
        ordered_names.append(name)
        total += size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise BackupError("Backup exceeds the fixed uncompressed size limit")
    if DATABASE_MEMBER not in expected_names:
        raise BackupError("Backup contains no SQLite database")
    if ordered_names != sorted(ordered_names):
        raise BackupError("Backup manifest file records are not in canonical order")
    if len({name.casefold() for name in expected_names}) != len(expected_names):
        raise BackupError("Backup manifest contains portable path aliases")
    actual_names = set(names) - {MANIFEST_NAME}
    if actual_names != expected_names:
        raise BackupError("Backup contents do not match its manifest")
    return manifest, records


def _verify_open_archive(
    archive: zipfile.ZipFile,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    manifest, records = _read_manifest(archive)
    for record in records:
        name = str(record["path"])
        info = archive.getinfo(name)
        if info.file_size != record["size_bytes"]:
            raise BackupError(f"Backup member size does not match: {name}")
        member_digest = sha256()
        with archive.open(info) as source:
            while chunk := source.read(1024 * 1024):
                member_digest.update(chunk)
        if member_digest.hexdigest() != record["sha256"]:
            raise BackupError(f"Backup member hash does not match: {name}")
    return manifest, records


def _evidence_member(base: object, relative: object) -> str:
    if not isinstance(base, str) or not isinstance(relative, str):
        raise BackupError("SQLite contains an invalid evidence path")
    member = f"evidence/{base}/{relative}"
    if not _safe_member(member) or not member.startswith("evidence/"):
        raise BackupError("SQLite contains an unsafe evidence path")
    return member


def _validate_reference(
    records: dict[str, dict[str, object]],
    member: str,
    digest: object,
    size: object | None = None,
) -> None:
    if not isinstance(digest, str) or not _valid_sha256(digest):
        raise BackupError("SQLite contains an invalid evidence hash")
    record = records.get(member)
    if record is None:
        raise BackupError(f"SQLite references missing backup evidence: {member}")
    if record["sha256"] != digest:
        raise BackupError(f"SQLite evidence hash does not match backup member: {member}")
    if size is not None:
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BackupError("SQLite contains an invalid evidence size")
        if record["size_bytes"] != size:
            raise BackupError(f"SQLite evidence size does not match backup member: {member}")


def _validate_validation_manifest(
    records: dict[str, dict[str, object]],
    base: str,
    payload: bytes,
) -> None:
    if len(payload) > MAX_MANIFEST_BYTES:
        raise BackupError("Validation evidence manifest exceeds the fixed size limit")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise BackupError("Validation evidence manifest is invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "artifacts"}
        or document.get("schema") != "reddock.validation-package/1"
        or not isinstance(document.get("artifacts"), list)
        or len(document["artifacts"]) != 3
    ):
        raise BackupError("Validation evidence manifest structure is unsupported")
    expected_paths = {"raw/http-recheck.json", "normalized/result.json", "metadata.json"}
    seen: set[str] = set()
    for item in document["artifacts"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"kind", "path", "media_type", "bytes", "sha256", "truncated"}
        ):
            raise BackupError("Validation evidence manifest contains an invalid artifact")
        relative = item.get("path")
        size = item.get("bytes")
        digest = item.get("sha256")
        if (
            not isinstance(item.get("kind"), str)
            or not item["kind"]
            or not isinstance(item.get("media_type"), str)
            or not item["media_type"]
            or not isinstance(item.get("truncated"), bool)
            or not isinstance(relative, str)
            or relative not in expected_paths
            or relative in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise BackupError("Validation evidence manifest contains an unsafe artifact")
        seen.add(relative)
        member = _evidence_member(base, relative)
        _validate_reference(records, member, digest, size)
    if seen != expected_paths:
        raise BackupError("Validation evidence manifest is incomplete")


def _validate_database_evidence(
    database: Path,
    records: list[dict[str, object]],
    expected_revision: object,
    evidence_reader: Callable[[str], bytes],
) -> None:
    revision = _check_database(database)
    if revision != expected_revision:
        raise BackupError("SQLite schema revision does not match the backup manifest")
    by_name = {str(record["path"]): record for record in records}
    try:
        uri = f"{database.resolve().as_uri()}?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            tables: set[str] = set()
            for index, row in enumerate(
                connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'"),
                start=1,
            ):
                if index > MAX_DATABASE_SCHEMA_OBJECTS:
                    raise BackupError("SQLite schema contains too many tables")
                tables.add(str(row[0]))
            reference_count = 0
            if "evidence_records" in tables:
                rows = connection.execute(
                    "SELECT dockyard_id, discovery_run_id, relative_path, size_bytes, sha256 "
                    "FROM evidence_records"
                )
                for dockyard_id, run_id, relative, size, digest in rows:
                    reference_count += 1
                    if reference_count > MAX_DATABASE_EVIDENCE_REFERENCES:
                        raise BackupError("SQLite contains too many evidence references")
                    member = _evidence_member(f"{int(dockyard_id)}/{int(run_id)}", relative)
                    _validate_reference(by_name, member, digest, size)

            run_references = {
                "detection_runs": (
                    ("metadata.json", "metadata_sha256"),
                    ("normalized/result.json", "result_sha256"),
                ),
                "validation_runs": (
                    ("metadata.json", "metadata_sha256"),
                    ("normalized/result.json", "result_sha256"),
                    ("raw/manifest.json", "manifest_sha256"),
                ),
                "correlation_runs": (
                    ("metadata.json", "metadata_sha256"),
                    ("normalized/result.json", "result_sha256"),
                ),
                "intelligence_runs": (
                    ("normalized/result.json", "input_sha256"),
                    ("raw/advice.json", "result_sha256"),
                    ("metadata.json", "metadata_sha256"),
                ),
                "report_runs": (
                    ("normalized/result.json", "snapshot_sha256"),
                    ("raw/technical.md", "technical_sha256"),
                    ("raw/executive.md", "executive_sha256"),
                    ("raw/evidence-manifest.json", "manifest_sha256"),
                    ("raw/dockpack.zip", "dockpack_sha256"),
                ),
            }
            for table, references in run_references.items():
                if table not in tables:
                    continue
                columns = ", ".join(["evidence_path", *(column for _, column in references)])
                for row in connection.execute(f"SELECT {columns} FROM {table}"):
                    base = row[0]
                    for index, (relative, _) in enumerate(references, start=1):
                        digest = row[index]
                        if digest is None:
                            continue
                        reference_count += 1
                        if reference_count > MAX_DATABASE_EVIDENCE_REFERENCES:
                            raise BackupError("SQLite contains too many evidence references")
                        member = _evidence_member(base, relative)
                        _validate_reference(by_name, member, digest)
                    if table == "validation_runs" and row[3] is not None:
                        manifest_member = _evidence_member(base, "raw/manifest.json")
                        manifest_record = by_name.get(manifest_member)
                        if (
                            manifest_record is None
                            or int(manifest_record["size_bytes"]) > MAX_MANIFEST_BYTES
                        ):
                            raise BackupError(
                                "Validation evidence manifest exceeds the fixed size limit"
                            )
                        _validate_validation_manifest(
                            by_name,
                            str(base),
                            evidence_reader(manifest_member),
                        )
    except BackupError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as error:
        raise BackupError("SQLite evidence references could not be validated") from error


def _extract_member(archive: zipfile.ZipFile, name: str, destination: Path) -> str:
    digest = sha256()
    size = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(name) as source, destination.open("xb") as target:
        destination.chmod(0o640)
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
            target.write(chunk)
    record_digest = digest.hexdigest()
    info = archive.getinfo(name)
    if size != info.file_size:
        raise BackupError(f"Backup member changed while extracting: {name}")
    return record_digest


def _private_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _preflight_zip_directory(stream, archive_size: int) -> None:
    tail_size = min(archive_size, 22 + 65_535)
    stream.seek(archive_size - tail_size)
    tail = stream.read(tail_size)
    search_end = len(tail)
    eocd_index = -1
    while search_end:
        candidate = tail.rfind(b"PK\x05\x06", 0, search_end)
        if candidate < 0:
            break
        if candidate + 22 <= len(tail):
            comment_size = struct.unpack_from("<H", tail, candidate + 20)[0]
            if candidate + 22 + comment_size == len(tail):
                eocd_index = candidate
                break
        search_end = candidate
    if eocd_index < 0:
        raise BackupError("Backup ZIP end record is missing")
    eocd = struct.unpack_from("<4s4H2LH", tail, eocd_index)
    _, disk, directory_disk, disk_entries, total_entries, directory_size, directory_at, _ = eocd
    if disk or directory_disk or disk_entries != total_entries:
        raise BackupError("Multi-disk backup archives are unsupported")
    eocd_at = archive_size - tail_size + eocd_index
    if total_entries == 0xFFFF or directory_size == 0xFFFFFFFF or directory_at == 0xFFFFFFFF:
        if eocd_at < 20:
            raise BackupError("Backup ZIP64 locator is missing")
        stream.seek(eocd_at - 20)
        locator = stream.read(20)
        if len(locator) != 20:
            raise BackupError("Backup ZIP64 locator is truncated")
        signature, zip64_disk, zip64_at, disks = struct.unpack("<4sLQL", locator)
        if signature != b"PK\x06\x07" or zip64_disk != 0 or disks != 1:
            raise BackupError("Backup ZIP64 locator is unsupported")
        stream.seek(zip64_at)
        zip64 = stream.read(56)
        if len(zip64) != 56:
            raise BackupError("Backup ZIP64 end record is truncated")
        unpacked = struct.unpack("<4sQ2H2L4Q", zip64)
        if unpacked[0] != b"PK\x06\x06" or unpacked[1] < 44:
            raise BackupError("Backup ZIP64 end record is invalid")
        (
            _,
            _,
            _,
            _,
            disk,
            directory_disk,
            disk_entries,
            total_entries,
            directory_size,
            directory_at,
        ) = unpacked
        if disk or directory_disk or disk_entries != total_entries:
            raise BackupError("Multi-disk backup archives are unsupported")
    if total_entries > MAX_ARCHIVE_ENTRIES + 1:
        raise BackupError("Backup archive contains too many entries")
    if directory_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise BackupError("Backup central directory exceeds the fixed size limit")
    if directory_at + directory_size > eocd_at:
        raise BackupError("Backup central directory bounds are invalid")
    stream.seek(0)


@contextmanager
def _open_archive(path: Path) -> Iterator[zipfile.ZipFile]:
    if _is_link(path):
        raise BackupError("Backup must be a regular, non-link file")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            current = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_size > MAX_ARCHIVE_BYTES
            ):
                raise BackupError("Backup is not a bounded regular file")
            _preflight_zip_directory(stream, opened.st_size)
            with zipfile.ZipFile(stream, "r") as archive:
                yield archive
    except BackupError:
        raise
    except (OSError, zipfile.BadZipFile) as error:
        raise BackupError("Backup is not a readable ZIP archive") from error


@contextmanager
def _materialized_archive(path: Path) -> Iterator[Path]:
    if str(path) != "-":
        yield path
        return
    source = getattr(sys.stdin, "buffer", None)
    if source is None:
        raise BackupError("Standard input is unavailable for the backup archive")
    try:
        with tempfile.TemporaryDirectory(prefix="reddock-archive-") as temporary:
            destination = Path(temporary) / "stdin.rdbackup"
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            total = 0
            with os.fdopen(descriptor, "wb") as stream:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise BackupError("Standard-input backup exceeds the archive size limit")
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            yield destination
    except BackupError:
        raise
    except OSError as error:
        raise BackupError("Standard-input backup could not be staged privately") from error


def _write_source(
    archive: zipfile.ZipFile,
    name: str,
    source_path: Path,
    remaining_bytes: int,
) -> dict[str, object]:
    if _is_link(source_path):
        raise BackupError("A backup source became a link during creation")
    digest = sha256()
    size = 0
    with source_path.open("rb") as source:
        opened = os.fstat(source.fileno())
        current = source_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise BackupError("A backup source changed identity during creation")
        if opened.st_size > remaining_bytes:
            raise BackupError("Backup exceeds the fixed uncompressed size limit")
        with archive.open(_private_zip_info(name), "w", force_zip64=True) as target:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > remaining_bytes:
                    raise BackupError("Backup exceeds the fixed uncompressed size limit")
                digest.update(chunk)
                target.write(chunk)
        finished = os.fstat(source.fileno())
        if (opened.st_size, opened.st_mtime_ns) != (finished.st_size, finished.st_mtime_ns):
            raise BackupError("A backup source changed while it was being archived")
    return {"path": name, "sha256": digest.hexdigest(), "size_bytes": size}


def _fsync_file(path: Path) -> None:
    # Windows requires a writable descriptor for fsync; POSIX accepts this for
    # the private files and staged evidence this helper is called on.
    with path.open("rb+") as stream:
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    if os.name != "posix":
        return
    for current, directories, files in os.walk(root, topdown=False):
        current_path = Path(current)
        for name in files:
            _fsync_file(current_path / name)
        for name in directories:
            _fsync_directory(current_path / name)
        _fsync_directory(current_path)


def _verify_backup_file(path: Path) -> dict[str, object]:
    if _is_link(path):
        raise BackupError("Backup must be a regular, non-link file")
    path = path.resolve()
    if not path.is_file():
        raise BackupError("Backup must be a regular, non-link file")
    with _open_archive(path) as archive:
        manifest, records = _verify_open_archive(archive)
        database_record = next(
            record for record in records if record["path"] == DATABASE_MEMBER
        )
        try:
            with tempfile.TemporaryDirectory(prefix="reddock-verify-") as temporary:
                database = Path(temporary) / "reddock.db"
                extracted_digest = _extract_member(archive, DATABASE_MEMBER, database)
                if extracted_digest != database_record["sha256"]:
                    raise BackupError("SQLite database changed while verifying the backup")
                _validate_database_evidence(
                    database,
                    records,
                    manifest["database"]["schema_revision"],
                    archive.read,
                )
        except OSError as error:
            raise BackupError("Temporary SQLite verification could not be completed") from error
    return manifest


def verify_backup(path: Path) -> dict[str, object]:
    with _materialized_archive(path) as materialized:
        return _verify_backup_file(materialized)


def create_backup(
    data_dir: Path,
    output: Path,
    *,
    confirm_offline: bool = False,
    confirm_overwrite: bool = False,
) -> str:
    if not confirm_offline:
        raise BackupError("Backup requires --confirm-offline after RedDock has been stopped")
    if _is_link(data_dir):
        raise BackupError("Data directory must be a regular, non-link directory")
    data_dir = data_dir.resolve()
    if not data_dir.is_dir():
        raise BackupError("Data directory must be a regular, non-link directory")
    if _is_link(output) or (_path_present(output) and not confirm_overwrite):
        raise BackupError(
            "Backup output already exists or is a link; choose a new name or confirm overwrite"
        )
    if _path_present(output) and not output.is_file():
        raise BackupError("Backup output must be a regular file")
    output = output.resolve()
    if output.is_relative_to(data_dir):
        raise BackupError("Backup output must be outside the RedDock data directory")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise BackupError("Backup output directory could not be created") from error
    if _is_link(output.parent) or not output.parent.is_dir():
        raise BackupError("Backup output parent must be a regular, non-link directory")

    database = data_dir / "reddock.db"
    if database.is_file() and database.stat(follow_symlinks=False).st_size > MAX_DATABASE_BYTES:
        raise BackupError("SQLite database exceeds the fixed database size limit")
    schema_revision = _check_database(database)
    try:
        sources = [(DATABASE_MEMBER, database), *_evidence_files(data_dir / "evidence")]
        if len(sources) > MAX_ARCHIVE_ENTRIES:
            raise BackupError("Backup contains too many files")

        temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
        try:
            descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w+b") as stream:
                with zipfile.ZipFile(
                    stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
                ) as archive:
                    records: list[dict[str, object]] = []
                    total = 0
                    for name, source in sources:
                        record = _write_source(
                            archive,
                            name,
                            source,
                            MAX_UNCOMPRESSED_BYTES - total,
                        )
                        total += int(record["size_bytes"])
                        records.append(record)
                    archive.writestr(
                        _private_zip_info(MANIFEST_NAME),
                        _manifest_bytes(records, schema_revision),
                    )
                stream.flush()
                os.fsync(stream.fileno())
            verify_backup(temporary)
            archive_digest = _hash_file(temporary)[1]
            if not confirm_overwrite and (_path_present(output) or _is_link(output)):
                raise BackupError("Backup output appeared during creation; refusing to replace it")
            os.replace(temporary, output)
            _fsync_file(output)
            _fsync_directory(output.parent)
        finally:
            if _path_present(temporary):
                temporary.unlink()
                _fsync_directory(temporary.parent)
        return archive_digest
    except BackupError:
        raise
    except OSError as error:
        raise BackupError("Backup filesystem operation failed") from error


def _extract_verified(archive_path: Path, staging: Path) -> None:
    with _open_archive(archive_path) as archive:
        manifest, records = _verify_open_archive(archive)
        for record in records:
            name = str(record["path"])
            destination = staging.joinpath(*PurePosixPath(name).parts)
            extracted_digest = _extract_member(archive, name, destination)
            if extracted_digest != record["sha256"]:
                raise BackupError(f"Backup member changed while restoring: {name}")
    _validate_database_evidence(
        staging / DATABASE_MEMBER,
        records,
        manifest["database"]["schema_revision"],
        lambda member: _read_bounded_file(
            staging.joinpath(*PurePosixPath(member).parts),
            MAX_MANIFEST_BYTES,
        ),
    )


def _write_restore_marker(path: Path, document: dict[str, object], *, create: bool) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True).encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        if create:
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                raise BackupError(
                    "An incomplete restore is already recorded; run the recover command"
                ) from error
        else:
            os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if _path_present(temporary):
            temporary.unlink()
            _fsync_directory(temporary.parent)


def _preflight_data_paths(data_dir: Path, *, require_database: bool) -> tuple[Path, Path]:
    database = data_dir / "reddock.db"
    evidence = data_dir / "evidence"
    if _is_link(database) or _is_link(evidence):
        raise BackupError("Existing database and evidence paths cannot be links")
    if require_database and not database.is_file():
        raise BackupError("SQLite database must be a regular file")
    if database.exists() and not database.is_file():
        raise BackupError("Existing database path is not a regular file")
    if evidence.exists() and not evidence.is_dir():
        raise BackupError("Existing evidence path is not a directory")
    for suffix in ("-journal", "-shm", "-wal"):
        if _path_present(Path(f"{database}{suffix}")):
            raise BackupError("SQLite sidecar exists; stop RedDock cleanly first")
    return database, evidence


def _preflight_recovery_path(path: Path, *, directory: bool) -> None:
    if not _path_present(path):
        return
    if _is_link(path):
        raise BackupError("Restore recovery paths cannot be links")
    if directory and not path.is_dir():
        raise BackupError("Restore recovery directory has an invalid type")
    if not directory and not path.is_file():
        raise BackupError("Restore recovery file has an invalid type")


def _preflight_database_sidecars(database: Path) -> None:
    for suffix in ("-journal", "-shm", "-wal"):
        if _path_present(Path(f"{database}{suffix}")):
            raise BackupError("SQLite sidecar exists; keep RedDock stopped during recovery")


def _replace_durable(source: Path, destination: Path) -> None:
    os.replace(source, destination)
    _fsync_directory(destination.parent)


def _unlink_durable(path: Path, *, missing_ok: bool = False) -> None:
    path.unlink(missing_ok=missing_ok)
    _fsync_directory(path.parent)


def _rmtree_durable(path: Path) -> None:
    shutil.rmtree(path)
    _fsync_directory(path.parent)


def _validate_live_data(data_dir: Path, *, require_evidence: bool = True) -> None:
    database, evidence = _preflight_data_paths(data_dir, require_database=True)
    if require_evidence and not evidence.is_dir():
        raise BackupError("Restored evidence directory must be present")
    revision = _check_database(database)
    sources = _evidence_files(evidence)
    records: list[dict[str, object]] = []
    total = database.stat(follow_symlinks=False).st_size
    if total > MAX_DATABASE_BYTES:
        raise BackupError("Restored SQLite database exceeds the fixed size limit")
    for name, source in sources:
        remaining = MAX_UNCOMPRESSED_BYTES - total
        source_size = source.stat(follow_symlinks=False).st_size
        if source_size > remaining:
            raise BackupError("Restored evidence exceeds the fixed size limit")
        size, digest = _hash_file(source, max_bytes=remaining)
        total += size
        records.append({"path": name, "size_bytes": size, "sha256": digest})
    _validate_database_evidence(
        database,
        records,
        revision,
        lambda member: _read_bounded_file(
            data_dir.joinpath(*PurePosixPath(member).parts),
            MAX_MANIFEST_BYTES,
        ),
    )


def _load_restore_marker(data_dir: Path) -> dict[str, object]:
    marker = data_dir / RESTORE_MARKER
    if _is_link(marker) or not marker.is_file():
        raise BackupError("Restore marker is not a regular, non-link file")
    try:
        with marker.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            current = marker.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_size > MAX_MANIFEST_BYTES
            ):
                raise BackupError("Restore marker is not a bounded regular file")
            payload = stream.read(MAX_MANIFEST_BYTES + 1)
        document = json.loads(payload.decode("utf-8"))
    except BackupError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BackupError("Restore marker is unreadable; keep RedDock stopped") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "token", "state", "had_database", "had_evidence"}
        or document.get("schema") != "reddock.restore/1"
        or document.get("state") not in {"prepared", "committed"}
        or not isinstance(document.get("token"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", str(document["token"]))
        or not isinstance(document.get("had_database"), bool)
        or not isinstance(document.get("had_evidence"), bool)
    ):
        raise BackupError("Restore marker is invalid; keep RedDock stopped")
    return document


def assert_no_incomplete_restore(data_dir: Path) -> None:
    """Fail startup while a restore marker requires operator recovery."""
    if _path_present(data_dir / RESTORE_MARKER):
        raise BackupError(
            "An interrupted SQLite restore requires offline recovery before RedDock can start"
        )


def recover_restore(
    data_dir: Path,
    *,
    confirm_offline: bool = False,
    confirm_rollback: bool = False,
    confirm_finalize: bool = False,
) -> bool:
    if not confirm_offline:
        raise BackupError("Recovery requires --confirm-offline after RedDock has been stopped")
    if confirm_rollback and confirm_finalize:
        raise BackupError("Recovery accepts only one state-specific confirmation")
    if _is_link(data_dir):
        raise BackupError("Data directory must be a regular, non-link directory")
    data_dir = data_dir.resolve()
    if not data_dir.is_dir():
        raise BackupError("Data directory must be a regular, non-link directory")
    marker_path = data_dir / RESTORE_MARKER
    if not _path_present(marker_path):
        return False
    document = _load_restore_marker(data_dir)
    if document["had_evidence"] and not document["had_database"]:
        raise BackupError("Restore marker describes evidence without a database")
    if document["state"] == "prepared" and not confirm_rollback:
        raise BackupError(
            "Interrupted restore is prepared; inspect the data, then rerun with "
            "--confirm-rollback to restore the previous database and evidence"
        )
    if document["state"] == "committed" and not confirm_finalize:
        raise BackupError(
            "Interrupted restore is committed; inspect the restored data, then rerun with "
            "--confirm-finalize to keep it and delete the previous rollback copies"
        )
    token = str(document["token"])
    staging = data_dir / f".restore-{token}"
    old_database = data_dir / f".reddock.db.rollback-{token}"
    old_evidence = data_dir / f".evidence.rollback-{token}"
    database = data_dir / "reddock.db"
    evidence = data_dir / "evidence"

    _preflight_data_paths(data_dir, require_database=False)
    _preflight_recovery_path(staging, directory=True)
    _preflight_recovery_path(old_database, directory=False)
    _preflight_recovery_path(old_evidence, directory=True)
    _preflight_recovery_path(staging / DATABASE_MEMBER, directory=False)
    _preflight_recovery_path(staging / "evidence", directory=True)
    _preflight_database_sidecars(old_database)
    _preflight_database_sidecars(staging / DATABASE_MEMBER)

    try:
        if document["state"] == "committed":
            # Neither rollback copy is discarded until the complete installed
            # database/evidence pair (including nested manifests) is sound.
            _validate_live_data(data_dir)
            if old_database.exists():
                _unlink_durable(old_database)
            if old_evidence.exists():
                _rmtree_durable(old_evidence)
        else:
            staged_database = staging / DATABASE_MEMBER
            staged_evidence = staging / "evidence"
            if old_evidence.exists():
                if evidence.exists():
                    _rmtree_durable(evidence)
                _replace_durable(old_evidence, evidence)
            elif (
                not document["had_evidence"]
                and not staged_evidence.exists()
                and evidence.exists()
            ):
                _rmtree_durable(evidence)
            if old_database.exists():
                if database.exists():
                    _unlink_durable(database)
                _replace_durable(old_database, database)
            elif (
                not document["had_database"]
                and not staged_database.exists()
                and database.exists()
            ):
                _unlink_durable(database)
            if document["had_database"]:
                _validate_live_data(
                    data_dir,
                    require_evidence=bool(document["had_evidence"]),
                )
        if staging.exists():
            _rmtree_durable(staging)
        _unlink_durable(marker_path)
    except OSError as error:
        raise BackupError(
            "Restore recovery was incomplete; keep RedDock stopped and preserve restore files"
        ) from error
    return True


def restore_backup(
    data_dir: Path,
    archive: Path,
    *,
    confirm_offline: bool = False,
    confirm_replace: bool,
) -> None:
    if not confirm_offline:
        raise BackupError("Restore requires --confirm-offline after RedDock has been stopped")
    if not confirm_replace:
        raise BackupError("Restore requires --confirm-replace")
    if str(archive) == "-":
        with _materialized_archive(archive) as materialized:
            restore_backup(
                data_dir,
                materialized,
                confirm_offline=True,
                confirm_replace=True,
            )
        return
    if _is_link(data_dir):
        raise BackupError("Data directory must be a regular, non-link directory")
    data_dir = data_dir.resolve()
    if not data_dir.is_dir():
        raise BackupError("Data directory must be a regular, non-link directory")
    if _path_present(data_dir / RESTORE_MARKER):
        raise BackupError("An incomplete restore is recorded; run recover before restoring")
    if _is_link(archive):
        raise BackupError("Backup must be a regular, non-link file")
    archive = archive.resolve()
    if archive.is_relative_to(data_dir):
        raise BackupError("Restore archive must be outside the RedDock data directory")
    if not archive.is_file():
        raise BackupError("Backup must be a regular, non-link file")

    database, evidence = _preflight_data_paths(data_dir, require_database=False)
    if evidence.exists() and not database.exists():
        raise BackupError("Restore target cannot contain evidence without its SQLite database")

    token = uuid.uuid4().hex
    staging = data_dir / f".restore-{token}"
    old_database = data_dir / f".reddock.db.rollback-{token}"
    old_evidence = data_dir / f".evidence.rollback-{token}"
    marker = data_dir / RESTORE_MARKER
    marker_document: dict[str, object] = {
        "schema": "reddock.restore/1",
        "token": token,
        "state": "prepared",
        "had_database": database.exists(),
        "had_evidence": evidence.exists(),
    }
    marker_created = False
    try:
        staging.mkdir()
        staging.chmod(0o700)
        _fsync_directory(data_dir)
        _write_restore_marker(marker, marker_document, create=True)
        marker_created = True
        _extract_verified(archive, staging)
        restored_database = staging / DATABASE_MEMBER
        restored_evidence = staging / "evidence"
        restored_evidence.mkdir(exist_ok=True)
        restored_database.chmod(0o640)
        for current, directories, files in os.walk(restored_evidence):
            current_path = Path(current)
            current_path.chmod(0o750)
            for directory in directories:
                (current_path / directory).chmod(0o750)
            for name in files:
                (current_path / name).chmod(0o640)
        _fsync_tree(staging)

        if database.exists():
            _replace_durable(database, old_database)
        if evidence.exists():
            _replace_durable(evidence, old_evidence)
        _replace_durable(restored_database, database)
        _replace_durable(restored_evidence, evidence)
        _validate_live_data(data_dir)
        marker_document["state"] = "committed"
        _write_restore_marker(marker, marker_document, create=False)
    except Exception as error:
        if marker_created:
            recovery_state = _load_restore_marker(data_dir)["state"]
            if recovery_state == "committed":
                raise BackupError(
                    "Restore reached committed state, but commit durability is uncertain; "
                    "keep RedDock stopped and run recover to inspect the required action"
                ) from error
            recover_restore(
                data_dir,
                confirm_offline=True,
                confirm_rollback=True,
            )
        elif staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
            _fsync_directory(data_dir)
        if isinstance(error, BackupError):
            raise
        if isinstance(error, OSError):
            raise BackupError(
                "Restore filesystem operation failed; original data was restored"
            ) from error
        raise

    try:
        if old_database.exists():
            _unlink_durable(old_database)
        if old_evidence.exists():
            _rmtree_durable(old_evidence)
        if staging.exists():
            _rmtree_durable(staging)
        _unlink_durable(marker)
    except OSError as error:
        raise BackupError(
            "Restore committed, but cleanup is incomplete; keep RedDock stopped and run recover"
        ) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create and verify a new backup")
    create.add_argument("--data-dir", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--confirm-offline", action="store_true")
    create.add_argument("--confirm-overwrite", action="store_true")
    verify = subparsers.add_parser("verify", help="verify a backup without restoring it")
    verify.add_argument(
        "--archive",
        type=Path,
        required=True,
        help="backup path, or - to read a bounded archive from standard input",
    )
    restore = subparsers.add_parser("restore", help="replace SQLite data from a backup")
    restore.add_argument("--data-dir", type=Path, required=True)
    restore.add_argument(
        "--archive",
        type=Path,
        required=True,
        help="backup path, or - to read a bounded archive from standard input",
    )
    restore.add_argument("--confirm-offline", action="store_true")
    restore.add_argument("--confirm-replace", action="store_true")
    recover = subparsers.add_parser("recover", help="recover an interrupted restore")
    recover.add_argument("--data-dir", type=Path, required=True)
    recover.add_argument("--confirm-offline", action="store_true")
    recovery_confirmation = recover.add_mutually_exclusive_group()
    recovery_confirmation.add_argument("--confirm-rollback", action="store_true")
    recovery_confirmation.add_argument("--confirm-finalize", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.command == "create":
            digest = create_backup(
                arguments.data_dir,
                arguments.output,
                confirm_offline=arguments.confirm_offline,
                confirm_overwrite=arguments.confirm_overwrite,
            )
            print(f"Created {arguments.output} (sha256:{digest})")
        elif arguments.command == "verify":
            manifest = verify_backup(arguments.archive)
            print(
                f"Verified {arguments.archive} ({len(manifest['files'])} files, "
                f"RedDock {manifest['application']['version']})"
            )
        elif arguments.command == "restore":
            restore_backup(
                arguments.data_dir,
                arguments.archive,
                confirm_offline=arguments.confirm_offline,
                confirm_replace=arguments.confirm_replace,
            )
            print(f"Restored {arguments.archive}")
        else:
            recovered = recover_restore(
                arguments.data_dir,
                confirm_offline=arguments.confirm_offline,
                confirm_rollback=arguments.confirm_rollback,
                confirm_finalize=arguments.confirm_finalize,
            )
            print("Recovered interrupted restore" if recovered else "No interrupted restore found")
    except BackupError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("error: maintenance filesystem operation failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
