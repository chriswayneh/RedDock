from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.engine import Connection, Engine

from app.database import Base

BASELINE_REVISION = "0001_v080"

# Frozen v0.8.0 contract. A legacy database is stamped only after every released
# table and column is present. Extra tables and columns are permitted so an
# operator can restore a newer backup without the bootstrapper destroying data.
BASELINE_SCHEMA: dict[str, tuple[str, ...]] = {
    "dockyards": ("id", "name", "description", "status", "created_at", "updated_at"),
    "assets": (
        "id",
        "dockyard_id",
        "asset_type",
        "identity",
        "display_name",
        "ip_address",
        "hostname",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
    ),
    "correlation_runs": (
        "id",
        "dockyard_id",
        "status",
        "asset_count",
        "finding_count",
        "asset_relationship_count",
        "finding_correlation_count",
        "framework_mapping_count",
        "error",
        "evidence_path",
        "metadata_sha256",
        "result_sha256",
        "graph",
        "created_at",
        "started_at",
        "completed_at",
    ),
    "detection_runs": (
        "id",
        "dockyard_id",
        "status",
        "detectors",
        "enrichment",
        "asset_count",
        "service_count",
        "observation_count",
        "finding_count",
        "new_finding_count",
        "resolved_finding_count",
        "error",
        "evidence_path",
        "metadata_sha256",
        "result_sha256",
        "created_at",
        "started_at",
        "completed_at",
    ),
    "discovery_runs": (
        "id",
        "dockyard_id",
        "adapter",
        "adapter_version",
        "profile",
        "requested_target",
        "normalized_target",
        "status",
        "decision",
        "decision_reason",
        "error",
        "asset_count",
        "service_count",
        "observation_count",
        "evidence_path",
        "created_at",
        "started_at",
        "completed_at",
    ),
    "lab_authorizations": (
        "id",
        "dockyard_id",
        "capability",
        "status",
        "acknowledgement",
        "note",
        "created_at",
        "expires_at",
        "revoked_at",
    ),
    "report_runs": (
        "id",
        "dockyard_id",
        "status",
        "report_schema",
        "snapshot_sha256",
        "technical_sha256",
        "executive_sha256",
        "manifest_sha256",
        "dockpack_sha256",
        "dockpack_bytes",
        "evidence_path",
        "source_counts",
        "error",
        "created_at",
        "completed_at",
    ),
    "scope_entries": ("id", "dockyard_id", "rule", "kind", "value", "note", "created_at"),
    "evidence_records": (
        "id",
        "dockyard_id",
        "discovery_run_id",
        "kind",
        "relative_path",
        "media_type",
        "size_bytes",
        "sha256",
        "truncated",
        "created_at",
    ),
    "intelligence_runs": (
        "id",
        "dockyard_id",
        "correlation_run_id",
        "status",
        "provider",
        "model",
        "destination",
        "sends_data_external",
        "prompt_version",
        "approval_note",
        "input",
        "output",
        "input_sha256",
        "result_sha256",
        "metadata_sha256",
        "evidence_path",
        "error",
        "created_at",
        "approved_at",
        "started_at",
        "completed_at",
    ),
    "lab_audit_events": (
        "id",
        "dockyard_id",
        "capability",
        "action",
        "decision",
        "reason",
        "authorization_id",
        "discovery_run_id",
        "created_at",
    ),
    "services": (
        "id",
        "asset_id",
        "transport",
        "port",
        "state",
        "service_name",
        "product",
        "version",
        "first_seen",
        "last_seen",
    ),
    "findings": (
        "id",
        "dockyard_id",
        "fingerprint",
        "detector",
        "detector_version",
        "rule_id",
        "title",
        "description",
        "category",
        "severity",
        "confidence",
        "status",
        "status_note",
        "asset_id",
        "service_id",
        "remediation",
        "detail",
        "cve_references",
        "first_seen",
        "last_seen",
        "first_detection_run_id",
        "last_detection_run_id",
        "resolved_at",
        "created_at",
        "updated_at",
    ),
    "observations": (
        "id",
        "dockyard_id",
        "discovery_run_id",
        "asset_id",
        "service_id",
        "adapter",
        "observation_type",
        "summary",
        "detail",
        "confidence",
        "raw_reference",
        "observed_at",
        "created_at",
    ),
    "asset_relationships": (
        "id",
        "correlation_run_id",
        "dockyard_id",
        "source_asset_id",
        "target_asset_id",
        "relationship_type",
        "confidence",
        "basis",
        "observation_id",
        "discovery_run_id",
        "evidence_record_id",
        "evidence_sha256",
        "created_at",
    ),
    "finding_evidence": (
        "id",
        "finding_id",
        "observation_id",
        "detection_run_id",
        "discovery_run_id",
        "evidence_record_id",
        "summary",
        "created_at",
    ),
    "framework_mappings": (
        "id",
        "correlation_run_id",
        "dockyard_id",
        "finding_id",
        "framework",
        "external_id",
        "title",
        "basis",
        "mapping_version",
        "evidence_sha256",
        "created_at",
    ),
    "validation_runs": (
        "id",
        "dockyard_id",
        "finding_id",
        "validator",
        "validator_version",
        "target",
        "status",
        "decision",
        "decision_reason",
        "approval_note",
        "outcome",
        "confidence",
        "summary",
        "detail",
        "error",
        "evidence_path",
        "metadata_sha256",
        "result_sha256",
        "manifest_sha256",
        "created_at",
        "approved_at",
        "started_at",
        "completed_at",
    ),
    "finding_correlations": (
        "id",
        "correlation_run_id",
        "dockyard_id",
        "source_finding_id",
        "target_finding_id",
        "relationship_type",
        "confidence",
        "basis",
        "asset_relationship_id",
        "source_evidence_sha256",
        "target_evidence_sha256",
        "created_at",
    ),
}


def _config(connection: Connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).with_name("schema_migrations")))
    config.attributes["connection"] = connection
    return config


def _create_missing_baseline_tables(connection: Connection) -> None:
    for table in Base.metadata.sorted_tables:
        if table.name in BASELINE_SCHEMA:
            table.create(bind=connection, checkfirst=True)


def _validate_legacy_baseline(connection: Connection) -> None:
    inspector = inspect(connection)
    present = set(inspector.get_table_names())
    missing_tables = sorted(set(BASELINE_SCHEMA) - present)
    missing_columns: dict[str, list[str]] = {}
    for table, expected in BASELINE_SCHEMA.items():
        if table not in present:
            continue
        actual = {column["name"] for column in inspector.get_columns(table)}
        missing = sorted(set(expected) - actual)
        if missing:
            missing_columns[table] = missing
    if missing_tables or missing_columns:
        details = []
        if missing_tables:
            details.append(f"missing tables: {', '.join(missing_tables)}")
        if missing_columns:
            columns = "; ".join(
                f"{table} ({', '.join(names)})" for table, names in missing_columns.items()
            )
            details.append(f"missing columns: {columns}")
        raise RuntimeError(
            "Database does not match the released RedDock v0.8.0 schema; " + "; ".join(details)
        )


def upgrade_database(engine: Engine) -> None:
    """Bootstrap a released schema once, then apply every versioned migration."""
    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        config = _config(connection)

        if "alembic_version" not in tables:
            if tables:
                _create_missing_baseline_tables(connection)
                _validate_legacy_baseline(connection)
                command.stamp(config, BASELINE_REVISION)
            else:
                # Create the current model, stamp the released baseline, and run
                # every migration so data-seeding migrations are never skipped.
                Base.metadata.create_all(bind=connection)
                command.stamp(config, BASELINE_REVISION)

        command.upgrade(config, "head")
