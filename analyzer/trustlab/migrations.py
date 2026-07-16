"""Explicit, deterministic schema migrations."""

from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
from typing import Any

from .compatibility import (
    SchemaFamily,
    current_write_version,
    report_migration_path,
)
from .exceptions import UnsupportedSchemaVersionError
from .report_v2 import report_v2_from_v1_shape
from .report_v3 import (
    migrate_v2_source_reference,
    report_v3_from_v2_shape,
)
from .report_v4 import report_v4_from_v3_shape
from .report_v5 import report_v5_from_v4_shape
from .report_v6 import report_v6_from_v5_shape
from .validators import validate_report


def migrate_report_v1_to_v2(source: dict[str, Any]) -> dict[str, Any]:
    """Validate and migrate report v1 without modifying the source document."""

    if source.get("schema_version") != "1.0.0":
        raise UnsupportedSchemaVersionError(
            "report migration requires schema version 1.0.0"
        )
    validate_report(source)
    migrated = report_v2_from_v1_shape(source, preserve_legacy_source=True)
    validate_report(migrated)
    return migrated


def migrate_report_v2_to_v3(source: dict[str, Any]) -> dict[str, Any]:
    """Validate v2 and migrate it to the content-addressed v3 contract."""

    if source.get("schema_version") != "2.0.0":
        raise UnsupportedSchemaVersionError(
            "report migration requires schema version 2.0.0"
        )
    validate_report(source)
    reference, event_id, extension = migrate_v2_source_reference(source)
    migrated = report_v3_from_v2_shape(
        source,
        raw_artifacts=[reference],
        collection_event_id=event_id,
        source_schema_version="2.0.0",
        generator_name="trustlab-migration",
        add_v2_to_v3_migration=True,
        extra_extensions=extension,
    )
    validate_report(migrated)
    return migrated


def migrate_report_v3_to_v4(source: dict[str, Any]) -> dict[str, Any]:
    """Validate v3 and migrate it without inventing unavailable mount records."""

    if source.get("schema_version") != "3.0.0":
        raise UnsupportedSchemaVersionError(
            "report migration requires schema version 3.0.0"
        )
    validate_report(source)
    migrated = report_v4_from_v3_shape(
        source,
        add_v3_to_v4_migration=True,
    )
    validate_report(migrated)
    return migrated


def migrate_report_v4_to_v5(source: dict[str, Any]) -> dict[str, Any]:
    """Validate v4 and migrate without reconstructing discarded structure."""

    if source.get("schema_version") != "4.0.0":
        raise UnsupportedSchemaVersionError(
            "report migration requires schema version 4.0.0"
        )
    validate_report(source)
    migrated = report_v5_from_v4_shape(
        source,
        add_v4_to_v5_migration=True,
    )
    validate_report(migrated)
    return migrated


def migrate_report_v5_to_v6(source: dict[str, Any]) -> dict[str, Any]:
    """Validate v5 and migrate without reinterpreting conflated root facts."""

    if source.get("schema_version") != "5.0.0":
        raise UnsupportedSchemaVersionError(
            "report migration requires schema version 5.0.0"
        )
    validate_report(source)
    migrated = report_v6_from_v5_shape(
        source,
        add_v5_to_v6_migration=True,
    )
    validate_report(migrated)
    return migrated


def migrate_report_to_current(source: dict[str, Any]) -> dict[str, Any]:
    """Migrate any readable historical report through explicit major steps."""

    migrators = MappingProxyType(
        {
            "report-v1-to-v2": migrate_report_v1_to_v2,
            "report-v2-to-v3": migrate_report_v2_to_v3,
            "report-v3-to-v4": migrate_report_v3_to_v4,
            "report-v4-to-v5": migrate_report_v4_to_v5,
            "report-v5-to-v6": migrate_report_v5_to_v6,
        }
    )
    steps = report_migration_path(
        source.get("schema_version"),
        target_version=current_write_version(SchemaFamily.REPORT),
    )
    if not steps:
        validate_report(source)
        return deepcopy(source)
    migrated = source
    for step in steps:
        try:
            migrator = migrators[step.migration_id]
        except KeyError as exc:
            raise UnsupportedSchemaVersionError(
                "registered report migration has no implementation"
            ) from exc
        migrated = migrator(migrated)
    return migrated
