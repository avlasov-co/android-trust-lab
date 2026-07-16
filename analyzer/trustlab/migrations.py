"""Explicit, deterministic schema migrations."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .exceptions import UnsupportedSchemaVersionError
from .report_v2 import report_v2_from_v1_shape
from .report_v3 import (
    migrate_v2_source_reference,
    report_v3_from_v2_shape,
)
from .report_v4 import report_v4_from_v3_shape
from .report_v5 import report_v5_from_v4_shape
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


def migrate_report_to_current(source: dict[str, Any]) -> dict[str, Any]:
    """Migrate any readable historical report through explicit major steps."""

    version = source.get("schema_version")
    if version == "1.0.0":
        return migrate_report_v4_to_v5(
            migrate_report_v3_to_v4(
                migrate_report_v2_to_v3(migrate_report_v1_to_v2(source))
            )
        )
    if version == "2.0.0":
        return migrate_report_v4_to_v5(
            migrate_report_v3_to_v4(migrate_report_v2_to_v3(source))
        )
    if version == "3.0.0":
        return migrate_report_v4_to_v5(migrate_report_v3_to_v4(source))
    if version == "4.0.0":
        return migrate_report_v4_to_v5(source)
    if version == "5.0.0":
        validate_report(source)
        return deepcopy(source)
    raise UnsupportedSchemaVersionError("unsupported report schema version")
