"""Explicit, deterministic schema migrations."""

from __future__ import annotations

from typing import Any

from .exceptions import UnsupportedSchemaVersionError
from .report_v2 import report_v2_from_v1_shape
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
