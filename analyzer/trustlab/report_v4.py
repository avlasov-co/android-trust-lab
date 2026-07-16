"""Build report v4 documents with source-preserving Android mount evidence."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from ._version import __version__
from .canonical_json import canonical_json_bytes
from .exceptions import SchemaValidationError
from .identity import finalize_report_identity

REPORT_V3_VERSION = "3.0.0"
REPORT_V4_VERSION = "4.0.0"
_MODERN_MOUNT_FIELDS = (
    "observation",
    "records",
    "system_resolution",
    "dynamic_partitions",
    "apex_set",
)


def unavailable_mount_model() -> dict[str, Any]:
    """Represent a historical report whose raw mount records are unavailable."""

    reason = "structured mount records were not present in the historical report"
    return {
        "observation": {
            "scope": "unknown",
            "selected_source": None,
            "selected_format": None,
            "parse_status": "not_parsed",
            "selection_reason": reason,
            "attempts": [],
            "evidence_paths": [],
        },
        "records": [],
        "system_resolution": {
            "state": "unresolved",
            "system_root": None,
            "record_indices": [],
            "reason": reason,
        },
        "dynamic_partitions": {
            "state": "unknown",
            "record_indices": [],
            "sources": [],
        },
        "apex_set": {
            "packages": [],
            "record_indices": [],
            "mount_count": 0,
            "package_count": 0,
            "read_only_count": 0,
            "writable_count": 0,
            "unknown_access_count": 0,
            "overlay_count": 0,
            "bind_count": 0,
        },
        "integrity_context": {
            "assessment": "not_assessed",
            "reason": reason,
            "bind_mounts_detected": 0,
            "unknown_sensitive_mounts": [],
        },
    }


def _mount_model(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return unavailable_mount_model()
    model = {field: deepcopy(value[field]) for field in _MODERN_MOUNT_FIELDS}
    integrity = value["integrity_summary"]
    model["integrity_context"] = {
        "assessment": integrity["assessment"],
        "reason": integrity["reason"],
        "bind_mounts_detected": integrity["bind_mounts_detected"],
        "unknown_sensitive_mounts": deepcopy(integrity["unknown_sensitive_mounts"]),
    }
    return model


def report_v4_from_v3_shape(
    source: dict[str, Any],
    *,
    modern_mounts: dict[str, Any] | None = None,
    add_v3_to_v4_migration: bool = False,
    migration_implementation_version: str | None = None,
) -> dict[str, Any]:
    """Upgrade v3 evidence and bind the richer mount model into report identity."""

    if (
        add_v3_to_v4_migration
        and "org.androidtrustlab.migration-v4" in source["extensions"]
    ):
        raise SchemaValidationError(
            "report migration source uses a reserved v4 extension key"
        )
    report = deepcopy(source)
    report["report_id"] = "atlrep-" + "0" * 32
    report["content_digest"] = "0" * 64
    report["schema_version"] = REPORT_V4_VERSION
    report["mounts"].update(_mount_model(modern_mounts))
    if add_v3_to_v4_migration:
        implementation_version = migration_implementation_version or __version__
        source_payload = canonical_json_bytes(source)
        report["provenance"]["source_schema_version"] = REPORT_V3_VERSION
        report["provenance"]["migration_history"].append(
            {
                "migration_id": "report-v3-to-v4",
                "source_schema_version": REPORT_V3_VERSION,
                "target_schema_version": REPORT_V4_VERSION,
                "implementation": {
                    "name": "trustlab-migration",
                    "version": implementation_version,
                },
            }
        )
        report["extensions"]["org.androidtrustlab.migration-v4"] = {
            "encoding": "atl-canonical-json-v1",
            "source_report_json": source_payload.decode("utf-8"),
            "source_sha256": hashlib.sha256(source_payload).hexdigest(),
        }
    return finalize_report_identity(report)
