"""Build report v5 documents with structured SELinux/process evidence."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from ._version import __version__
from .canonical_json import canonical_json_bytes
from .exceptions import SchemaValidationError
from .identity import finalize_report_identity
from .security_evidence import SELECTED_PROCESS_NAMES

REPORT_V4_VERSION = "4.0.0"
REPORT_V5_VERSION = "5.0.0"


def _unavailable_string(reason: str) -> dict[str, Any]:
    return {"status": "not_collected", "value": None, "reason": reason}


def _unavailable_boolean(reason: str) -> dict[str, Any]:
    return {"status": "not_collected", "value": None, "reason": reason}


def historical_selinux_model(source: dict[str, Any]) -> dict[str, Any]:
    """Carry exact v4 mode evidence without inventing missing source structure."""

    reason = "structured SELinux source evidence was unavailable in report v4"
    denials = source["selinux"]["denials_collected"]
    denial_status = deepcopy(denials)
    if denial_status["status"] == "observed" and denial_status["value"] is False:
        denial_status = _unavailable_boolean(
            "the historical report states that denials were not collected"
        )
    return {
        "source_observer": source["observer"]["observer_type"],
        "policy_mode": {
            **deepcopy(source["selinux"]["mode"]),
            "evidence_refs": [],
        },
        "current_context": {
            **_unavailable_string(reason),
            "evidence_refs": [],
        },
        "denial_collection": {
            "status": denial_status["status"],
            "reason": denial_status["reason"],
            "evidence_refs": [],
        },
        "limitations": [
            "complete_policy_not_inspected",
            "historical_structure_unavailable",
        ],
    }


def historical_process_model(source: dict[str, Any]) -> dict[str, Any]:
    """Refuse to reinterpret v4 substring-derived process booleans."""

    reason = "structured process evidence was unavailable in report v4"
    return {
        "source_observer": source["observer"]["observer_type"],
        "capture_status": "not_collected",
        "source_format": "unknown",
        "scope": "unknown",
        "completeness": "unknown",
        "evidence_refs": [],
        "selected_processes": [
            {
                "name": name,
                "visibility": _unavailable_boolean(reason),
                "context": _unavailable_string(reason),
                "evidence_refs": [],
            }
            for name in SELECTED_PROCESS_NAMES
        ],
        "limitations": [
            "historical_structure_unavailable",
            "observer_scoped_visibility",
        ],
    }


def report_v5_from_v4_shape(
    source: dict[str, Any],
    *,
    structured_selinux: dict[str, Any] | None = None,
    structured_processes: dict[str, Any] | None = None,
    add_v4_to_v5_migration: bool = False,
    migration_implementation_version: str | None = None,
) -> dict[str, Any]:
    """Upgrade v4 while binding structured security evidence into identity."""

    if (
        add_v4_to_v5_migration
        and "org.androidtrustlab.migration-v5" in source["extensions"]
    ):
        raise SchemaValidationError(
            "report migration source uses a reserved v5 extension key"
        )
    report = deepcopy(source)
    report["report_id"] = "atlrep-" + "0" * 32
    report["content_digest"] = "0" * 64
    report["schema_version"] = REPORT_V5_VERSION
    report["selinux"] = deepcopy(
        structured_selinux
        if structured_selinux is not None
        else historical_selinux_model(source)
    )
    report["process_state"] = deepcopy(
        structured_processes
        if structured_processes is not None
        else historical_process_model(source)
    )
    if add_v4_to_v5_migration:
        implementation_version = migration_implementation_version or __version__
        source_payload = canonical_json_bytes(source)
        report["provenance"]["source_schema_version"] = REPORT_V4_VERSION
        report["provenance"]["migration_history"].append(
            {
                "migration_id": "report-v4-to-v5",
                "source_schema_version": REPORT_V4_VERSION,
                "target_schema_version": REPORT_V5_VERSION,
                "implementation": {
                    "name": "trustlab-migration",
                    "version": implementation_version,
                },
            }
        )
        report["extensions"]["org.androidtrustlab.migration-v5"] = {
            "encoding": "atl-canonical-json-v1",
            "source_report_json": source_payload.decode("utf-8"),
            "source_sha256": hashlib.sha256(source_payload).hexdigest(),
        }
    return finalize_report_identity(report)
