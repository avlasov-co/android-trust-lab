"""Build report v6 documents with traceable root and Magisk evidence."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from ._version import __version__
from .canonical_json import canonical_json_bytes
from .exceptions import SchemaValidationError
from .identity import finalize_report_identity
from .privacy import (
    contains_sensitive_identifier,
    validate_portable_historical_report,
)

REPORT_V5_VERSION = "5.0.0"
REPORT_V6_VERSION = "6.0.0"


def _reject_sensitive_historical_source(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str) and contains_sensitive_identifier(current):
            raise SchemaValidationError(
                "report v5 source requires redaction before portable v6 migration"
            )


def _unavailable_boolean(reason: str) -> dict[str, Any]:
    return {
        "status": "not_collected",
        "value": None,
        "reason": reason,
        "evidence_refs": [],
    }


def _unavailable_string(reason: str) -> dict[str, Any]:
    return {
        "status": "not_collected",
        "value": None,
        "reason": reason,
        "evidence_refs": [],
    }


def historical_root_model(source: dict[str, Any]) -> dict[str, Any]:
    """Carry only the exact UID fact; refuse to reinterpret v5 root booleans."""

    reason = "independent root evidence was unavailable in report v5"
    uid = source["root_state"]["uid"]
    uid_is_root = _unavailable_boolean(reason)
    if uid["status"] == "observed":
        is_root = uid["value"] == "0"
        uid_is_root = {
            "status": "observed" if is_root else "observed_absent",
            "value": is_root,
            "reason": None if is_root else "the observer effective UID was not root",
            "evidence_refs": [],
        }
    return {
        "source_observer": source["observer"]["observer_type"],
        "observer_effective_uid_is_root": uid_is_root,
        "root_shell_available": _unavailable_boolean(reason),
        "su_binary_observed": _unavailable_boolean(reason),
        "su_invocation_tested": _unavailable_boolean(reason),
        "su_invocation_result": _unavailable_string(reason),
        "root_management_artifact_observed": _unavailable_boolean(reason),
        "limitations": ["historical_structure_unavailable"],
    }


def historical_magisk_model(source: dict[str, Any]) -> dict[str, Any]:
    """Refuse to reinterpret v5 substring-derived Magisk observations."""

    reason = "independent Magisk evidence was unavailable in report v5"
    return {
        "source_observer": source["observer"]["observer_type"],
        "binary_visibility": _unavailable_boolean(reason),
        "daemon_visibility": _unavailable_boolean(reason),
        "process_visibility": _unavailable_boolean(reason),
        "zygisk_visibility": _unavailable_boolean(reason),
        "version_name": _unavailable_string(reason),
        "version_code": _unavailable_string(reason),
        "module_context": _unavailable_string(reason),
        "command_status": {
            "status": "not_collected",
            "reason": reason,
            "evidence_refs": [],
        },
        "limitations": ["historical_structure_unavailable"],
    }


def historical_confidence_model() -> dict[str, Any]:
    """Represent missing v5 confidence factors without reusing its target heuristic."""

    return {
        "level": "unassessed",
        "source_quality": "historical_unstructured",
        "command_success": "unknown",
        "observer_capability": "unspecified",
        "corroborating_signal_count": 0,
        "target_limitations": ["historical_factors_unavailable"],
        "evidence_refs": [],
    }


def report_v6_from_v5_shape(
    source: dict[str, Any],
    *,
    structured_root: dict[str, Any] | None = None,
    structured_magisk: dict[str, Any] | None = None,
    confidence: dict[str, Any] | None = None,
    add_v5_to_v6_migration: bool = False,
    migration_implementation_version: str | None = None,
) -> dict[str, Any]:
    """Upgrade v5 while binding independent root/Magisk evidence into identity."""

    if (
        add_v5_to_v6_migration
        and "org.androidtrustlab.migration-v6" in source["extensions"]
    ):
        raise SchemaValidationError(
            "report migration source uses a reserved v6 extension key"
        )
    report = deepcopy(source)
    report["report_id"] = "atlrep-" + "0" * 32
    report["content_digest"] = "0" * 64
    report["schema_version"] = REPORT_V6_VERSION
    report["root_state"] = deepcopy(
        structured_root
        if structured_root is not None
        else historical_root_model(source)
    )
    report["magisk_state"] = deepcopy(
        structured_magisk
        if structured_magisk is not None
        else historical_magisk_model(source)
    )
    report["verified_boot"]["confidence"] = deepcopy(
        confidence if confidence is not None else historical_confidence_model()
    )
    if add_v5_to_v6_migration:
        validate_portable_historical_report(source)
        _reject_sensitive_historical_source(source)
        implementation_version = migration_implementation_version or __version__
        source_payload = canonical_json_bytes(source)
        report["provenance"]["source_schema_version"] = REPORT_V5_VERSION
        report["provenance"]["migration_history"].append(
            {
                "migration_id": "report-v5-to-v6",
                "source_schema_version": REPORT_V5_VERSION,
                "target_schema_version": REPORT_V6_VERSION,
                "implementation": {
                    "name": "trustlab-migration",
                    "version": implementation_version,
                },
            }
        )
        report["extensions"]["org.androidtrustlab.migration-v6"] = {
            "encoding": "atl-canonical-json-v1",
            "source_report_json": source_payload.decode("utf-8"),
            "source_sha256": hashlib.sha256(source_payload).hexdigest(),
        }
    return finalize_report_identity(report)
