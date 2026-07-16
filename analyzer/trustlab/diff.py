"""Diff normalized Android Trust Lab reports."""

from __future__ import annotations

from typing import Any

from .canonical_json import framed_content_digest
from .compatibility import SchemaFamily, current_write_version
from .migration_codec import encode_legacy_report, legacy_report_digest
from .migrations import migrate_report_to_current
from .trust_dimensions import severity_for_dimension
from .validators import validate_report

# Default dimensions must represent actual measured trust-state fields.
# App-visible/root-visible dimensions are intentionally not included here until
# the compared reports contain real app-probe/root-probe payloads. Mapping those
# to observer_type creates fake signal when only the observer changed.
DIMENSION_PATHS = {
    "bootloader_lock_state": ["verified_boot", "flash_locked"],
    "verified_boot_state": ["verified_boot", "verified_boot_state"],
    "vbmeta_state": ["verified_boot", "vbmeta_device_state"],
    "verity_mode": ["verified_boot", "verity_mode"],
    "selinux_mode": ["selinux", "mode"],
    "mount_integrity": ["mounts", "integrity_summary"],
    "system_mount_resolution": ["mounts", "system_resolution"],
    "dynamic_partition_state": ["mounts", "dynamic_partitions"],
    "apex_mount_set": ["mounts", "apex_set"],
    "root_presence": ["root_state", "su_present"],
    "magisk_presence": ["magisk_state", "magisk_binary_present"],
    "property_consistency": ["properties", "security"],
    "emulator_state": ["emulator_state", "is_emulator"],
    "observer_privilege": ["observer", "privilege_level"],
}


def _comparison_value(value: Any) -> Any:
    if isinstance(value, dict) and {"status", "value", "reason"} <= value.keys():
        return {"status": value["status"], "value": value["value"]}
    if isinstance(value, dict):
        return {key: _comparison_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_comparison_value(item) for item in value]
    return value


def get_path(obj: dict[str, Any], path: list[str]) -> Any:
    current: Any = obj
    for part in path:
        if not isinstance(current, dict):
            return "unknown"
        current = current.get(part, "unknown")
    return _comparison_value(current)


def _report_for_diff(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    original_id = report.get("report_id", "unknown")
    original_version = str(report.get("schema_version", "unknown"))
    validate_report(report)
    common = migrate_report_to_current(report)
    applied_count = {
        "1.0.0": 3,
        "2.0.0": 2,
        "3.0.0": 1,
        "4.0.0": 0,
    }.get(original_version, 0)
    migrations = (
        common["provenance"]["migration_history"][-applied_count:]
        if applied_count
        else []
    )
    common_identity = {
        "report_id": common["report_id"],
        "content_digest": common["content_digest"],
        "schema_version": common["schema_version"],
    }
    return common, {
        "original_report_id": original_id,
        "original_schema_version": original_version,
        "original_content_digest": report.get("content_digest")
        if original_version in {"3.0.0", "4.0.0"}
        else None,
        "original_document_digest": legacy_report_digest(encode_legacy_report(report)),
        "common_report": common_identity,
        "applied_migrations": migrations,
    }


def interpretation(dimension: str) -> str:
    messages = {
        "bootloader_lock_state": "Bootloader lock evidence changed. On virtual targets this is property evidence only, not hardware-backed proof.",
        "root_presence": "Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim.",
        "magisk_presence": "Magisk-related visibility changed between reports. The project records visibility and does not hide or modify it.",
        "mount_integrity": "Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion.",
        "system_mount_resolution": "The resolved Android system root changed. Review the referenced mount records and source quality.",
        "dynamic_partition_state": "Dynamic-partition evidence changed. This records layout evidence, not an integrity verdict.",
        "apex_mount_set": "The observed APEX package mount set changed. Review capture completeness and package mount records.",
        "selinux_mode": "SELinux mode changed. This affects runtime MAC boundary interpretation.",
        "verified_boot_state": "Verified boot property evidence changed. Emulator evidence remains limited for hardware-backed conclusions.",
        "vbmeta_state": "vbmeta device-state evidence changed. Interpret according to target class and observer.",
        "verity_mode": "dm-verity-related property evidence changed.",
        "property_consistency": "Security-relevant property group changed. This does not imply bypass by itself.",
        "observer_privilege": "Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation.",
    }
    return messages.get(dimension, "Trust-state dimension changed between reports.")


def make_diff(base: dict[str, Any], compare: dict[str, Any]) -> dict[str, Any]:
    base, base_provenance = _report_for_diff(base)
    compare, compare_provenance = _report_for_diff(compare)
    common_version = base.get("schema_version")
    if compare.get("schema_version") != common_version:
        raise ValueError("report migration did not produce one common schema version")
    provenance = {
        "common_report_schema_version": common_version,
        "base": base_provenance,
        "compare": compare_provenance,
    }
    changed = []
    unchanged = []
    confidence_changes = []

    for dimension, path in DIMENSION_PATHS.items():
        before = get_path(base, path)
        after = get_path(compare, path)
        if before != after:
            changed.append(
                {
                    "dimension": dimension,
                    "before": before,
                    "after": after,
                    "severity": severity_for_dimension(dimension),
                    "interpretation": interpretation(dimension),
                    "evidence_paths": [".".join(path)],
                }
            )
        else:
            unchanged.append(dimension)

    base_conf = get_path(base, ["verified_boot", "confidence"])
    compare_conf = get_path(compare, ["verified_boot", "confidence"])
    if base_conf != compare_conf:
        confidence_changes.append(
            {
                "path": "verified_boot.confidence",
                "before": base_conf,
                "after": compare_conf,
            }
        )

    summary = (
        f"{len(changed)} dimensions changed, {len(unchanged)} dimensions unchanged."
    )
    schema_version = current_write_version(SchemaFamily.DIFF)
    result = {
        "schema_version": schema_version,
        "base_report": {
            "report_id": base["report_id"],
            "content_digest": base["content_digest"],
            "schema_version": base["schema_version"],
        },
        "compare_report": {
            "report_id": compare["report_id"],
            "content_digest": compare["content_digest"],
            "schema_version": compare["schema_version"],
        },
        "changed_dimensions": changed,
        "unchanged_dimensions": unchanged,
        "new_signals": [],
        "missing_signals": [],
        "confidence_changes": confidence_changes,
        "summary": summary,
        "provenance": provenance,
    }
    content_digest = framed_content_digest(
        family="diff",
        schema_version=schema_version,
        value=result,
    )
    return {
        "diff_id": f"atldiff-{content_digest[:32]}",
        "content_digest": content_digest,
        **result,
    }
