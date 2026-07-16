"""Diff normalized Android Trust Lab reports."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .assessment import confidence_assessment, direction_assessment
from .canonical_json import framed_content_digest
from .comparison import classify_comparison
from .compatibility import (
    SchemaFamily,
    current_write_version,
    prepare_report_for_comparison,
)
from .transitions import (
    classify_status_transition,
    confidence_impact,
    evidence_is_available,
    evidence_status,
    signal_direction,
    transition_interpretation,
)
from .trust_dimensions import materiality_for_dimension

# Default dimensions must represent actual measured trust-state fields.
# App-visible/root-visible dimensions are intentionally not included here until
# the compared reports contain real app-probe/root-probe payloads. Mapping those
# to observer_type creates fake signal when only the observer changed.
DIMENSION_PATHS = {
    "bootloader_lock_state": ["verified_boot", "flash_locked"],
    "verified_boot_state": ["verified_boot", "verified_boot_state"],
    "vbmeta_state": ["verified_boot", "vbmeta_device_state"],
    "verity_mode": ["verified_boot", "verity_mode"],
    "selinux_mode": ["selinux", "policy_mode"],
    "selinux_current_context": ["selinux", "current_context"],
    "selinux_denial_collection": ["selinux", "denial_collection"],
    "selected_process_visibility": ["process_state", "selected_processes"],
    "mount_integrity": ["mounts", "integrity_summary"],
    "system_mount_resolution": ["mounts", "system_resolution"],
    "dynamic_partition_state": ["mounts", "dynamic_partitions"],
    "apex_mount_set": ["mounts", "apex_set"],
    "root_shell_availability": ["root_state", "root_shell_available"],
    "su_binary_visibility": ["root_state", "su_binary_observed"],
    "su_invocation_tested": ["root_state", "su_invocation_tested"],
    "su_invocation_result": ["root_state", "su_invocation_result"],
    "root_management_artifact": [
        "root_state",
        "root_management_artifact_observed",
    ],
    "magisk_binary_visibility": ["magisk_state", "binary_visibility"],
    "magisk_daemon_visibility": ["magisk_state", "daemon_visibility"],
    "magisk_process_visibility": ["magisk_state", "process_visibility"],
    "zygisk_visibility": ["magisk_state", "zygisk_visibility"],
    "magisk_version_name": ["magisk_state", "version_name"],
    "magisk_version_code": ["magisk_state", "version_code"],
    "magisk_module_context": ["magisk_state", "module_context"],
    "magisk_command_status": ["magisk_state", "command_status"],
    "property_consistency": ["properties", "security"],
    "emulator_state": ["emulator_state", "is_emulator"],
}

VERIFIED_BOOT_DIMENSIONS = frozenset(
    {
        "bootloader_lock_state",
        "verified_boot_state",
        "vbmeta_state",
        "verity_mode",
    }
)


def _comparison_value(value: Any) -> Any:
    if isinstance(value, dict) and {"status", "value", "reason"} <= value.keys():
        return {"status": value["status"], "value": value["value"]}
    if (
        isinstance(value, dict)
        and {"status", "reason", "evidence_refs"} <= value.keys()
    ):
        return {"status": value["status"]}
    if isinstance(value, dict):
        return {
            key: _comparison_value(item)
            for key, item in value.items()
            if key != "evidence_refs"
        }
    if isinstance(value, list):
        return [_comparison_value(item) for item in value]
    return value


def get_raw_path(obj: dict[str, Any], path: list[str]) -> Any:
    current: Any = obj
    for part in path:
        if not isinstance(current, dict):
            return "unknown"
        current = current.get(part, "unknown")
    return current


def get_path(obj: dict[str, Any], path: list[str]) -> Any:
    return _comparison_value(get_raw_path(obj, path))


def _source_evidence(value: Any) -> list[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        evidence_refs = value.get("evidence_refs")
        if isinstance(evidence_refs, list):
            refs.update(ref for ref in evidence_refs if isinstance(ref, str))
        for nested in value.values():
            refs.update(_source_evidence(nested))
    elif isinstance(value, list):
        for nested in value:
            refs.update(_source_evidence(nested))
    return sorted(refs)


def _observed_value(value: Any, status: str) -> Any:
    if not evidence_is_available(status):
        return None
    if isinstance(value, dict) and value.get("status") == status:
        return _comparison_value(value.get("value"))
    return _comparison_value(value)


def _transition(
    before_status: str,
    after_status: str,
    *,
    comparison_axis: str,
) -> dict[str, str]:
    return {
        "before_status": before_status,
        "after_status": after_status,
        "classification": classify_status_transition(
            before_status,
            after_status,
            comparison_axis=comparison_axis,
        ),
        "confidence_impact": confidence_impact(before_status, after_status),
    }


def _signal_entry(
    dimension: str,
    before_raw: Any,
    after_raw: Any,
    transition: dict[str, str],
    assessment: dict[str, Any],
    evidence_path: str,
) -> dict[str, Any]:
    before_status = transition["before_status"]
    after_status = transition["after_status"]
    return {
        "dimension": dimension,
        **transition,
        "observed_values": {
            "before": _observed_value(before_raw, before_status),
            "after": _observed_value(after_raw, after_status),
        },
        "source_evidence": {
            "before": _source_evidence(before_raw),
            "after": _source_evidence(after_raw),
        },
        "interpretation": transition_interpretation(
            before_status,
            after_status,
            transition["classification"],
        ),
        "materiality": assessment["materiality"],
        "direction": assessment["direction"],
        "confidence": deepcopy(assessment["confidence"]),
        "rationale": list(assessment["rationale"]),
        "evidence_paths": [evidence_path],
    }


def _field_confidence(report: dict[str, Any], dimension: str) -> str:
    if dimension not in VERIFIED_BOOT_DIMENSIONS:
        return "not_available"
    confidence = report.get("verified_boot", {}).get("confidence", {})
    level = confidence.get("level") if isinstance(confidence, dict) else None
    return (
        str(level) if level in {"high", "medium", "low", "unassessed"} else "unassessed"
    )


def _corroborating_evidence_count(
    base: dict[str, Any],
    compare: dict[str, Any],
    dimension: str,
    before_raw: Any,
    after_raw: Any,
) -> int:
    count = len(set(_source_evidence(before_raw)) | set(_source_evidence(after_raw)))
    if dimension not in VERIFIED_BOOT_DIMENSIONS:
        return count
    for report in (base, compare):
        confidence = report.get("verified_boot", {}).get("confidence", {})
        if isinstance(confidence, dict):
            corroborating = confidence.get("corroborating_signal_count")
            if isinstance(corroborating, int) and not isinstance(corroborating, bool):
                count = max(count, corroborating)
    return count


def _dimension_assessment(
    dimension: str,
    before: Any,
    after: Any,
    before_raw: Any,
    after_raw: Any,
    transition: dict[str, str],
    *,
    base: dict[str, Any],
    compare: dict[str, Any],
    compatibility: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    direction, direction_rationale = direction_assessment(
        dimension,
        before,
        after,
        transition_class=transition["classification"],
    )
    migration_count = sum(
        len(compatibility["migrations"][side]) for side in ("base", "compare")
    )
    confidence = confidence_assessment(
        before_status=transition["before_status"],
        after_status=transition["after_status"],
        before_field_confidence=_field_confidence(base, dimension),
        after_field_confidence=_field_confidence(compare, dimension),
        corroborating_evidence_count=_corroborating_evidence_count(
            base, compare, dimension, before_raw, after_raw
        ),
        migration_count=migration_count,
        comparability=comparison["comparability"],
        warning_count=len(comparison["warnings"]),
    )
    return {
        "materiality": materiality_for_dimension(dimension),
        "direction": direction,
        "confidence": confidence,
        "rationale": [
            "materiality_from_dimension_policy",
            direction_rationale,
            "confidence_from_explicit_factors",
        ],
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
        "selinux_current_context": "Observer SELinux context visibility changed. This is scoped evidence, not complete policy inspection.",
        "selinux_denial_collection": "SELinux denial collection status changed; compare collection scope before interpreting absence.",
        "selected_process_visibility": "Selected process visibility or sanitized contexts changed. Inconclusive scoped evidence is distinct from observed absence.",
        "verified_boot_state": "Verified boot property evidence changed. Emulator evidence remains limited for hardware-backed conclusions.",
        "vbmeta_state": "vbmeta device-state evidence changed. Interpret according to target class and observer.",
        "verity_mode": "dm-verity-related property evidence changed.",
        "property_consistency": "Security-relevant property group changed. This does not imply bypass by itself.",
        "observer_privilege": "Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation.",
    }
    return messages.get(dimension, "Trust-state dimension changed between reports.")


def make_diff(
    base: dict[str, Any],
    compare: dict[str, Any],
    *,
    allow_mixed: bool = False,
) -> dict[str, Any]:
    base, base_provenance, base_compatibility = prepare_report_for_comparison(
        base, side="base"
    )
    compare, compare_provenance, compare_compatibility = prepare_report_for_comparison(
        compare, side="compare"
    )
    common_version = base.get("schema_version")
    if compare.get("schema_version") != common_version:
        raise ValueError("report migration did not produce one common schema version")
    comparison = classify_comparison(base, compare, allow_mixed=allow_mixed)
    provenance = {
        "common_report_schema_version": common_version,
        "base": base_provenance,
        "compare": compare_provenance,
    }
    compatibility = {
        "input_schema_versions": {
            "base": base_compatibility["schema_version"],
            "compare": compare_compatibility["schema_version"],
        },
        "migrations": {
            "base": base_compatibility["migrations"],
            "compare": compare_compatibility["migrations"],
        },
        "warnings": [
            *base_compatibility["warnings"],
            *compare_compatibility["warnings"],
        ],
        "canonical_comparison_schema_version": common_version,
        "migration_mode": "temporary_in_memory",
    }
    changed = []
    unchanged = []
    new_signals: list[dict[str, Any]] = []
    missing_signals: list[dict[str, Any]] = []
    confidence_changes = []

    for dimension, path in DIMENSION_PATHS.items():
        before_raw = get_raw_path(base, path)
        after_raw = get_raw_path(compare, path)
        before = _comparison_value(before_raw)
        after = _comparison_value(after_raw)
        if before != after:
            transition = _transition(
                evidence_status(before_raw),
                evidence_status(after_raw),
                comparison_axis=comparison["axis"],
            )
            assessment = _dimension_assessment(
                dimension,
                before,
                after,
                before_raw,
                after_raw,
                transition,
                base=base,
                compare=compare,
                compatibility=compatibility,
                comparison=comparison,
            )
            changed.append(
                {
                    "dimension": dimension,
                    "before": before,
                    "after": after,
                    "transition": transition,
                    **assessment,
                    "interpretation": interpretation(dimension),
                    "evidence_paths": [".".join(path)],
                }
            )
            direction = signal_direction(
                transition["before_status"], transition["after_status"]
            )
            if direction is not None:
                entry = _signal_entry(
                    dimension,
                    before_raw,
                    after_raw,
                    transition,
                    assessment,
                    ".".join(path),
                )
                (new_signals if direction == "new" else missing_signals).append(entry)
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
        f"{len(changed)} dimensions changed, {len(unchanged)} dimensions unchanged; "
        f"{len(new_signals)} signals became available, "
        f"{len(missing_signals)} signals became unavailable."
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
        "new_signals": new_signals,
        "missing_signals": missing_signals,
        "confidence_changes": confidence_changes,
        "summary": summary,
        "compatibility": compatibility,
        "comparison": comparison,
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
