"""Diff normalized Android Trust Lab reports."""

from __future__ import annotations

from typing import Any, Dict, List
import hashlib

from .trust_dimensions import severity_for_dimension


def json_like_for_hash(value: Any) -> str:
    """Return a stable string representation for deterministic diff IDs."""
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

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
    "root_presence": ["root_state", "su_present"],
    "magisk_presence": ["magisk_state", "magisk_binary_present"],
    "property_consistency": ["properties", "security"],
    "emulator_state": ["emulator_state", "is_emulator"],
    "observer_privilege": ["observer", "privilege_level"],
}


def get_path(obj: Dict[str, Any], path: List[str]) -> Any:
    current: Any = obj
    for part in path:
        if not isinstance(current, dict):
            return "unknown"
        current = current.get(part, "unknown")
    return current


def interpretation(dimension: str) -> str:
    messages = {
        "bootloader_lock_state": "Bootloader lock evidence changed. On virtual targets this is property evidence only, not hardware-backed proof.",
        "root_presence": "Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim.",
        "magisk_presence": "Magisk-related visibility changed between reports. The project records visibility and does not hide or modify it.",
        "mount_integrity": "Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion.",
        "selinux_mode": "SELinux mode changed. This affects runtime MAC boundary interpretation.",
        "verified_boot_state": "Verified boot property evidence changed. Emulator evidence remains limited for hardware-backed conclusions.",
        "vbmeta_state": "vbmeta device-state evidence changed. Interpret according to target class and observer.",
        "verity_mode": "dm-verity-related property evidence changed.",
        "property_consistency": "Security-relevant property group changed. This does not imply bypass by itself.",
        "observer_privilege": "Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation.",
    }
    return messages.get(dimension, "Trust-state dimension changed between reports.")


def make_diff(base: Dict[str, Any], compare: Dict[str, Any]) -> Dict[str, Any]:
    changed = []
    unchanged = []
    confidence_changes = []

    for dimension, path in DIMENSION_PATHS.items():
        before = get_path(base, path)
        after = get_path(compare, path)
        if before != after:
            changed.append({
                "dimension": dimension,
                "before": before,
                "after": after,
                "severity": severity_for_dimension(dimension),
                "interpretation": interpretation(dimension),
                "evidence_paths": [".".join(path)],
            })
        else:
            unchanged.append(dimension)

    base_conf = get_path(base, ["verified_boot", "confidence"])
    compare_conf = get_path(compare, ["verified_boot", "confidence"])
    if base_conf != compare_conf:
        confidence_changes.append({"path": "verified_boot.confidence", "before": base_conf, "after": compare_conf})

    diff_payload = json_like_for_hash({
        "base_report": base.get("report_id"),
        "compare_report": compare.get("report_id"),
        "changed_dimensions": changed,
        "unchanged_dimensions": unchanged,
        "confidence_changes": confidence_changes,
    })
    diff_id = "atldiff-" + hashlib.sha256(diff_payload.encode()).hexdigest()[:16]
    summary = f"{len(changed)} dimensions changed, {len(unchanged)} dimensions unchanged."

    return {
        "diff_id": diff_id,
        "schema_version": "1.0.0",
        "base_report": base.get("report_id", "unknown"),
        "compare_report": compare.get("report_id", "unknown"),
        "changed_dimensions": changed,
        "unchanged_dimensions": unchanged,
        "new_signals": [],
        "missing_signals": [],
        "confidence_changes": confidence_changes,
        "summary": summary,
    }
