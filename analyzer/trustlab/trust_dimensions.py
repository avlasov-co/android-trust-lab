"""Canonical trust dimensions and state-class helpers."""

TRUST_DIMENSIONS = [
    "bootloader_lock_state",
    "verified_boot_state",
    "vbmeta_state",
    "verity_mode",
    "selinux_mode",
    "selinux_current_context",
    "selinux_denial_collection",
    "selected_process_visibility",
    "mount_integrity",
    "system_mount_resolution",
    "dynamic_partition_state",
    "apex_mount_set",
    "observer_uid_root",
    "root_shell_availability",
    "su_binary_visibility",
    "su_invocation_tested",
    "su_invocation_result",
    "root_management_artifact",
    "magisk_binary_visibility",
    "magisk_daemon_visibility",
    "magisk_process_visibility",
    "zygisk_visibility",
    "magisk_version_name",
    "magisk_version_code",
    "magisk_module_context",
    "magisk_command_status",
    "property_consistency",
    "emulator_state",
    "physical_device_state",
    "app_visible_state",
    "root_visible_state",
    "observer_privilege",
]

# These dimensions are part of the trust model, but should only be diffed when
# reports include direct supporting payloads. They are not mapped to generic
# target or observer metadata by default because that creates misleading signal.
CONTEXTUAL_DIMENSIONS = [
    "physical_device_state",
    "app_visible_state",
    "root_visible_state",
]

STATE_CLASSES = {
    "A": "stock virtual baseline",
    "B": "rooted virtual system",
    "C": "writable system modified",
    "D": "Magisk collector present",
    "E": "physical device baseline",
    "F": "physical rooted device",
}

SEVERITY_BY_DIMENSION = {
    "bootloader_lock_state": "high",
    "observer_uid_root": "medium",
    "root_shell_availability": "medium",
    "su_binary_visibility": "medium",
    "su_invocation_tested": "low",
    "su_invocation_result": "medium",
    "root_management_artifact": "medium",
    "magisk_binary_visibility": "medium",
    "magisk_daemon_visibility": "medium",
    "magisk_process_visibility": "medium",
    "zygisk_visibility": "medium",
    "magisk_version_name": "info",
    "magisk_version_code": "info",
    "magisk_module_context": "info",
    "magisk_command_status": "low",
    "mount_integrity": "high",
    "system_mount_resolution": "medium",
    "dynamic_partition_state": "low",
    "apex_mount_set": "medium",
    "selinux_mode": "high",
    "selinux_current_context": "medium",
    "selinux_denial_collection": "low",
    "selected_process_visibility": "medium",
    "verified_boot_state": "high",
    "vbmeta_state": "high",
    "verity_mode": "high",
    "property_consistency": "medium",
    "observer_privilege": "info",
    "emulator_state": "info",
}


def severity_for_dimension(dimension: str) -> str:
    return SEVERITY_BY_DIMENSION.get(dimension, "low")
