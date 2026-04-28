"""Canonical trust dimensions and state-class helpers."""

TRUST_DIMENSIONS = [
    "bootloader_lock_state",
    "verified_boot_state",
    "vbmeta_state",
    "verity_mode",
    "selinux_mode",
    "mount_integrity",
    "root_presence",
    "magisk_presence",
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

OBSERVER_PRIVILEGE = {
    "host": "host",
    "adb_shell": "shell",
    "unprivileged_app": "app_sandbox",
    "root_collector": "root",
}

SEVERITY_BY_DIMENSION = {
    "bootloader_lock_state": "high",
    "root_presence": "medium",
    "magisk_presence": "medium",
    "mount_integrity": "high",
    "selinux_mode": "high",
    "verified_boot_state": "high",
    "vbmeta_state": "high",
    "verity_mode": "high",
    "property_consistency": "medium",
    "observer_privilege": "info",
    "emulator_state": "info",
}


def severity_for_dimension(dimension: str) -> str:
    return SEVERITY_BY_DIMENSION.get(dimension, "low")
