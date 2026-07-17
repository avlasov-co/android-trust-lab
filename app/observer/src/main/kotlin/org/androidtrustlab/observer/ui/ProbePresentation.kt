package org.androidtrustlab.observer.ui

import org.androidtrustlab.observer.probe.AppProbeArtifact
import org.androidtrustlab.observer.probe.AppProbeOutcome

internal enum class OutcomeCategory(val wireStatus: String) {
    OBSERVED("observed"),
    INACCESSIBLE("inaccessible"),
    UNSUPPORTED("unsupported"),
    ERROR("error"),
}

internal data class OutcomeGroup(
    val category: OutcomeCategory,
    val probeIds: List<String>,
)

internal enum class RedactionItem {
    BUILD_FINGERPRINT_HASHED,
    DIAGNOSTICS_CATEGORIZED,
    FILE_PATHS_REPLACED,
    INSTALLER_PACKAGE_CATEGORIZED,
    MOUNT_FIELDS_ALLOWLISTED,
    SELINUX_CATEGORIES_REMOVED,
}

internal fun groupOutcomes(outcomes: List<AppProbeOutcome>): List<OutcomeGroup> {
    require(outcomes.size == EXPECTED_PROBE_IDS.size)
    require(outcomes.map(AppProbeOutcome::probeId) == EXPECTED_PROBE_IDS)
    return OutcomeCategory.entries.map { category ->
        OutcomeGroup(
            category,
            outcomes.filter { it.status == category.wireStatus }.map(AppProbeOutcome::probeId),
        )
    }
}

internal fun redactionItems(): List<RedactionItem> = AppProbeArtifact.REDACTION_FIELDS.map {
    when (it) {
        "build_fingerprint_hashed" -> RedactionItem.BUILD_FINGERPRINT_HASHED
        "diagnostics_categorized" -> RedactionItem.DIAGNOSTICS_CATEGORIZED
        "file_paths_replaced" -> RedactionItem.FILE_PATHS_REPLACED
        "installer_package_categorized" -> RedactionItem.INSTALLER_PACKAGE_CATEGORIZED
        "mount_fields_allowlisted" -> RedactionItem.MOUNT_FIELDS_ALLOWLISTED
        "selinux_categories_removed" -> RedactionItem.SELINUX_CATEGORIES_REMOVED
        else -> error("Unmapped redaction contract field")
    }
}

private val EXPECTED_PROBE_IDS = listOf(
    "build_version",
    "app_identity",
    "install_source",
    "selinux_self_context",
    "file_system_shell",
    "file_system_su",
    "file_system_xbin_su",
    "file_vendor_bin_su",
    "file_sbin_su",
    "proc_self_status",
    "proc_self_mountinfo",
    "emulator_indicators",
)
