package org.androidtrustlab.observer.probe

import java.time.Instant

enum class ProbeStatus(val wireName: String) {
    OBSERVED("observed"),
    INACCESSIBLE("inaccessible"),
    UNSUPPORTED("unsupported"),
    ERROR("error"),
}

enum class ProbeMechanism(val wireName: String) {
    PUBLIC_API("public_api"),
    PROCFS("procfs"),
    FILESYSTEM("filesystem"),
}

enum class ProbeId(
    val wireName: String,
    val mechanism: ProbeMechanism,
    val apiName: String,
    val minimumSdk: Int?,
) {
    BUILD_VERSION("build_version", ProbeMechanism.PUBLIC_API, "android.os.build", 1),
    APP_IDENTITY("app_identity", ProbeMechanism.PUBLIC_API, "android.process.my_uid", 1),
    INSTALL_SOURCE(
        "install_source",
        ProbeMechanism.PUBLIC_API,
        "android.package_manager.install_source",
        5,
    ),
    SELINUX_SELF_CONTEXT(
        "selinux_self_context",
        ProbeMechanism.PROCFS,
        "proc.self.attr.current",
        null,
    ),
    FILE_SYSTEM_SHELL("file_system_shell", ProbeMechanism.FILESYSTEM, "android.system.os", 21),
    FILE_SYSTEM_SU("file_system_su", ProbeMechanism.FILESYSTEM, "android.system.os", 21),
    FILE_SYSTEM_XBIN_SU(
        "file_system_xbin_su",
        ProbeMechanism.FILESYSTEM,
        "android.system.os",
        21,
    ),
    FILE_VENDOR_BIN_SU(
        "file_vendor_bin_su",
        ProbeMechanism.FILESYSTEM,
        "android.system.os",
        21,
    ),
    FILE_SBIN_SU("file_sbin_su", ProbeMechanism.FILESYSTEM, "android.system.os", 21),
    PROC_SELF_STATUS("proc_self_status", ProbeMechanism.PROCFS, "proc.self.status", null),
    PROC_SELF_MOUNTINFO(
        "proc_self_mountinfo",
        ProbeMechanism.PROCFS,
        "proc.self.mountinfo",
        null,
    ),
    EMULATOR_INDICATORS(
        "emulator_indicators",
        ProbeMechanism.PUBLIC_API,
        "android.os.build.indicators",
        1,
    );

    val sourceRef: String = "captures/$wireName.txt"
}

enum class DiagnosticClass(val wireName: String) {
    NONE("none"),
    ERRNO("ErrnoException"),
    IO("IOException"),
    NAME_NOT_FOUND("NameNotFoundException"),
    RUNTIME("RuntimeException"),
    SECURITY("SecurityException"),
    UNSUPPORTED("UnsupportedOperationException"),
}

enum class DiagnosticCode(val wireName: String) {
    ACCESS_DENIED("access_denied"),
    API_LEVEL_TOO_LOW("api_level_too_low"),
    CAPABILITY_UNAVAILABLE("capability_unavailable"),
    INPUT_LIMIT_EXCEEDED("input_limit_exceeded"),
    IO_FAILURE("io_failure"),
    MALFORMED_DATA("malformed_data"),
    SELF_PACKAGE_UNAVAILABLE("self_package_unavailable"),
    UNEXPECTED_PLATFORM_ERROR("unexpected_platform_error"),
}

data class ProbeDiagnostic(
    val exceptionClass: DiagnosticClass,
    val messageCode: DiagnosticCode,
) {
    internal fun toJson(): JsonValue = jsonObject(
        "exception_class" to exceptionClass.wireName.json(),
        "message_code" to messageCode.wireName.json(),
    )
}

sealed interface ProbeValue {
    fun toJson(): JsonValue
}

data class BuildVersionValue(
    val sdkInt: Int,
    val release: String,
    val securityPatch: String,
    val baseOsPresent: Boolean,
    val buildType: String,
    val buildTags: List<String>,
    val supportedAbis: List<String>,
    val buildFingerprintSha256: String,
) : ProbeValue {
    init {
        require(sdkInt in 1..10000)
        require(Regex("^(?:unknown|[0-9]{1,3}(?:\\.[0-9]{1,3}){0,3})$").matches(release))
        require(Regex("^(?:unknown|[0-9]{4}-[0-9]{2}-[0-9]{2})$").matches(securityPatch))
        require(buildType in setOf("user", "userdebug", "eng", "other"))
        require(buildTags.size <= 4 && buildTags.distinct().size == buildTags.size)
        require(buildTags.all { it in setOf("release_keys", "test_keys", "dev_keys", "other") })
        require(supportedAbis.isNotEmpty() && supportedAbis.size <= 8)
        require(supportedAbis.distinct().size == supportedAbis.size)
        require(
            supportedAbis.all {
                it in setOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64", "riscv64", "other")
            },
        )
        require(Regex("^[a-f0-9]{64}$").matches(buildFingerprintSha256))
    }

    override fun toJson(): JsonValue = jsonObject(
        "sdk_int" to sdkInt.json(),
        "release" to release.json(),
        "security_patch" to securityPatch.json(),
        "base_os_present" to baseOsPresent.json(),
        "build_type" to buildType.json(),
        "build_tags" to jsonArray(buildTags.map(String::json)),
        "supported_abis" to jsonArray(supportedAbis.map(String::json)),
        "build_fingerprint_sha256" to buildFingerprintSha256.json(),
    )
}

data class AppIdentityValue(val appUid: Int, val debuggable: Boolean) : ProbeValue {
    init {
        require(appUid >= 0)
    }

    override fun toJson(): JsonValue = jsonObject(
        "app_uid" to appUid.json(),
        "debuggable" to debuggable.json(),
    )
}

enum class InstallApiVariant(val wireName: String) {
    INSTALL_SOURCE_INFO("install_source_info"),
    LEGACY_INSTALLER_API("legacy_installer_api"),
}

enum class InstallSourceCategory(val wireName: String) {
    NONE("none"),
    PLATFORM_INSTALLER("platform_installer"),
    APP_STORE("app_store"),
    OTHER("other"),
}

data class InstallSourceValue(
    val apiVariant: InstallApiVariant,
    val installerPresent: Boolean,
    val sourceCategory: InstallSourceCategory,
) : ProbeValue {
    init {
        require((sourceCategory == InstallSourceCategory.NONE) == !installerPresent)
    }

    override fun toJson(): JsonValue = jsonObject(
        "api_variant" to apiVariant.wireName.json(),
        "installer_present" to installerPresent.json(),
        "source_category" to sourceCategory.wireName.json(),
    )
}

data class SelinuxContextValue(
    val baseContext: String,
    val categoriesRemoved: Boolean,
) : ProbeValue {
    init {
        require(baseContext.length <= 256)
        require(Regex("^[a-z0-9_]+:[a-z0-9_]+:[a-z0-9_]+:[a-z0-9_]+$").matches(baseContext))
    }

    override fun toJson(): JsonValue = jsonObject(
        "base_context" to baseContext.json(),
        "categories_removed" to categoriesRemoved.json(),
    )
}

data class ReadAccess(
    val status: ProbeStatus,
    val value: Boolean?,
    val diagnostic: ProbeDiagnostic?,
) {
    init {
        require((status == ProbeStatus.OBSERVED) == (value != null))
        require((status == ProbeStatus.OBSERVED) == (diagnostic == null))
    }

    internal fun toJson(): JsonValue = jsonObject(
        "status" to status.wireName.json(),
        "value" to value.nullableJson(),
        "diagnostic" to (diagnostic?.toJson() ?: JsonNull),
    )
}

enum class FilePathId(val wireName: String) {
    SYSTEM_SHELL("system_shell"),
    SYSTEM_SU("system_su"),
    SYSTEM_XBIN_SU("system_xbin_su"),
    VENDOR_BIN_SU("vendor_bin_su"),
    SBIN_SU("sbin_su"),
}

data class FileCheckValue(
    val pathId: FilePathId,
    val exists: Boolean,
    val readAccess: ReadAccess,
) : ProbeValue {
    init {
        require(exists || (readAccess.status == ProbeStatus.OBSERVED && readAccess.value == false))
    }

    override fun toJson(): JsonValue = jsonObject(
        "path_id" to pathId.wireName.json(),
        "exists" to exists.json(),
        "read_access" to readAccess.toJson(),
    )
}

data class ProcStatusValue(
    val noNewPrivs: Boolean?,
    val seccompMode: Int?,
    val seccompFilterCount: Int?,
    val effectiveCapabilitiesNonzero: Boolean?,
    val boundingCapabilitiesNonzero: Boolean?,
) : ProbeValue {
    init {
        require(seccompMode == null || seccompMode in 0..2)
        require(seccompFilterCount == null || seccompFilterCount in 0..65535)
    }

    override fun toJson(): JsonValue = jsonObject(
        "no_new_privs" to noNewPrivs.nullableJson(),
        "seccomp_mode" to seccompMode.nullableJson(),
        "seccomp_filter_count" to seccompFilterCount.nullableJson(),
        "effective_capabilities_nonzero" to effectiveCapabilitiesNonzero.nullableJson(),
        "bounding_capabilities_nonzero" to boundingCapabilitiesNonzero.nullableJson(),
    )
}

enum class MountPointId(val wireName: String) {
    ROOT("root"),
    SYSTEM("system"),
    SYSTEM_ROOT("system_root"),
    VENDOR("vendor"),
    PRODUCT("product"),
    SYSTEM_EXT("system_ext"),
    ODM("odm"),
    DATA("data"),
    APEX("apex"),
}

data class AppMountRecord(
    val mountPointId: MountPointId,
    val filesystemType: String,
    val readOnly: Boolean,
    val overlay: Boolean,
) {
    init {
        require(Regex("^[a-z0-9][a-z0-9_.-]{0,31}$").matches(filesystemType))
    }

    internal fun toJson(): JsonValue = jsonObject(
        "mount_point_id" to mountPointId.wireName.json(),
        "filesystem_type" to filesystemType.json(),
        "read_only" to readOnly.json(),
        "overlay" to overlay.json(),
    )
}

data class MountInfoValue(
    val recordCount: Int,
    val apexMountCount: Int,
    val selectedMounts: List<AppMountRecord>,
) : ProbeValue {
    init {
        require(recordCount in 0..16384)
        require(apexMountCount in 0..4096 && apexMountCount <= recordCount)
        require(selectedMounts.size <= 9)
        require(selectedMounts.map(AppMountRecord::mountPointId).distinct().size == selectedMounts.size)
    }

    override fun toJson(): JsonValue = jsonObject(
        "record_count" to recordCount.json(),
        "malformed_record_count" to 0.json(),
        "apex_mount_count" to apexMountCount.json(),
        "selected_mounts" to jsonArray(selectedMounts.map(AppMountRecord::toJson)),
    )
}

data class EmulatorIndicatorsValue(val indicators: List<String>) : ProbeValue {
    init {
        require(indicators.size <= 9 && indicators.distinct().size == indicators.size)
        require(
            indicators.all {
                it in setOf(
                    "fingerprint_generic",
                    "fingerprint_emulator",
                    "hardware_goldfish",
                    "hardware_ranchu",
                    "hardware_cuttlefish",
                    "model_emulator",
                    "product_sdk",
                    "brand_device_generic",
                    "manufacturer_genymotion",
                )
            },
        )
    }

    override fun toJson(): JsonValue = jsonObject(
        "outcome" to (if (indicators.isEmpty()) "not_indicated" else "indicated").json(),
        "indicators" to jsonArray(indicators.map(String::json)),
    )
}

data class ProbeResult(
    val probeId: ProbeId,
    val status: ProbeStatus,
    val value: ProbeValue?,
    val diagnostic: ProbeDiagnostic?,
) {
    init {
        require((status == ProbeStatus.OBSERVED) == (value != null))
        require((status == ProbeStatus.OBSERVED) == (diagnostic == null))
        if (value != null) {
            require(
                when (probeId) {
                    ProbeId.BUILD_VERSION -> value is BuildVersionValue
                    ProbeId.APP_IDENTITY -> value is AppIdentityValue
                    ProbeId.INSTALL_SOURCE -> value is InstallSourceValue
                    ProbeId.SELINUX_SELF_CONTEXT -> value is SelinuxContextValue
                    ProbeId.FILE_SYSTEM_SHELL ->
                        value is FileCheckValue && value.pathId == FilePathId.SYSTEM_SHELL
                    ProbeId.FILE_SYSTEM_SU ->
                        value is FileCheckValue && value.pathId == FilePathId.SYSTEM_SU
                    ProbeId.FILE_SYSTEM_XBIN_SU ->
                        value is FileCheckValue && value.pathId == FilePathId.SYSTEM_XBIN_SU
                    ProbeId.FILE_VENDOR_BIN_SU ->
                        value is FileCheckValue && value.pathId == FilePathId.VENDOR_BIN_SU
                    ProbeId.FILE_SBIN_SU ->
                        value is FileCheckValue && value.pathId == FilePathId.SBIN_SU
                    ProbeId.PROC_SELF_STATUS -> value is ProcStatusValue
                    ProbeId.PROC_SELF_MOUNTINFO -> value is MountInfoValue
                    ProbeId.EMULATOR_INDICATORS -> value is EmulatorIndicatorsValue
                },
            )
        }
    }

    internal fun toJson(): JsonValue = jsonObject(
        "probe_id" to probeId.wireName.json(),
        "mechanism" to probeId.mechanism.wireName.json(),
        "capability" to jsonObject(
            "api_name" to probeId.apiName.json(),
            "minimum_sdk" to probeId.minimumSdk.nullableJson(),
        ),
        "source_ref" to probeId.sourceRef.json(),
        "status" to status.wireName.json(),
        "value" to (value?.toJson() ?: JsonNull),
        "diagnostic" to (diagnostic?.toJson() ?: JsonNull),
    )
}

enum class AppTargetType(val wireName: String) {
    AVD("avd"),
    UNKNOWN("unknown"),
}

enum class CollectionCompletion(val wireName: String) {
    COMPLETE("complete"),
    PARTIAL("partial"),
}

data class AppProbeArtifact(
    val collectorVersion: String,
    val collectionId: String,
    val experimentId: String,
    val targetPseudonym: String,
    val targetType: AppTargetType,
    val startedAt: String,
    val endedAt: String,
    val completion: CollectionCompletion,
    val probes: List<ProbeResult>,
) {
    init {
        require(
            Regex(
                "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$",
            ).matches(collectorVersion),
        )
        require(Regex("^atlcol-[a-f0-9]{16}$").matches(collectionId))
        require(Regex("^target-[a-f0-9]{16}$").matches(targetPseudonym))
        require(
            experimentId == "unknown" || Regex("^E[0-9]{2}_[a-z0-9_]+$").matches(experimentId),
        )
        require(Instant.parse(endedAt) >= Instant.parse(startedAt))
        require(probes.map(ProbeResult::probeId) == ProbeId.entries)
        val expectedCompletion = if (
            probes.any { it.status == ProbeStatus.INACCESSIBLE || it.status == ProbeStatus.ERROR }
        ) {
            CollectionCompletion.PARTIAL
        } else {
            CollectionCompletion.COMPLETE
        }
        require(completion == expectedCompletion)
        val emulator = probes.last()
        val indicators = (emulator.value as? EmulatorIndicatorsValue)?.indicators.orEmpty()
        require(targetType == if (indicators.isEmpty()) AppTargetType.UNKNOWN else AppTargetType.AVD)
    }

    fun toJson(): JsonValue = jsonObject(
        "artifact_kind" to "app_probe_json".json(),
        "schema_version" to SCHEMA_VERSION.json(),
        "collector" to jsonObject(
            "name" to "trustlab-app".json(),
            "version" to collectorVersion.json(),
        ),
        "observer" to jsonObject(
            "observer_type" to "unprivileged_app".json(),
            "privilege_level" to "app_sandbox".json(),
            "collection_method" to "app_snapshot".json(),
        ),
        "collection_id" to collectionId.json(),
        "experiment_id" to experimentId.json(),
        "target" to jsonObject(
            "pseudonymous_id" to targetPseudonym.json(),
            "target_type" to targetType.wireName.json(),
        ),
        "started_at" to startedAt.json(),
        "ended_at" to endedAt.json(),
        "completion_status" to completion.wireName.json(),
        "environment" to jsonObject(
            "platform" to "android".json(),
            "transport" to "app_api".json(),
            "execution_context" to "app_collector".json(),
        ),
        "redaction_policy" to jsonObject(
            "policy_id" to "atl_portable_v1".json(),
            "redaction_state" to "applied".json(),
            "direct_identifiers_removed" to true.json(),
            "serials_removed" to true.json(),
            "secrets_removed" to true.json(),
            "applied_fields" to jsonArray(REDACTION_FIELDS.map(String::json)),
        ),
        "probes" to jsonArray(probes.map(ProbeResult::toJson)),
    )

    companion object {
        const val SCHEMA_VERSION = "2.0.0"
        val REDACTION_FIELDS = listOf(
            "build_fingerprint_hashed",
            "diagnostics_categorized",
            "file_paths_replaced",
            "installer_package_categorized",
            "mount_fields_allowlisted",
            "selinux_categories_removed",
        )
    }
}
