package org.androidtrustlab.observer.probe

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal class ProbeInaccessibleException : Exception()
internal class ProbeUnsupportedException(val apiLevelTooLow: Boolean = false) : Exception()
internal class ProbeLimitException : Exception()
internal class ProbeMalformedException : Exception()
internal class SelfPackageUnavailableException : Exception()

internal data class BuildSnapshot(
    val sdkInt: Int,
    val release: String,
    val securityPatch: String,
    val baseOs: String,
    val type: String,
    val tags: String,
    val supportedAbis: List<String>,
    val fingerprint: String,
    val model: String,
    val manufacturer: String,
    val brand: String,
    val device: String,
    val product: String,
    val hardware: String,
)

internal object ProbeRedactor {
    private val release = Regex("^[0-9]{1,3}(?:\\.[0-9]{1,3}){0,3}$")
    private val patch = Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    private val safeContext = Regex("^[a-z0-9_]+:[a-z0-9_]+:[a-z0-9_]+:[a-z0-9_]+$")

    fun buildVersion(snapshot: BuildSnapshot): BuildVersionValue = BuildVersionValue(
        sdkInt = snapshot.sdkInt,
        release = snapshot.release.takeIf(release::matches) ?: "unknown",
        securityPatch = snapshot.securityPatch.takeIf(patch::matches) ?: "unknown",
        baseOsPresent = snapshot.baseOs.isNotBlank(),
        buildType = when (snapshot.type.lowercase()) {
            "user", "userdebug", "eng" -> snapshot.type.lowercase()
            else -> "other"
        },
        buildTags = snapshot.tags
            .split(',')
            .asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .map {
                when (it) {
                    "release-keys" -> "release_keys"
                    "test-keys" -> "test_keys"
                    "dev-keys" -> "dev_keys"
                    else -> "other"
                }
            }
            .distinct()
            .sorted()
            .take(4)
            .toList(),
        supportedAbis = snapshot.supportedAbis
            .map {
                when (it.lowercase()) {
                    "arm64-v8a", "armeabi-v7a", "x86", "x86_64", "riscv64" -> it.lowercase()
                    else -> "other"
                }
            }
            .distinct()
            .sorted()
            .ifEmpty { listOf("other") }
            .take(8),
        buildFingerprintSha256 = sha256(snapshot.fingerprint),
    )

    fun selinuxContext(raw: String): SelinuxContextValue {
        val context = raw.trim().removeSuffix("\u0000")
        val parts = context.split(':')
        if (parts.size < 4) throw ProbeMalformedException()
        val base = parts.take(4).joinToString(":")
        if (base.length > 256) throw ProbeLimitException()
        if (!safeContext.matches(base)) throw ProbeMalformedException()
        return SelinuxContextValue(base, categoriesRemoved = parts.size > 4)
    }

    fun installSourceCategory(packageName: String?): InstallSourceCategory = when {
        packageName == null -> InstallSourceCategory.NONE
        packageName in PLATFORM_INSTALLERS -> InstallSourceCategory.PLATFORM_INSTALLER
        packageName in APP_STORES -> InstallSourceCategory.APP_STORE
        else -> InstallSourceCategory.OTHER
    }

    fun emulatorIndicators(snapshot: BuildSnapshot): EmulatorIndicatorsValue {
        val fingerprint = snapshot.fingerprint.lowercase()
        val model = snapshot.model.lowercase()
        val manufacturer = snapshot.manufacturer.lowercase()
        val brand = snapshot.brand.lowercase()
        val device = snapshot.device.lowercase()
        val product = snapshot.product.lowercase()
        val hardware = snapshot.hardware.lowercase()
        val indicators = buildList {
            if ("generic" in fingerprint) add("fingerprint_generic")
            if ("emulator" in fingerprint) add("fingerprint_emulator")
            if ("goldfish" in hardware) add("hardware_goldfish")
            if ("ranchu" in hardware) add("hardware_ranchu")
            if ("cuttlefish" in hardware) add("hardware_cuttlefish")
            if (model == "emulator" || "android sdk" in model || model == "google_sdk") {
                add("model_emulator")
            }
            if (product.startsWith("sdk") || product.startsWith("gphone")) add("product_sdk")
            if (brand.startsWith("generic") && device.startsWith("generic")) {
                add("brand_device_generic")
            }
            if ("genymotion" in manufacturer) add("manufacturer_genymotion")
        }.distinct().sorted()
        return EmulatorIndicatorsValue(indicators)
    }

    private fun sha256(value: String): String = MessageDigest
        .getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private val PLATFORM_INSTALLERS = setOf(
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
    )
    private val APP_STORES = setOf(
        "com.android.vending",
        "com.amazon.venezia",
        "com.sec.android.app.samsungapps",
    )
}

internal object ProcStatusParser {
    private const val MAX_LINE_LENGTH = 4096
    private val selected = setOf("NoNewPrivs", "Seccomp", "Seccomp_filters", "CapEff", "CapBnd")

    fun parse(text: String): ProcStatusValue {
        val values = linkedMapOf<String, String>()
        text.lineSequence().forEach { line ->
            if (line.length > MAX_LINE_LENGTH) throw ProbeLimitException()
            val separator = line.indexOf(':')
            if (separator <= 0) return@forEach
            val key = line.substring(0, separator)
            if (key !in selected) return@forEach
            if (values.put(key, line.substring(separator + 1).trim()) != null) {
                throw ProbeMalformedException()
            }
        }
        if (values.isEmpty()) throw ProbeMalformedException()
        return ProcStatusValue(
            noNewPrivs = values["NoNewPrivs"]?.let(::parseBooleanInteger),
            seccompMode = values["Seccomp"]?.let { parseBoundedInteger(it, 0..2) },
            seccompFilterCount = values["Seccomp_filters"]?.let {
                parseBoundedInteger(it, 0..65535)
            },
            effectiveCapabilitiesNonzero = values["CapEff"]?.let(::hexIsNonzero),
            boundingCapabilitiesNonzero = values["CapBnd"]?.let(::hexIsNonzero),
        )
    }

    private fun parseBooleanInteger(value: String): Boolean = when (value) {
        "0" -> false
        "1" -> true
        else -> throw ProbeMalformedException()
    }

    private fun parseBoundedInteger(value: String, range: IntRange): Int {
        val parsed = value.toIntOrNull() ?: throw ProbeMalformedException()
        if (parsed !in range) throw ProbeMalformedException()
        return parsed
    }

    private fun hexIsNonzero(value: String): Boolean {
        if (!Regex("^[0-9A-Fa-f]{1,32}$").matches(value)) throw ProbeMalformedException()
        return value.any { it != '0' }
    }
}

internal object MountInfoParser {
    private const val MAX_RECORDS = 16_384
    private const val MAX_LINE_LENGTH = 8192
    private val safeFilesystem = Regex("^[a-z0-9][a-z0-9_.-]{0,31}$")
    private val mountPointIds = mapOf(
        "/" to MountPointId.ROOT,
        "/system" to MountPointId.SYSTEM,
        "/system_root" to MountPointId.SYSTEM_ROOT,
        "/vendor" to MountPointId.VENDOR,
        "/product" to MountPointId.PRODUCT,
        "/system_ext" to MountPointId.SYSTEM_EXT,
        "/odm" to MountPointId.ODM,
        "/data" to MountPointId.DATA,
        "/apex" to MountPointId.APEX,
    )

    fun parse(text: String): MountInfoValue {
        if (text.isEmpty()) throw ProbeMalformedException()
        var count = 0
        var apexCount = 0
        val selected = linkedMapOf<MountPointId, AppMountRecord>()
        text.lineSequence().filter(String::isNotEmpty).forEach { line ->
            if (line.length > MAX_LINE_LENGTH) throw ProbeLimitException()
            count += 1
            if (count > MAX_RECORDS) throw ProbeLimitException()
            val fields = line.split(' ')
            val separator = fields.indexOf("-")
            if (fields.size < 10 || separator < 6 || separator + 3 >= fields.size) {
                throw ProbeMalformedException()
            }
            val mountPoint = decodeMountField(fields[4])
            val mountOptions = fields[5].split(',')
            val filesystem = fields[separator + 1].lowercase().let {
                if (safeFilesystem.matches(it)) it else "other"
            }
            val superOptions = fields[separator + 3].split(',')
            if (mountPoint == "/apex" || mountPoint.startsWith("/apex/")) {
                apexCount += 1
                if (apexCount > MAX_APEX_RECORDS) throw ProbeLimitException()
            }
            val pointId = mountPointIds[mountPoint]
                ?: if (mountPoint.startsWith("/apex/")) MountPointId.APEX else null
            if (pointId != null && pointId !in selected) {
                selected[pointId] = AppMountRecord(
                    mountPointId = pointId,
                    filesystemType = filesystem,
                    readOnly = "ro" in mountOptions || "ro" in superOptions,
                    overlay = filesystem == "overlay",
                )
            }
        }
        if (count == 0) throw ProbeMalformedException()
        return MountInfoValue(count, apexCount, selected.values.toList())
    }

    private fun decodeMountField(value: String): String {
        val output = StringBuilder()
        var index = 0
        while (index < value.length) {
            if (value[index] != '\\') {
                output.append(value[index++])
                continue
            }
            if (index + 3 >= value.length) throw ProbeMalformedException()
            val escape = value.substring(index, index + 4)
            output.append(
                when (escape) {
                    "\\040" -> ' '
                    "\\011" -> '\t'
                    "\\012" -> '\n'
                    "\\134" -> '\\'
                    else -> throw ProbeMalformedException()
                },
            )
            index += 4
        }
        return output.toString()
    }

    private const val MAX_APEX_RECORDS = 4096
}

internal data class ClassifiedFailure(
    val status: ProbeStatus,
    val diagnostic: ProbeDiagnostic,
)

internal object FailureClassifier {
    fun classify(exception: Exception): ClassifiedFailure = when (exception) {
        is ProbeInaccessibleException,
        is SecurityException,
        -> ClassifiedFailure(
            ProbeStatus.INACCESSIBLE,
            ProbeDiagnostic(
                if (exception is SecurityException) DiagnosticClass.SECURITY else DiagnosticClass.ERRNO,
                DiagnosticCode.ACCESS_DENIED,
            ),
        )
        is ProbeUnsupportedException -> ClassifiedFailure(
            ProbeStatus.UNSUPPORTED,
            ProbeDiagnostic(
                DiagnosticClass.UNSUPPORTED,
                if (exception.apiLevelTooLow) {
                    DiagnosticCode.API_LEVEL_TOO_LOW
                } else {
                    DiagnosticCode.CAPABILITY_UNAVAILABLE
                },
            ),
        )
        is ProbeLimitException -> ClassifiedFailure(
            ProbeStatus.ERROR,
            ProbeDiagnostic(DiagnosticClass.IO, DiagnosticCode.INPUT_LIMIT_EXCEEDED),
        )
        is ProbeMalformedException -> ClassifiedFailure(
            ProbeStatus.ERROR,
            ProbeDiagnostic(DiagnosticClass.RUNTIME, DiagnosticCode.MALFORMED_DATA),
        )
        is SelfPackageUnavailableException -> ClassifiedFailure(
            ProbeStatus.ERROR,
            ProbeDiagnostic(
                DiagnosticClass.NAME_NOT_FOUND,
                DiagnosticCode.SELF_PACKAGE_UNAVAILABLE,
            ),
        )
        is IOException -> ClassifiedFailure(
            ProbeStatus.ERROR,
            ProbeDiagnostic(DiagnosticClass.IO, DiagnosticCode.IO_FAILURE),
        )
        is UnsupportedOperationException -> ClassifiedFailure(
            ProbeStatus.UNSUPPORTED,
            ProbeDiagnostic(DiagnosticClass.UNSUPPORTED, DiagnosticCode.CAPABILITY_UNAVAILABLE),
        )
        else -> ClassifiedFailure(
            ProbeStatus.ERROR,
            ProbeDiagnostic(DiagnosticClass.RUNTIME, DiagnosticCode.UNEXPECTED_PLATFORM_ERROR),
        )
    }
}
