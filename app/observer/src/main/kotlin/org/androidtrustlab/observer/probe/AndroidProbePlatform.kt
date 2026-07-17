package org.androidtrustlab.observer.probe

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal fun fileReadAccess(readable: Boolean): ReadAccess = if (readable) {
    ReadAccess(ProbeStatus.OBSERVED, true, null)
} else {
    ReadAccess(
        ProbeStatus.INACCESSIBLE,
        null,
        ProbeDiagnostic(DiagnosticClass.ERRNO, DiagnosticCode.ACCESS_DENIED),
    )
}

/** Public-API and ordinary sandbox-read implementation of the fixed probe source. */
internal class AndroidProbeSource(private val context: Context) : ProbeSource {
    private val buildSnapshot: BuildSnapshot by lazy {
        BuildSnapshot(
            sdkInt = Build.VERSION.SDK_INT,
            release = Build.VERSION.RELEASE.orEmpty(),
            securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
            baseOs = Build.VERSION.BASE_OS.orEmpty(),
            type = Build.TYPE.orEmpty(),
            tags = Build.TAGS.orEmpty(),
            supportedAbis = Build.SUPPORTED_ABIS.orEmpty().toList(),
            fingerprint = Build.FINGERPRINT.orEmpty(),
            model = Build.MODEL.orEmpty(),
            manufacturer = Build.MANUFACTURER.orEmpty(),
            brand = Build.BRAND.orEmpty(),
            device = Build.DEVICE.orEmpty(),
            product = Build.PRODUCT.orEmpty(),
            hardware = Build.HARDWARE.orEmpty(),
        )
    }

    override fun buildVersion(): BuildVersionValue = ProbeRedactor.buildVersion(buildSnapshot)

    override fun appIdentity(): AppIdentityValue = AppIdentityValue(
        appUid = Process.myUid(),
        debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
    )

    override fun installSource(): InstallSourceValue {
        val packageName = context.packageName
        val packageManager = context.packageManager
        return if (Build.VERSION.SDK_INT >= 30) {
            val installer = try {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } catch (_: PackageManager.NameNotFoundException) {
                throw SelfPackageUnavailableException()
            }
            InstallSourceValue(
                InstallApiVariant.INSTALL_SOURCE_INFO,
                installerPresent = installer != null,
                sourceCategory = ProbeRedactor.installSourceCategory(installer),
            )
        } else {
            @Suppress("DEPRECATION")
            val installer = packageManager.getInstallerPackageName(packageName)
            InstallSourceValue(
                InstallApiVariant.LEGACY_INSTALLER_API,
                installerPresent = installer != null,
                sourceCategory = ProbeRedactor.installSourceCategory(installer),
            )
        }
    }

    override fun selinuxSelfContext(): SelinuxContextValue = ProbeRedactor.selinuxContext(
        readBounded(SELINUX_SELF_CONTEXT, 4096),
    )

    override fun fileCheck(pathId: FilePathId): FileCheckValue {
        val path = FILE_PATHS.getValue(pathId)
        val exists = try {
            Os.stat(path)
            true
        } catch (exception: ErrnoException) {
            when (exception.errno) {
                OsConstants.ENOENT -> false
                OsConstants.EACCES, OsConstants.EPERM -> throw ProbeInaccessibleException()
                else -> throw IOException()
            }
        }
        if (!exists) {
            return FileCheckValue(
                pathId,
                exists = false,
                readAccess = ReadAccess(ProbeStatus.OBSERVED, false, null),
            )
        }
        val access = try {
            fileReadAccess(Os.access(path, OsConstants.R_OK))
        } catch (exception: ErrnoException) {
            when (exception.errno) {
                OsConstants.EACCES, OsConstants.EPERM -> ReadAccess(
                    ProbeStatus.INACCESSIBLE,
                    null,
                    ProbeDiagnostic(DiagnosticClass.ERRNO, DiagnosticCode.ACCESS_DENIED),
                )
                else -> ReadAccess(
                    ProbeStatus.ERROR,
                    null,
                    ProbeDiagnostic(DiagnosticClass.IO, DiagnosticCode.IO_FAILURE),
                )
            }
        }
        return FileCheckValue(pathId, exists = true, readAccess = access)
    }

    override fun procSelfStatus(): ProcStatusValue = ProcStatusParser.parse(
        readBounded(PROC_SELF_STATUS, 64 * 1024),
    )

    override fun procSelfMountInfo(): MountInfoValue = MountInfoParser.parse(
        readBounded(PROC_SELF_MOUNTINFO, 1024 * 1024),
    )

    override fun emulatorIndicators(): EmulatorIndicatorsValue =
        ProbeRedactor.emulatorIndicators(buildSnapshot)

    private fun readBounded(path: String, limit: Int): String {
        val descriptor = try {
            Os.open(path, readOnlyFlags(), 0)
        } catch (exception: ErrnoException) {
            when (exception.errno) {
                OsConstants.ENOENT -> throw ProbeUnsupportedException()
                OsConstants.EACCES, OsConstants.EPERM -> throw ProbeInaccessibleException()
                else -> throw IOException()
            }
        }
        val output = ByteArrayOutputStream(minOf(limit, 8192))
        val buffer = ByteArray(8192)
        try {
            while (true) {
                val count = try {
                    Os.read(descriptor, buffer, 0, buffer.size)
                } catch (_: ErrnoException) {
                    throw IOException()
                }
                if (count == 0) break
                if (output.size() + count > limit) throw ProbeLimitException()
                output.write(buffer, 0, count)
            }
        } finally {
            try {
                Os.close(descriptor)
            } catch (_: ErrnoException) {
                // The read outcome is already fixed; close diagnostics are not exported.
            }
        }
        val decoder = StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(output.toByteArray())).toString()
        } catch (_: Exception) {
            throw ProbeMalformedException()
        }
    }

    private companion object {
        fun readOnlyFlags(): Int = OsConstants.O_RDONLY or if (Build.VERSION.SDK_INT >= 27) {
            OsConstants.O_CLOEXEC
        } else {
            0
        }

        const val SELINUX_SELF_CONTEXT = "/proc/self/attr/current"
        const val PROC_SELF_STATUS = "/proc/self/status"
        const val PROC_SELF_MOUNTINFO = "/proc/self/mountinfo"
        val FILE_PATHS = mapOf(
            FilePathId.SYSTEM_SHELL to "/system/bin/sh",
            FilePathId.SYSTEM_SU to "/system/bin/su",
            FilePathId.SYSTEM_XBIN_SU to "/system/xbin/su",
            FilePathId.VENDOR_BIN_SU to "/vendor/bin/su",
            FilePathId.SBIN_SU to "/sbin/su",
        )
    }
}
