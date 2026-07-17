package org.androidtrustlab.observer.probe

import java.io.File
import java.time.Instant
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AppProbeContractTest {
    @Test
    fun orchestratorUsesExactProbeOrderAndIsolatesFailures() {
        val source = FakeSource(failure = ProbeId.SELINUX_SELF_CONTEXT to SecurityException("raw secret"))
        val probes = ProbeOrchestrator(source).run()

        assertEquals(ProbeId.entries, probes.map(ProbeResult::probeId))
        val failed = probes.single { it.probeId == ProbeId.SELINUX_SELF_CONTEXT }
        assertEquals(ProbeStatus.INACCESSIBLE, failed.status)
        assertEquals(DiagnosticClass.SECURITY, failed.diagnostic?.exceptionClass)
        assertEquals(DiagnosticCode.ACCESS_DENIED, failed.diagnostic?.messageCode)
        assertTrue(probes.filterNot { it == failed }.all { it.status == ProbeStatus.OBSERVED })
    }

    @Test
    fun orchestratorReportsFixedProgressAndCancelsBetweenProbes() {
        val progress = mutableListOf<Pair<Int, Int>>()
        val completed = ProbeOrchestrator(FakeSource()).run(
            onProgress = { current, total -> progress += current to total },
        )
        assertEquals((1..12).map { it to 12 }, progress)
        assertEquals(ProbeId.entries, completed.map(ProbeResult::probeId))

        var calls = 0
        assertThrows(ProbeCollectionCancelledException::class.java) {
            ProbeOrchestrator(FakeSource()).run(
                onProgress = { _, _ -> calls += 1 },
                shouldCancel = { calls == 3 },
            )
        }
        assertEquals(3, calls)
    }

    @Test
    fun failureClassifierCoversAllFourWireStatusesWithoutRawMessages() {
        assertEquals(ProbeStatus.INACCESSIBLE, FailureClassifier.classify(ProbeInaccessibleException()).status)
        assertEquals(ProbeStatus.UNSUPPORTED, FailureClassifier.classify(ProbeUnsupportedException()).status)
        assertEquals(ProbeStatus.ERROR, FailureClassifier.classify(ProbeMalformedException()).status)
        assertEquals(ProbeStatus.ERROR, FailureClassifier.classify(IllegalStateException("/data/user/0 secret")).status)

        val artifact = artifact(FakeSource(failure = ProbeId.PROC_SELF_STATUS to IllegalStateException("/data/user/0 secret")))
        val text = CanonicalJson.encode(artifact.toJson()).decodeToString()
        assertFalse(text.contains("/data/user/0"))
        assertFalse(text.contains("IllegalStateException"))
        assertTrue(text.contains("unexpected_platform_error"))
    }

    @Test
    fun selinuxParserRemovesCategoriesAndRejectsMalformedContext() {
        assertEquals(
            SelinuxContextValue("u:r:untrusted_app:s0", true),
            ProbeRedactor.selinuxContext("u:r:untrusted_app:s0:c12,c34\n"),
        )
        assertThrows(ProbeMalformedException::class.java) {
            ProbeRedactor.selinuxContext("not-a-context")
        }
        assertThrows(ProbeLimitException::class.java) {
            ProbeRedactor.selinuxContext("u:r:${"a".repeat(250)}:s0")
        }
    }

    @Test
    fun procStatusParserRetainsOnlyAllowlistedFields() {
        val value = ProcStatusParser.parse(
            """
            Name: private-name
            Pid: 1234
            TracerPid: 5678
            NoNewPrivs: 1
            Seccomp: 2
            Seccomp_filters: 1
            CapEff: 0000000000000000
            CapBnd: 0000000000000001
            """.trimIndent(),
        )
        val encoded = CanonicalJson.encode(value.toJson()).decodeToString()
        assertTrue(value.noNewPrivs == true && value.seccompMode == 2)
        assertFalse(encoded.contains("private-name"))
        assertFalse(encoded.contains("1234"))
        assertFalse(encoded.contains("TracerPid"))
        assertThrows(ProbeMalformedException::class.java) {
            ProcStatusParser.parse("NoNewPrivs: 1\nNoNewPrivs: 0")
        }
    }

    @Test
    fun mountParserEmitsOnlyLogicalCategoriesAndFailsOnPartialInput() {
        val value = MountInfoParser.parse(
            """
            21 1 253:0 / / ro,seclabel - ext4 /dev/block/dm-0 ro
            22 21 253:1 / /system ro,seclabel - ext4 /dev/block/dm-1 ro
            23 21 0:55 / /apex/com.example ro - tmpfs tmpfs ro
            """.trimIndent(),
        )
        val encoded = CanonicalJson.encode(value.toJson()).decodeToString()
        assertEquals(3, value.recordCount)
        assertEquals(1, value.apexMountCount)
        assertFalse(encoded.contains("/dev/block"))
        assertFalse(encoded.contains("com.example"))
        assertFalse(encoded.contains("253:"))
        assertThrows(ProbeMalformedException::class.java) {
            MountInfoParser.parse("malformed mountinfo")
        }
        assertThrows(ProbeLimitException::class.java) {
            MountInfoParser.parse("x".repeat(8193))
        }
        val excessApex = (0..4096).joinToString("\n") { index ->
            "${index + 1} 1 0:1 / /apex/package$index ro - tmpfs tmpfs ro"
        }
        assertThrows(ProbeLimitException::class.java) {
            MountInfoParser.parse(excessApex)
        }
    }

    @Test
    fun emulatorIndicatorsDoNotCreatePhysicalVerdict() {
        val ordinary = snapshot(
            fingerprint = "vendor/device/release",
            product = "device",
            hardware = "qcom",
        ).copy(
            model = "Pixel",
            manufacturer = "Vendor",
            brand = "vendor",
            device = "device",
        )
        val ordinaryValue = ProbeRedactor.emulatorIndicators(ordinary)
        assertTrue(ordinaryValue.indicators.isEmpty())
        assertTrue(ordinaryValue.toJson().toString().contains("not_indicated"))

        val emulator = snapshot(hardware = "ranchu", product = "sdk_gphone64_x86_64")
        assertTrue(
            ProbeRedactor.emulatorIndicators(emulator).indicators.containsAll(
                listOf("hardware_ranchu", "product_sdk"),
            ),
        )
        val everyIndicator = emulator.copy(
            fingerprint = "generic emulator",
            hardware = "goldfish ranchu cuttlefish",
            model = "emulator",
            manufacturer = "genymotion",
            brand = "generic",
            device = "generic_device",
            product = "sdk_all",
        )
        assertEquals(9, ProbeRedactor.emulatorIndicators(everyIndicator).indicators.size)
    }

    @Test
    fun fixedFileReadabilityUsesANonOpeningAccessCheck() {
        assertEquals(ProbeStatus.OBSERVED, fileReadAccess(true).status)
        assertEquals(ProbeStatus.INACCESSIBLE, fileReadAccess(false).status)
        val source = File("src/main/kotlin/org/androidtrustlab/observer/probe/AndroidProbePlatform.kt")
            .readText()
        val fileCheck = source.substringAfter("override fun fileCheck")
            .substringBefore("override fun procSelfStatus")
        assertTrue(fileCheck.contains("Os.access"))
        assertFalse(fileCheck.contains("Os.open"))
    }

    @Test
    fun bundleIsCanonicalDeterministicAndDigestBound() {
        val first = AppProbeBundleBuilder.build(artifact(FakeSource()))
        val second = AppProbeBundleBuilder.build(artifact(FakeSource()))
        assertArrayEquals(first.artifactBytes, second.artifactBytes)
        assertArrayEquals(first.manifestBytes, second.manifestBytes)
        assertEquals(first.artifactSha256, second.artifactSha256)

        val artifactText = first.artifactBytes.decodeToString()
        val manifestText = first.manifestBytes.decodeToString()
        assertTrue(artifactText.startsWith("{\"artifact_kind\":\"app_probe_json\""))
        assertTrue(manifestText.contains("\"sha256\":\"${first.artifactSha256}\""))
        assertTrue(manifestText.contains("\"relative_path\":\"app_probe.json\""))
        assertTrue(manifestText.contains("\"trustlab_app\":\"0.3.0-dev0\""))
        assertFalse(artifactText.contains("/proc/"))
        assertFalse(artifactText.contains("/system/"))
        assertFalse(artifactText.contains("installer.example"))

        val golden = File("../../tests/fixtures/app_probe_v2_bundle")
        assertArrayEquals(golden.resolve("app_probe.json").readBytes(), first.artifactBytes)
        assertArrayEquals(golden.resolve("manifest.json").readBytes(), first.manifestBytes)

        val mutableArtifact = first.artifactBytes
        val mutableManifest = first.manifestBytes
        mutableArtifact[0] = 'x'.code.toByte()
        mutableManifest[0] = 'x'.code.toByte()
        assertEquals('{'.code.toByte(), first.artifactBytes[0])
        assertEquals('{'.code.toByte(), first.manifestBytes[0])
    }

    @Test
    fun repeatedCollectionsKeepTargetPseudonymAndRotateCollectionId() {
        val first = artifact(FakeSource(), entropySeed = 0)
        val second = artifact(FakeSource(), entropySeed = 32)
        assertEquals(first.targetPseudonym, second.targetPseudonym)
        assertFalse(first.collectionId == second.collectionId)
    }

    @Test
    fun contractModelsRejectValuesOutsideSchemaBounds() {
        assertThrows(IllegalArgumentException::class.java) {
            EmulatorIndicatorsValue(List(10) { "hardware_ranchu" })
        }
        assertThrows(IllegalArgumentException::class.java) {
            MountInfoValue(4096, 4097, emptyList())
        }
        assertThrows(IllegalArgumentException::class.java) {
            SelinuxContextValue("u:r:${"a".repeat(250)}:s0", false)
        }
    }

    @Test
    fun partialBundlePreservesUnavailableProbeStatuses() {
        val source = FakeSource(
            failure = ProbeId.SELINUX_SELF_CONTEXT to ProbeInaccessibleException(),
            secondaryFailure = ProbeId.PROC_SELF_STATUS to ProbeUnsupportedException(),
        )
        val bundle = AppProbeBundleBuilder.build(artifact(source))
        val artifactText = bundle.artifactBytes.decodeToString()
        val manifestText = bundle.manifestBytes.decodeToString()
        assertTrue(artifactText.contains("\"completion_status\":\"partial\""))
        assertTrue(artifactText.contains("\"status\":\"inaccessible\""))
        assertTrue(artifactText.contains("\"status\":\"unsupported\""))
        assertTrue(manifestText.contains("\"probe_id\":\"app.selinux_self_context\""))
        assertTrue(manifestText.contains("\"probe_id\":\"app.proc_self_status\""))
        assertTrue(manifestText.contains("\"relative_path\":null"))
    }

    @Test
    fun mainSourcesContainNoForbiddenCollectionMechanism() {
        val sources = File("src/main/kotlin").walkTopDown()
            .filter(File::isFile)
            .joinToString("\n", transform = File::readText)
        listOf(
            "java.net.",
            "android.net.ConnectivityManager",
            "android.net.NetworkCapabilities",
            "android.net.NetworkRequest",
            "Runtime.getRuntime",
            "ProcessBuilder",
            "getInstalledPackages",
            "getInstalledApplications",
            "queryIntentActivities",
            "Settings.Secure.ANDROID_ID",
            "Build.SERIAL",
            "Build.getSerial",
            "Class.forName",
            "getDeclaredMethod",
            "System.loadLibrary",
        ).forEach { forbidden -> assertFalse("forbidden API: $forbidden", sources.contains(forbidden)) }
    }

    private fun artifact(
        source: ProbeSource,
        targetPseudonym: String = "target-0011223344556677",
        entropySeed: Int = 0,
    ): AppProbeArtifact {
        val times = ArrayDeque(
            listOf(Instant.parse("2026-07-16T10:00:00Z"), Instant.parse("2026-07-16T10:00:01Z")),
        )
        var entropyCall = entropySeed
        return AppProbeCollector(
            source = source,
            collectorVersion = "0.3.0-dev0",
            clock = ProbeClock { times.removeFirst() },
            entropy = ProbeEntropy { count ->
                ByteArray(count) { (entropyCall + it).toByte() }.also { entropyCall += count }
            },
            targetPseudonym = targetPseudonym,
        ).collect()
    }

    private class FakeSource(
        private val failure: Pair<ProbeId, Exception>? = null,
        private val secondaryFailure: Pair<ProbeId, Exception>? = null,
    ) : ProbeSource {
        private fun failIf(id: ProbeId) {
            when (id) {
                failure?.first -> throw failure.second
                secondaryFailure?.first -> throw secondaryFailure.second
                else -> Unit
            }
        }

        override fun buildVersion(): BuildVersionValue {
            failIf(ProbeId.BUILD_VERSION)
            return ProbeRedactor.buildVersion(snapshot())
        }

        override fun appIdentity(): AppIdentityValue {
            failIf(ProbeId.APP_IDENTITY)
            return AppIdentityValue(10123, true)
        }

        override fun installSource(): InstallSourceValue {
            failIf(ProbeId.INSTALL_SOURCE)
            return InstallSourceValue(InstallApiVariant.INSTALL_SOURCE_INFO, true, InstallSourceCategory.APP_STORE)
        }

        override fun selinuxSelfContext(): SelinuxContextValue {
            failIf(ProbeId.SELINUX_SELF_CONTEXT)
            return SelinuxContextValue("u:r:untrusted_app:s0", true)
        }

        override fun fileCheck(pathId: FilePathId): FileCheckValue {
            val id = when (pathId) {
                FilePathId.SYSTEM_SHELL -> ProbeId.FILE_SYSTEM_SHELL
                FilePathId.SYSTEM_SU -> ProbeId.FILE_SYSTEM_SU
                FilePathId.SYSTEM_XBIN_SU -> ProbeId.FILE_SYSTEM_XBIN_SU
                FilePathId.VENDOR_BIN_SU -> ProbeId.FILE_VENDOR_BIN_SU
                FilePathId.SBIN_SU -> ProbeId.FILE_SBIN_SU
            }
            failIf(id)
            val exists = pathId == FilePathId.SYSTEM_SHELL
            return FileCheckValue(
                pathId,
                exists,
                ReadAccess(ProbeStatus.OBSERVED, exists, null),
            )
        }

        override fun procSelfStatus(): ProcStatusValue {
            failIf(ProbeId.PROC_SELF_STATUS)
            return ProcStatusValue(true, 2, 1, false, false)
        }

        override fun procSelfMountInfo(): MountInfoValue {
            failIf(ProbeId.PROC_SELF_MOUNTINFO)
            return MountInfoValue(
                42,
                12,
                listOf(
                    AppMountRecord(MountPointId.ROOT, "ext4", true, false),
                    AppMountRecord(MountPointId.SYSTEM, "ext4", true, false),
                    AppMountRecord(MountPointId.APEX, "tmpfs", true, false),
                ),
            )
        }

        override fun emulatorIndicators(): EmulatorIndicatorsValue {
            failIf(ProbeId.EMULATOR_INDICATORS)
            return EmulatorIndicatorsValue(listOf("hardware_ranchu", "product_sdk"))
        }
    }

    private companion object {
        fun snapshot(
            fingerprint: String = "generic/sdk/generic:17/test",
            product: String = "sdk_gphone64_x86_64",
            hardware: String = "ranchu",
        ) = BuildSnapshot(
            sdkInt = 37,
            release = "17",
            securityPatch = "2026-07-05",
            baseOs = "present",
            type = "userdebug",
            tags = "dev-keys",
            supportedAbis = listOf("x86_64"),
            fingerprint = fingerprint,
            model = "Android SDK built for x86_64",
            manufacturer = "Google",
            brand = "generic",
            device = "generic_x86_64",
            product = product,
            hardware = hardware,
        )
    }
}
