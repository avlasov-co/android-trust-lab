package org.androidtrustlab.observer.probe

import android.content.Context
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import org.androidtrustlab.observer.BuildConfig

internal interface ProbeSource {
    fun buildVersion(): BuildVersionValue
    fun appIdentity(): AppIdentityValue
    fun installSource(): InstallSourceValue
    fun selinuxSelfContext(): SelinuxContextValue
    fun fileCheck(pathId: FilePathId): FileCheckValue
    fun procSelfStatus(): ProcStatusValue
    fun procSelfMountInfo(): MountInfoValue
    fun emulatorIndicators(): EmulatorIndicatorsValue
}

internal fun interface ProbeClock {
    fun now(): Instant
}

internal fun interface ProbeEntropy {
    fun bytes(count: Int): ByteArray
}

internal class ProbeCollectionCancelledException : Exception()

internal class ProbeOrchestrator(private val source: ProbeSource) {
    fun run(
        onProgress: (completed: Int, total: Int) -> Unit = { _, _ -> },
        shouldCancel: () -> Boolean = { false },
    ): List<ProbeResult> {
        val operations: List<Pair<ProbeId, () -> ProbeValue>> = listOf(
            ProbeId.BUILD_VERSION to source::buildVersion,
            ProbeId.APP_IDENTITY to source::appIdentity,
            ProbeId.INSTALL_SOURCE to source::installSource,
            ProbeId.SELINUX_SELF_CONTEXT to source::selinuxSelfContext,
            ProbeId.FILE_SYSTEM_SHELL to { source.fileCheck(FilePathId.SYSTEM_SHELL) },
            ProbeId.FILE_SYSTEM_SU to { source.fileCheck(FilePathId.SYSTEM_SU) },
            ProbeId.FILE_SYSTEM_XBIN_SU to { source.fileCheck(FilePathId.SYSTEM_XBIN_SU) },
            ProbeId.FILE_VENDOR_BIN_SU to { source.fileCheck(FilePathId.VENDOR_BIN_SU) },
            ProbeId.FILE_SBIN_SU to { source.fileCheck(FilePathId.SBIN_SU) },
            ProbeId.PROC_SELF_STATUS to source::procSelfStatus,
            ProbeId.PROC_SELF_MOUNTINFO to source::procSelfMountInfo,
            ProbeId.EMULATOR_INDICATORS to source::emulatorIndicators,
        )
        val results = ArrayList<ProbeResult>(operations.size)
        operations.forEach { (probeId, operation) ->
            if (shouldCancel()) throw ProbeCollectionCancelledException()
            results += observe(probeId, operation)
            onProgress(results.size, operations.size)
        }
        if (shouldCancel()) throw ProbeCollectionCancelledException()
        return results
    }

    private fun observe(probeId: ProbeId, block: () -> ProbeValue): ProbeResult = try {
        ProbeResult(probeId, ProbeStatus.OBSERVED, block(), null)
    } catch (exception: Exception) {
        val failure = FailureClassifier.classify(exception)
        ProbeResult(probeId, failure.status, null, failure.diagnostic)
    }
}

internal class AppProbeCollector(
    private val source: ProbeSource,
    private val collectorVersion: String,
    private val clock: ProbeClock,
    private val entropy: ProbeEntropy,
    private val targetPseudonym: String,
    private val experimentId: String = "unknown",
) {
    fun collect(
        onProgress: (completed: Int, total: Int) -> Unit = { _, _ -> },
        shouldCancel: () -> Boolean = { false },
    ): AppProbeArtifact {
        val startedAt = clock.now()
        val probes = ProbeOrchestrator(source).run(onProgress, shouldCancel)
        val endedAt = clock.now()
        val emulator = probes.last()
        val indicators = (emulator.value as? EmulatorIndicatorsValue)?.indicators.orEmpty()
        val completion = if (
            probes.any { it.status == ProbeStatus.INACCESSIBLE || it.status == ProbeStatus.ERROR }
        ) {
            CollectionCompletion.PARTIAL
        } else {
            CollectionCompletion.COMPLETE
        }
        return AppProbeArtifact(
            collectorVersion = collectorVersion,
            collectionId = "atlcol-${opaqueId()}",
            experimentId = experimentId,
            targetPseudonym = targetPseudonym,
            targetType = if (indicators.isEmpty()) AppTargetType.UNKNOWN else AppTargetType.AVD,
            startedAt = startedAt.toString(),
            endedAt = endedAt.toString(),
            completion = completion,
            probes = probes,
        )
    }

    private fun opaqueId(): String = entropy.bytes(8).joinToString("") {
        HEX[(it.toInt() ushr 4) and 0x0f].toString() + HEX[it.toInt() and 0x0f]
    }

    private companion object {
        const val HEX = "0123456789abcdef"
    }
}

data class AppProbeExportMetadata(
    val collectionId: String,
    val appVersion: String,
    val appProbeSchemaVersion: String,
    val manifestSchemaVersion: String,
    val startedAt: String,
    val endedAt: String,
    val completionStatus: String,
)

data class AppProbeOutcome(
    val probeId: String,
    val status: String,
)

class AppProbeBundle internal constructor(
    artifactBytes: ByteArray,
    manifestBytes: ByteArray,
    val artifactSha256: String,
    val manifestSha256: String,
    val metadata: AppProbeExportMetadata,
    outcomes: List<AppProbeOutcome>,
) {
    private val artifactPayload = artifactBytes.copyOf()
    private val manifestPayload = manifestBytes.copyOf()
    private val outcomeSnapshot = outcomes.toList()

    val artifactBytes: ByteArray
        get() = artifactPayload.copyOf()

    val manifestBytes: ByteArray
        get() = manifestPayload.copyOf()

    val outcomes: List<AppProbeOutcome>
        get() = outcomeSnapshot.toList()

    companion object {
        const val ARTIFACT_FILE_NAME = "app_probe.json"
        const val MANIFEST_FILE_NAME = "manifest.json"
    }
}

internal object TargetPseudonymStore {
    private val validTarget = Regex("^target-[a-f0-9]{16}$")

    @Synchronized
    fun loadOrCreate(context: Context, entropy: ProbeEntropy): String {
        val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
        val existing = preferences.getString(TARGET_KEY, null)
        if (existing != null && validTarget.matches(existing)) return existing
        val target = "target-${opaqueHex(entropy.bytes(8))}"
        if (!preferences.edit().putString(TARGET_KEY, target).commit()) throw IOException()
        return target
    }

    private const val PREFERENCES_NAME = "app_probe_identity"
    private const val TARGET_KEY = "target_pseudonym"
}

private fun opaqueHex(bytes: ByteArray): String {
    require(bytes.size == 8)
    return bytes.joinToString("") {
        HEX[(it.toInt() ushr 4) and 0x0f].toString() + HEX[it.toInt() and 0x0f]
    }
}

private const val HEX = "0123456789abcdef"

internal object AppProbeBundleBuilder {
    fun build(artifact: AppProbeArtifact): AppProbeBundle {
        val artifactBytes = CanonicalJson.encode(artifact.toJson())
        val artifactSha256 = sha256(artifactBytes)
        val manifestBytes = CanonicalJson.encode(manifest(artifact, artifactBytes.size, artifactSha256))
        return AppProbeBundle(
            artifactBytes = artifactBytes,
            manifestBytes = manifestBytes,
            artifactSha256 = artifactSha256,
            manifestSha256 = sha256(manifestBytes),
            metadata = AppProbeExportMetadata(
                collectionId = artifact.collectionId,
                appVersion = artifact.collectorVersion,
                appProbeSchemaVersion = AppProbeArtifact.SCHEMA_VERSION,
                manifestSchemaVersion = "1.0.0",
                startedAt = artifact.startedAt,
                endedAt = artifact.endedAt,
                completionStatus = artifact.completion.wireName,
            ),
            outcomes = artifact.probes.map {
                AppProbeOutcome(it.probeId.wireName, it.status.wireName)
            },
        )
    }

    private fun manifest(
        artifact: AppProbeArtifact,
        byteSize: Int,
        artifactSha256: String,
    ): JsonValue {
        val artifacts = buildList {
            add(
                jsonObject(
                    "logical_name" to "raw_report".json(),
                    "relative_path" to AppProbeBundle.ARTIFACT_FILE_NAME.json(),
                    "media_type" to "application/json".json(),
                    "byte_size" to byteSize.json(),
                    "sha256" to artifactSha256.json(),
                    "probe_id" to "app.raw_report".json(),
                    "status" to "observed".json(),
                    "exit_code" to JsonNull,
                    "timed_out" to false.json(),
                    "sensitivity" to "internal".json(),
                    "redaction_state" to "redacted".json(),
                    "detail" to JsonNull,
                ),
            )
            artifact.probes.filter { it.status != ProbeStatus.OBSERVED }.forEach { probe ->
                add(
                    jsonObject(
                        "logical_name" to "probe_outcome.${probe.probeId.wireName}".json(),
                        "relative_path" to JsonNull,
                        "media_type" to "application/json".json(),
                        "byte_size" to JsonNull,
                        "sha256" to JsonNull,
                        "probe_id" to "app.${probe.probeId.wireName}".json(),
                        "status" to when (probe.status) {
                            ProbeStatus.INACCESSIBLE -> "inaccessible"
                            ProbeStatus.UNSUPPORTED -> "unsupported"
                            ProbeStatus.ERROR -> "command_error"
                            ProbeStatus.OBSERVED -> error("observed probes have no outcome artifact")
                        }.json(),
                        "exit_code" to JsonNull,
                        "timed_out" to false.json(),
                        "sensitivity" to "internal".json(),
                        "redaction_state" to "withheld".json(),
                        "detail" to JsonNull,
                    ),
                )
            }
        }
        return jsonObject(
            "collection_id" to artifact.collectionId.json(),
            "schema_version" to "1.0.0".json(),
            "experiment_id" to artifact.experimentId.json(),
            "collector" to jsonObject(
                "name" to "trustlab-app".json(),
                "version" to artifact.collectorVersion.json(),
            ),
            "observer" to jsonObject(
                "observer_type" to "unprivileged_app".json(),
                "privilege_level" to "app_sandbox".json(),
                "collection_method" to "app_snapshot".json(),
            ),
            "target" to jsonObject(
                "pseudonymous_id" to artifact.targetPseudonym.json(),
                "target_type" to artifact.targetType.wireName.json(),
            ),
            "started_at" to artifact.startedAt.json(),
            "ended_at" to artifact.endedAt.json(),
            "completion_status" to artifact.completion.wireName.json(),
            "tool_versions" to jsonObject("trustlab_app" to artifact.collectorVersion.json()),
            "environment" to jsonObject(
                "platform" to "android".json(),
                "transport" to "app_api".json(),
                "execution_context" to "app_collector".json(),
            ),
            "warnings" to jsonArray(emptyList()),
            "redaction_policy" to jsonObject(
                "policy_id" to "atl_portable_v1".json(),
                "redaction_state" to "applied".json(),
                "direct_identifiers_removed" to true.json(),
                "serials_removed" to true.json(),
                "secrets_removed" to true.json(),
            ),
            "artifacts" to jsonArray(artifacts),
        )
    }

    private fun sha256(value: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** Explicit entry point used only after the user starts a foreground probe session. */
object PublicAppProbe {
    fun collect(
        context: Context,
        onProgress: (completed: Int, total: Int) -> Unit = { _, _ -> },
        shouldCancel: () -> Boolean = { false },
    ): AppProbeBundle {
        val random = SecureRandom()
        val entropy = ProbeEntropy { count -> ByteArray(count).also(random::nextBytes) }
        val applicationContext = context.applicationContext
        val collector = AppProbeCollector(
            source = AndroidProbeSource(applicationContext),
            collectorVersion = BuildConfig.VERSION_NAME,
            clock = ProbeClock(Instant::now),
            entropy = entropy,
            targetPseudonym = TargetPseudonymStore.loadOrCreate(applicationContext, entropy),
        )
        return AppProbeBundleBuilder.build(collector.collect(onProgress, shouldCancel))
    }
}
