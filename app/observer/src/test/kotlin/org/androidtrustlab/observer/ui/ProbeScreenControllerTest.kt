package org.androidtrustlab.observer.ui

import java.security.SecureRandom
import org.androidtrustlab.observer.probe.AppProbeBundle
import org.androidtrustlab.observer.probe.AppProbeExportMetadata
import org.androidtrustlab.observer.probe.AppProbeOutcome
import org.androidtrustlab.observer.probe.ProbeCollectionCancelledException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeScreenControllerTest {
    @Test
    fun collectionRequiresAcknowledgementAndExplicitStart() {
        val runner = HoldingTaskRunner()
        var collections = 0
        val controller = ProbeScreenController(
            collectProbe = { progress, _ ->
                collections += 1
                progress(1, 12)
                progress(12, 12)
                bundle()
            },
            taskRunner = runner,
        )

        assertEquals(ProbeScreenState.Scope, controller.state)
        assertEquals(0, collections)
        assertFalse(controller.startProbe())
        controller.setScopeAcknowledged(true)
        assertTrue(controller.startProbe())
        assertFalse(controller.startProbe())
        assertEquals(ProbeScreenState.Running(0, 12), controller.state)
        assertEquals(0, collections)

        runner.runNext()
        assertEquals(1, collections)
        assertTrue(controller.state is ProbeScreenState.Ready)
    }

    @Test
    fun progressIsOrderedAndListenerReplacementDoesNotRestartCollection() {
        val runner = HoldingTaskRunner()
        var collections = 0
        val states = mutableListOf<ProbeScreenState>()
        val controller = ProbeScreenController(
            collectProbe = { progress, _ ->
                collections += 1
                (1..12).forEach { progress(it, 12) }
                bundle()
            },
            taskRunner = runner,
        )
        val firstListener: (ProbeScreenState) -> Unit = states::add
        controller.attach(firstListener)
        controller.setScopeAcknowledged(true)
        controller.startProbe()
        controller.detach(firstListener)

        val recreatedStates = mutableListOf<ProbeScreenState>()
        controller.attach(recreatedStates::add)
        assertEquals(ProbeScreenState.Running(0, 12), recreatedStates.single())
        runner.runNext()

        assertEquals(listOf(0), states.filterIsInstance<ProbeScreenState.Running>().map { it.completed })
        assertEquals((0..12).toList(), recreatedStates.filterIsInstance<ProbeScreenState.Running>().map { it.completed })
        assertTrue(recreatedStates.last() is ProbeScreenState.Ready)
        assertEquals(1, collections)
        assertTrue(runner.tasks.isEmpty())
    }

    @Test
    fun foregroundCancellationAndExceptionsBecomeFixedFailures() {
        val cancelRunner = HoldingTaskRunner()
        val canceled = ProbeScreenController(
            collectProbe = { _, shouldCancel ->
                if (shouldCancel()) throw ProbeCollectionCancelledException()
                bundle()
            },
            taskRunner = cancelRunner,
        )
        canceled.setScopeAcknowledged(true)
        canceled.startProbe()
        assertTrue(canceled.cancelCollection())
        cancelRunner.runNext()
        assertEquals(
            ProbeScreenState.Failed(UiFailure.PROBE_CANCELLED),
            canceled.state,
        )

        val errorRunner = HoldingTaskRunner()
        val failed = ProbeScreenController(
            collectProbe = { _, _ -> throw IllegalStateException("/data/user/0/private") },
            taskRunner = errorRunner,
        )
        failed.setScopeAcknowledged(true)
        failed.startProbe()
        errorRunner.runNext()
        assertEquals(ProbeScreenState.Failed(UiFailure.PROBE_FAILED), failed.state)
        assertFalse(failed.state.toString().contains("/data/user/0"))

        val raceRunner = HoldingTaskRunner()
        val ignoresCancellation = ProbeScreenController(
            collectProbe = { _, _ -> bundle() },
            taskRunner = raceRunner,
        )
        ignoresCancellation.setScopeAcknowledged(true)
        ignoresCancellation.startProbe()
        ignoresCancellation.cancelCollection()
        raceRunner.runNext()
        assertEquals(
            ProbeScreenState.Failed(UiFailure.PROBE_CANCELLED),
            ignoresCancellation.state,
        )
    }

    @Test
    fun exportCancellationFailureAndSuccessRetainReviewableBundle() {
        val runner = HoldingTaskRunner()
        val expectedBundle = bundle()
        val controller = ProbeScreenController(
            collectProbe = { _, _ -> expectedBundle },
            taskRunner = runner,
            filenameFactory = { "reviewed.zip" },
        )
        controller.setScopeAcknowledged(true)
        controller.startProbe()
        runner.runNext()

        assertEquals("reviewed.zip", controller.requestExport()?.suggestedFilename)
        val awaitingStates = mutableListOf<ProbeScreenState>()
        controller.attach(awaitingStates::add)
        assertTrue(awaitingStates.single() is ProbeScreenState.AwaitingDestination)
        assertTrue(controller.cancelExport())
        assertEquals(
            ProbeScreenState.Ready(expectedBundle, UiNotice.EXPORT_CANCELLED),
            controller.state,
        )

        controller.requestExport()
        assertTrue(controller.exportTo { throw IllegalStateException("provider secret") })
        assertTrue(controller.state is ProbeScreenState.Exporting)
        val exportingStates = mutableListOf<ProbeScreenState>()
        controller.attach(exportingStates::add)
        assertTrue(exportingStates.single() is ProbeScreenState.Exporting)
        runner.runNext()
        assertEquals(
            ProbeScreenState.Ready(expectedBundle, UiNotice.EXPORT_FAILED),
            controller.state,
        )

        var exported: AppProbeBundle? = null
        controller.requestExport()
        controller.exportTo { exported = it }
        runner.runNext()
        assertTrue(exported === expectedBundle)
        assertEquals(
            ProbeScreenState.Ready(expectedBundle, UiNotice.EXPORT_COMPLETE),
            controller.state,
        )
    }

    @Test
    fun pickerLaunchFailureReturnsToReviewableCategoricalFailure() {
        val runner = HoldingTaskRunner()
        val expectedBundle = bundle()
        val controller = ProbeScreenController(
            collectProbe = { _, _ -> expectedBundle },
            taskRunner = runner,
            filenameFactory = { "reviewed.zip" },
        )
        controller.setScopeAcknowledged(true)
        controller.startProbe()
        runner.runNext()
        controller.requestExport()

        assertTrue(controller.failExportSelection())
        assertEquals(
            ProbeScreenState.Ready(expectedBundle, UiNotice.EXPORT_FAILED),
            controller.state,
        )
    }

    @Test
    fun filenameIsUtcAsciiUniqueAndContainsNoTargetPseudonym() {
        var seed = 0
        val random = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                bytes.indices.forEach { bytes[it] = (seed + it).toByte() }
                seed += bytes.size
            }
        }
        val first = suggestedExportFilename(bundle(), random)
        val second = suggestedExportFilename(bundle(), random)

        assertTrue(
            Regex(
                "^android-trust-lab-app-probe-20260716T100001Z-0011223344556677-[a-f0-9]{8}\\.zip$",
            ).matches(first),
        )
        assertFalse(first == second)
        assertFalse(first.contains("target-"))
    }

    private class HoldingTaskRunner : TaskRunner {
        val tasks = ArrayDeque<() -> Unit>()

        override fun execute(task: () -> Unit) {
            tasks.addLast(task)
        }

        fun runNext() = tasks.removeFirst().invoke()
    }
}

internal fun bundle(): AppProbeBundle = AppProbeBundle(
    artifactBytes = "{}".toByteArray(),
    manifestBytes = "{}".toByteArray(),
    artifactSha256 = "a".repeat(64),
    manifestSha256 = "b".repeat(64),
    metadata = AppProbeExportMetadata(
        collectionId = "atlcol-0011223344556677",
        appVersion = "0.3.0-dev0",
        appProbeSchemaVersion = "2.0.0",
        manifestSchemaVersion = "1.0.0",
        startedAt = "2026-07-16T10:00:00Z",
        endedAt = "2026-07-16T10:00:01Z",
        completionStatus = "complete",
    ),
    outcomes = listOf(
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
    ).map { AppProbeOutcome(it, "observed") },
)
