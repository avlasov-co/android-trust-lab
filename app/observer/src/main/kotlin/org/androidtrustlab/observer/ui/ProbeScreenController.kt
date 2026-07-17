package org.androidtrustlab.observer.ui

import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicBoolean
import org.androidtrustlab.observer.probe.AppProbeBundle
import org.androidtrustlab.observer.probe.ProbeCollectionCancelledException

internal fun interface TaskRunner {
    fun execute(task: () -> Unit)
}

internal enum class UiNotice {
    NONE,
    EXPORT_COMPLETE,
    EXPORT_CANCELLED,
    EXPORT_FAILED,
}

internal enum class UiFailure {
    PROBE_FAILED,
    PROBE_CANCELLED,
}

internal data class ExportRequest(val suggestedFilename: String)

internal sealed interface ProbeScreenState {
    data object Scope : ProbeScreenState
    data class Running(val completed: Int, val total: Int) : ProbeScreenState
    data class Ready(val bundle: AppProbeBundle, val notice: UiNotice) : ProbeScreenState
    data class AwaitingDestination(
        val bundle: AppProbeBundle,
        val request: ExportRequest,
    ) : ProbeScreenState

    data class Exporting(val bundle: AppProbeBundle) : ProbeScreenState
    data class Failed(val failure: UiFailure) : ProbeScreenState
}

internal class ProbeScreenController(
    private val collectProbe: (
        onProgress: (completed: Int, total: Int) -> Unit,
        shouldCancel: () -> Boolean,
    ) -> AppProbeBundle,
    private val taskRunner: TaskRunner,
    private val filenameFactory: (AppProbeBundle) -> String = ::suggestedExportFilename,
) {
    private val lock = Any()
    private var currentState: ProbeScreenState = ProbeScreenState.Scope
    private var listener: ((ProbeScreenState) -> Unit)? = null
    private var acknowledged = false
    private var activeCancellation: AtomicBoolean? = null

    val state: ProbeScreenState
        get() = synchronized(lock) { currentState }

    val isScopeAcknowledged: Boolean
        get() = synchronized(lock) { acknowledged }

    fun attach(newListener: (ProbeScreenState) -> Unit) {
        val stateSnapshot = synchronized(lock) {
            listener = newListener
            currentState
        }
        newListener(stateSnapshot)
    }

    fun detach(oldListener: (ProbeScreenState) -> Unit) {
        synchronized(lock) {
            if (listener === oldListener) listener = null
        }
    }

    fun setScopeAcknowledged(value: Boolean) {
        val callback = synchronized(lock) {
            acknowledged = value
            listener
        }
        callback?.invoke(state)
    }

    fun startProbe(): Boolean {
        val cancellation = AtomicBoolean(false)
        val callback = synchronized(lock) {
            if (!acknowledged || currentState is ProbeScreenState.Running ||
                currentState is ProbeScreenState.AwaitingDestination ||
                currentState is ProbeScreenState.Exporting
            ) {
                return false
            }
            activeCancellation = cancellation
            currentState = ProbeScreenState.Running(completed = 0, total = PROBE_COUNT)
            listener
        }
        callback?.invoke(ProbeScreenState.Running(completed = 0, total = PROBE_COUNT))
        taskRunner.execute {
            val nextState = try {
                val bundle = collectProbe(
                    { completed, total -> reportProgress(cancellation, completed, total) },
                    cancellation::get,
                )
                ProbeScreenState.Ready(bundle, UiNotice.NONE)
            } catch (_: ProbeCollectionCancelledException) {
                ProbeScreenState.Failed(UiFailure.PROBE_CANCELLED)
            } catch (_: Exception) {
                ProbeScreenState.Failed(UiFailure.PROBE_FAILED)
            }
            finishCollection(cancellation, nextState)
        }
        return true
    }

    fun cancelCollection(): Boolean = synchronized(lock) {
        val cancellation = activeCancellation ?: return false
        if (currentState !is ProbeScreenState.Running) return false
        cancellation.set(true)
        true
    }

    fun requestExport(): ExportRequest? {
        val transition = synchronized(lock) {
            val ready = currentState as? ProbeScreenState.Ready ?: return null
            val request = ExportRequest(filenameFactory(ready.bundle))
            val nextState = ProbeScreenState.AwaitingDestination(ready.bundle, request)
            currentState = nextState
            Triple(request, nextState, listener)
        }
        transition.third?.invoke(transition.second)
        return transition.first
    }

    fun cancelExport(): Boolean {
        val transition = synchronized(lock) {
            val awaiting = currentState as? ProbeScreenState.AwaitingDestination
                ?: return false
            val nextState = ProbeScreenState.Ready(
                awaiting.bundle,
                UiNotice.EXPORT_CANCELLED,
            )
            currentState = nextState
            nextState to listener
        }
        transition.second?.invoke(transition.first)
        return true
    }

    fun failExportSelection(): Boolean {
        val transition = synchronized(lock) {
            val awaiting = currentState as? ProbeScreenState.AwaitingDestination
                ?: return false
            val nextState = ProbeScreenState.Ready(
                awaiting.bundle,
                UiNotice.EXPORT_FAILED,
            )
            currentState = nextState
            nextState to listener
        }
        transition.second?.invoke(transition.first)
        return true
    }

    fun exportTo(writer: (AppProbeBundle) -> Unit): Boolean {
        val start = synchronized(lock) {
            val awaiting = currentState as? ProbeScreenState.AwaitingDestination
                ?: return false
            val nextState = ProbeScreenState.Exporting(awaiting.bundle)
            currentState = nextState
            Triple(awaiting.bundle, nextState, listener)
        }
        start.third?.invoke(start.second)
        taskRunner.execute {
            val notice = try {
                writer(start.first)
                UiNotice.EXPORT_COMPLETE
            } catch (_: Exception) {
                UiNotice.EXPORT_FAILED
            }
            transition(ProbeScreenState.Ready(start.first, notice))
        }
        return true
    }

    private fun reportProgress(cancellation: AtomicBoolean, completed: Int, total: Int) {
        require(total == PROBE_COUNT && completed in 1..total)
        val transition = synchronized(lock) {
            if (activeCancellation !== cancellation || currentState !is ProbeScreenState.Running) {
                return
            }
            val nextState = ProbeScreenState.Running(completed, total)
            currentState = nextState
            nextState to listener
        }
        transition.second?.invoke(transition.first)
    }

    private fun finishCollection(cancellation: AtomicBoolean, nextState: ProbeScreenState) {
        val transition = synchronized(lock) {
            if (activeCancellation !== cancellation) return
            activeCancellation = null
            val committedState = if (cancellation.get()) {
                ProbeScreenState.Failed(UiFailure.PROBE_CANCELLED)
            } else {
                nextState
            }
            currentState = committedState
            committedState to listener
        }
        transition.second?.invoke(transition.first)
    }

    private fun transition(nextState: ProbeScreenState) {
        val callback = synchronized(lock) {
            currentState = nextState
            listener
        }
        callback?.invoke(nextState)
    }

    private companion object {
        const val PROBE_COUNT = 12
    }
}

internal object UserInitiatedTaskRunner : TaskRunner {
    override fun execute(task: () -> Unit) {
        Thread(task, "atl-user-initiated-task").apply {
            isDaemon = true
            start()
        }
    }
}

internal object ProbeSessionStore {
    private var controller: ProbeScreenController? = null

    @Synchronized
    fun getOrCreate(
        collectProbe: (
            onProgress: (completed: Int, total: Int) -> Unit,
            shouldCancel: () -> Boolean,
        ) -> AppProbeBundle,
    ): ProbeScreenController {
        val existing = controller
        if (existing != null) return existing
        return ProbeScreenController(collectProbe, UserInitiatedTaskRunner).also {
            controller = it
        }
    }

    @Synchronized
    fun resetForTests() {
        controller = null
    }
}

internal fun suggestedExportFilename(
    bundle: AppProbeBundle,
    random: SecureRandom = SecureRandom(),
): String {
    val timestamp = EXPORT_TIME_FORMAT.format(Instant.parse(bundle.metadata.endedAt))
    val collection = bundle.metadata.collectionId.removePrefix("atlcol-")
    require(Regex("^[a-f0-9]{16}$").matches(collection))
    val suffix = ByteArray(4).also(random::nextBytes).joinToString("") { "%02x".format(it) }
    return "android-trust-lab-app-probe-$timestamp-$collection-$suffix.zip"
}

private val EXPORT_TIME_FORMAT: DateTimeFormatter = DateTimeFormatter
    .ofPattern("yyyyMMdd'T'HHmmss'Z'")
    .withZone(ZoneOffset.UTC)
