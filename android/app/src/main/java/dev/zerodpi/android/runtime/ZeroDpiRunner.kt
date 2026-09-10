package dev.zerodpi.android.runtime

import kotlinx.coroutines.flow.Flow

data class ZeroDpiRunRequest(
    val configPath: String,
    val workingDirectory: String,
    val useRoot: Boolean = false,
    val mode: String = "",
    val bypassMethod: String = "",
    val listenHost: String = "",
    val listenPort: Int = 0,
)

sealed interface ZeroDpiRunnerEvent {
    data object Starting : ZeroDpiRunnerEvent
    data object RootHelperStarting : ZeroDpiRunnerEvent
    data class RootHelperAuthenticated(val pid: Long, val uid: Long) : ZeroDpiRunnerEvent
    data class DataPlaneStarted(val pid: Long, val uid: Long) : ZeroDpiRunnerEvent
    data class FirewallCleanup(val completed: Boolean) : ZeroDpiRunnerEvent
    data class ConfigLoaded(
        val mode: String,
        val bypassMethod: String,
        val listenHost: String,
        val listenPort: Int,
        val rootRequired: Boolean,
    ) : ZeroDpiRunnerEvent
    data class ScanStarted(
        val scan: String,
        val total: Int?,
    ) : ZeroDpiRunnerEvent
    data class ScanProgress(
        val scan: String,
        val phase: String?,
        val completed: Int,
        val total: Int?,
        val sni: String?,
        val ip: String?,
        val score: Int?,
    ) : ZeroDpiRunnerEvent
    data class ScanCompleted(
        val scan: String,
        val results: Int,
    ) : ZeroDpiRunnerEvent
    data class NextScanScheduled(
        val scan: String,
        val intervalSeconds: Long,
    ) : ZeroDpiRunnerEvent
    data class RescanStarted(
        val scan: String,
    ) : ZeroDpiRunnerEvent
    data class RescanFinished(
        val scan: String,
        val found: Int,
        val bestScore: Int?,
        val durationMs: Long,
        val switched: Boolean,
    ) : ZeroDpiRunnerEvent
    data class SelectedTarget(
        val target: String,
        val sni: String?,
        val ip: String,
        val score: Int?,
    ) : ZeroDpiRunnerEvent
    data class ListenerStarted(
        val mode: String,
        val listenAddress: String,
    ) : ZeroDpiRunnerEvent
    data class ConnectionAccepted(
        val peer: String,
        val sourcePort: Int,
    ) : ZeroDpiRunnerEvent
    data class BypassFinished(
        val sourcePort: Int,
        val status: String,
    ) : ZeroDpiRunnerEvent
    data class RelayBytes(
        val sourcePort: Int,
        val clientToServerBytes: Long,
        val serverToClientBytes: Long,
        val isFinal: Boolean,
    ) : ZeroDpiRunnerEvent
    data class ActiveTargetChanged(
        val target: String,
        val sni: String?,
        val ip: String,
        val score: Int?,
    ) : ZeroDpiRunnerEvent
    data class RootRequired(
        val message: String,
        val alternatives: List<String>,
    ) : ZeroDpiRunnerEvent
    data class FatalError(val message: String) : ZeroDpiRunnerEvent
    data class GracefulShutdown(val reason: String) : ZeroDpiRunnerEvent
    data class Log(val message: String) : ZeroDpiRunnerEvent
    data class Failed(val message: String) : ZeroDpiRunnerEvent
    data class Exited(val exitCode: Int) : ZeroDpiRunnerEvent
    data object StopTimedOut : ZeroDpiRunnerEvent
}

/**
 * Outcome of a [ZeroDpiRunner.stop] / [ZeroDpiRunner.forceStop] call.
 *
 * The result tells the caller whether a fresh [ZeroDpiRunnerEvent.Exited] will
 * still arrive on the event flow. Waiting on that event after the exit was
 * already emitted (by the process's own wait job) would deadlock callers such
 * as the service's automatic-restart shutdown.
 */
enum class RunnerStopResult {
    /** This call emitted the [ZeroDpiRunnerEvent.Exited] event itself. */
    Exited,

    /**
     * The [ZeroDpiRunnerEvent.Exited] event had already been emitted before
     * this call (nothing was running, or the process's wait job won the
     * race). No further exit event will arrive from this run.
     */
    AlreadyExited,

    /** The process did not stop within the grace period; [ZeroDpiRunnerEvent.StopTimedOut] was emitted. */
    TimedOut,
}

interface ZeroDpiRunner {
    fun events(): Flow<ZeroDpiRunnerEvent>
    suspend fun start(request: ZeroDpiRunRequest)
    suspend fun stop(): RunnerStopResult
    suspend fun forceStop(): RunnerStopResult

    /**
     * Kills whatever this runner still has running without emitting any event.
     *
     * [ZeroDpiService] calls this when it gives up on a run whose process went
     * silent: that run's bookkeeping is already resolved, so a late
     * [ZeroDpiRunnerEvent.Exited] would only overwrite the failure the service
     * published, and a surviving child would block the next launch.
     * Implementations must make sure no event from the abandoned run reaches
     * [events], and that a later [stop] reports [RunnerStopResult.AlreadyExited]
     * instead of waiting for an exit event that will never arrive.
     */
    suspend fun abandon()
}
