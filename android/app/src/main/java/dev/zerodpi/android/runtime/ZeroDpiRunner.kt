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

interface ZeroDpiRunner {
    fun events(): Flow<ZeroDpiRunnerEvent>
    suspend fun start(request: ZeroDpiRunRequest)
    suspend fun stop()
    suspend fun forceStop()
}
