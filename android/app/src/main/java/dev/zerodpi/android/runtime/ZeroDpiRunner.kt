package dev.zerodpi.android.runtime

import kotlinx.coroutines.flow.Flow

data class ZeroDpiRunRequest(
    val configPath: String,
    val workingDirectory: String,
    val useRoot: Boolean = false,
)

sealed interface ZeroDpiRunnerEvent {
    data object Starting : ZeroDpiRunnerEvent
    data object Scanning : ZeroDpiRunnerEvent
    data object Running : ZeroDpiRunnerEvent
    data class Log(val message: String) : ZeroDpiRunnerEvent
    data class Failed(val message: String) : ZeroDpiRunnerEvent
    data class Exited(val exitCode: Int) : ZeroDpiRunnerEvent
}

interface ZeroDpiRunner {
    fun events(): Flow<ZeroDpiRunnerEvent>
    suspend fun start(request: ZeroDpiRunRequest)
    suspend fun stop()
}
