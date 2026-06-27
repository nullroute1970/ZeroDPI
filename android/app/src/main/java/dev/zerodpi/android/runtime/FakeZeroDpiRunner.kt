package dev.zerodpi.android.runtime

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch

class FakeZeroDpiRunner(
    private val scope: CoroutineScope,
) : ZeroDpiRunner {
    private val events = MutableSharedFlow<ZeroDpiRunnerEvent>(extraBufferCapacity = 32)
    private var job: Job? = null

    override fun events(): Flow<ZeroDpiRunnerEvent> = events.asSharedFlow()

    override suspend fun start(request: ZeroDpiRunRequest) {
        if (job?.isActive == true) {
            events.emit(ZeroDpiRunnerEvent.Log("Fake runner is already active."))
            return
        }

        job = scope.launch {
            events.emit(ZeroDpiRunnerEvent.Starting)
            events.emit(ZeroDpiRunnerEvent.Log("Using fake ZeroDPI runner. No native binary is required."))
            delay(450)
            events.emit(ZeroDpiRunnerEvent.Log("Loaded config from ${request.configPath}."))
            events.emit(ZeroDpiRunnerEvent.Scanning)
            delay(700)
            events.emit(ZeroDpiRunnerEvent.Log("Selected demo target cloudflare.com with score 95."))
            events.emit(ZeroDpiRunnerEvent.Running)
            events.emit(ZeroDpiRunnerEvent.Log("Listening on 127.0.0.1:1080."))

            while (true) {
                delay(5_000)
                events.emit(ZeroDpiRunnerEvent.Log("Fake relay heartbeat: 0 active connections."))
            }
        }
    }

    override suspend fun stop() {
        job?.cancel()
        job = null
        events.emit(ZeroDpiRunnerEvent.Exited(0))
    }
}
