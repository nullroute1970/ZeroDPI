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
            events.emit(
                ZeroDpiRunnerEvent.ConfigLoaded(
                    mode = request.mode,
                    bypassMethod = request.bypassMethod,
                    listenHost = request.listenHost,
                    listenPort = request.listenPort,
                    rootRequired = request.useRoot,
                ),
            )
            if (request.mode == "sni_scan" || request.mode == "ip_scan") {
                events.emit(ZeroDpiRunnerEvent.ScanStarted(request.mode.removeSuffix("_scan"), total = 1))
                delay(350)
                events.emit(
                    ZeroDpiRunnerEvent.ScanProgress(
                        scan = request.mode.removeSuffix("_scan"),
                        phase = null,
                        completed = 1,
                        total = 1,
                        sni = if (request.mode == "sni_scan") "cloudflare.com" else null,
                        ip = "1.1.1.1",
                        score = 95,
                    ),
                )
                delay(700)
                events.emit(ZeroDpiRunnerEvent.ScanCompleted(request.mode.removeSuffix("_scan"), results = 1))
                events.emit(ZeroDpiRunnerEvent.Log("Fake ${request.mode} completed."))
                events.emit(ZeroDpiRunnerEvent.Exited(0))
                job = null
                return@launch
            }

            events.emit(ZeroDpiRunnerEvent.ScanStarted("sni", total = 1))
            delay(700)
            events.emit(
                ZeroDpiRunnerEvent.SelectedTarget(
                    target = "sni",
                    sni = "cloudflare.com",
                    ip = "1.1.1.1",
                    score = 95,
                ),
            )
            events.emit(
                ZeroDpiRunnerEvent.ListenerStarted(
                    mode = request.mode,
                    listenAddress = "${request.listenHost}:${request.listenPort}",
                ),
            )
            events.emit(ZeroDpiRunnerEvent.ConnectionAccepted(peer = "127.0.0.1:53000", sourcePort = 44300))

            var bytes = 0L
            while (true) {
                delay(5_000)
                bytes += 1024L
                events.emit(
                    ZeroDpiRunnerEvent.RelayBytes(
                        sourcePort = 44300,
                        clientToServerBytes = bytes,
                        serverToClientBytes = bytes / 2,
                        isFinal = false,
                    ),
                )
            }
        }
    }

    override suspend fun stop() {
        job?.cancel()
        job = null
        events.emit(ZeroDpiRunnerEvent.Exited(0))
    }

    override suspend fun forceStop() {
        stop()
    }
}
