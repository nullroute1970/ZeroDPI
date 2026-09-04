package dev.zerodpi.android.runtime

import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import java.io.File

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
                writeScanResults(request)
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

    /**
     * Mirrors the real binary's SCAN_OUTPUT write for scan modes so fake-mode
     * runs exercise the same results-file path the app parses after the scan.
     */
    private fun writeScanResults(request: ZeroDpiRunRequest) {
        if (request.mode != "sni_scan" && request.mode != "ip_scan") return
        val dir = File(request.configPath).parentFile ?: return
        val results = if (request.mode == "sni_scan") {
            """
            [
              {"sni": "cloudflare.com", "ip": "1.1.1.1", "tcp_latency_ms": 35, "tls_ok": true,
               "tls_latency_ms": 60, "cert_valid": true, "ttfb_ms": 90, "download_bps": 1048576.0,
               "upload_bps": 786432.0, "speed_bps": 1048576.0, "http_status": 200, "score": 95},
              {"sni": "unreachable.example", "ip": "10.0.0.1", "tcp_latency_ms": null, "tls_ok": false,
               "tls_latency_ms": null, "cert_valid": false, "ttfb_ms": null, "download_bps": null,
               "upload_bps": null, "speed_bps": null, "http_status": null, "score": 0}
            ]
            """.trimIndent()
        } else {
            """
            [
              {"ip": "104.16.132.229", "tcp_latency_ms": 30, "tls_ok": true, "tls_latency_ms": 55,
               "cert_valid": true, "ttfb_ms": 80, "download_bps": 2048000.0, "upload_bps": 1048576.0,
               "speed_bps": 2048000.0, "http_status": 200, "score": 96}
            ]
            """.trimIndent()
        }
        File(dir, TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME).writeText(results)
    }
}
