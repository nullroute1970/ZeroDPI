package dev.zerodpi.android.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class RuntimeEventLineParserTest {
    @Test
    fun parsesMethodScanProgressEventWithPhase() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"scan_progress","scan":"proxy","phase":"method_test","completed":2,"total":5,"sni":"example.com","ip":"1.2.3.4","score":85}""",
        )
        val progress = event as ZeroDpiRunnerEvent.ScanProgress
        assertEquals("method_test", progress.phase)
        assertEquals(2, progress.completed)
        assertEquals(5, progress.total)
    }

    @Test
    fun parsesScanStartedWithTotal() {
        val event = RuntimeEventLineParser.parse("""{"event":"scan_started","scan":"sni","total":12}""")
        val started = event as ZeroDpiRunnerEvent.ScanStarted
        assertEquals("sni", started.scan)
        assertEquals(12, started.total)
    }

    @Test
    fun parsesBackgroundRescanStarted() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"rescan_started","scan":"sni"}""",
        )

        val started = event as ZeroDpiRunnerEvent.RescanStarted
        assertEquals("sni", started.scan)
    }

    @Test
    fun parsesBackgroundRescanFinishedSummary() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"rescan_finished","scan":"ip","found":4,"best_score":91,"duration_ms":2300,"switched":true}""",
        )

        val finished = event as ZeroDpiRunnerEvent.RescanFinished
        assertEquals("ip", finished.scan)
        assertEquals(4, finished.found)
        assertEquals(91, finished.bestScore)
        assertEquals(2_300L, finished.durationMs)
        assertEquals(true, finished.switched)
    }
    @Test
    fun parsesNetworkUnavailable() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_unavailable","message":"no route"}""",
        )
        val unavailable = event as ZeroDpiRunnerEvent.NetworkUnavailable
        assertEquals("no route", unavailable.message)
    }

    @Test
    fun parsesNetworkChanged() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_changed","source":"address","interface_ip":"192.0.2.10"}""",
        )
        val changed = event as ZeroDpiRunnerEvent.NetworkChanged
        assertEquals("address", changed.source)
        assertEquals("192.0.2.10", changed.interfaceIp)
    }

    @Test
    fun parsesNetworkRecoveryFailed() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_recovery_failed","attempt":2,"next_retry_ms":4000,"message":"open packet interceptor"}""",
        )
        val failed = event as ZeroDpiRunnerEvent.NetworkRecoveryFailed
        assertEquals(2, failed.attempt)
        assertEquals(4_000L, failed.nextRetryMs)
        assertEquals("open packet interceptor", failed.message)
    }

    @Test
    fun parsesNetworkRecovered() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_recovered","interface_ip":"192.0.2.10","target_verified":true,"target_switched":false}""",
        )
        val recovered = event as ZeroDpiRunnerEvent.NetworkRecovered
        assertEquals("192.0.2.10", recovered.interfaceIp)
        assertEquals(true, recovered.targetVerified)
        assertEquals(false, recovered.targetSwitched)
    }

}
