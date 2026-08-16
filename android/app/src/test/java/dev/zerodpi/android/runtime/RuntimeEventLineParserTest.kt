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
}
