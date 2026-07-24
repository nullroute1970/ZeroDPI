package dev.zerodpi.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LiveLogsFilterTest {
    @Test
    fun classifiesUnstructuredLogLinesByStableKeywords() {
        assertEquals(LogLevelFilter.Error, classifyLogLine("FATAL: runner failed"))
        assertEquals(LogLevelFilter.Warning, classifyLogLine("Warning: retrying"))
        assertEquals(LogLevelFilter.Info, classifyLogLine("relay connected"))
    }

    @Test
    fun searchIsCaseInsensitiveAndCombinesWithLevel() {
        val line = "WARNING: DNS Retry"

        assertTrue(logMatches(line, "dns retry", LogLevelFilter.All))
        assertTrue(logMatches(line, "DNS", LogLevelFilter.Warning))
        assertFalse(logMatches(line, "DNS", LogLevelFilter.Error))
        assertFalse(logMatches(line, "proxy", LogLevelFilter.Warning))
    }
}
