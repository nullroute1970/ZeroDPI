package dev.zerodpi.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RunStartupWatchdogPolicyTest {
    @Test
    fun usesTighterBudgetWhileScanProgressIsActive() {
        assertEquals(120_000L, RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive = true))
        assertEquals(240_000L, RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive = false))
    }

    @Test
    fun waitsOnlyForTheRemainingSilenceBudget() {
        val now = 1_000_000L

        assertEquals(
            RunStartupWatchdogPolicy.DEFAULT_SCAN_SILENCE_TIMEOUT_MS,
            RunStartupWatchdogPolicy.waitMs(now, lastEventMs = now, scanActive = true),
        )
        assertEquals(
            30_000L,
            RunStartupWatchdogPolicy.waitMs(now, lastEventMs = now - 90_000L, scanActive = true),
        )
        assertEquals(
            RunStartupWatchdogPolicy.DEFAULT_QUIET_PHASE_SILENCE_TIMEOUT_MS,
            RunStartupWatchdogPolicy.waitMs(now, lastEventMs = now, scanActive = false),
        )
    }

    @Test
    fun reportsStallOnlyAfterTheWholeBudget() {
        val now = 500_000L
        val scanActive = true
        val budget = RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive)

        assertNull(
            RunStartupWatchdogPolicy.stallMessage(
                nowMs = now,
                lastEventMs = now - (budget - 1L),
                scanActive = scanActive,
                scan = "sni",
            ),
        )
        assertEquals(
            "The sni scan made no progress for 120s.",
            RunStartupWatchdogPolicy.stallMessage(
                nowMs = now,
                lastEventMs = now - budget,
                scanActive = scanActive,
                scan = "sni",
            ),
        )
        assertEquals(
            "The target scan made no progress for 121s.",
            RunStartupWatchdogPolicy.stallMessage(
                nowMs = now,
                lastEventMs = now - (budget + 1_500L),
                scanActive = scanActive,
                scan = null,
            ),
        )
        assertEquals(
            "The ZeroDPI startup made no progress for 240s.",
            RunStartupWatchdogPolicy.stallMessage(
                nowMs = now,
                lastEventMs = now - RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive = false),
                scanActive = false,
                scan = "sni",
            ),
        )
    }

    @Test
    fun clampsClockSkewAndKeepsWaitPositive() {
        assertEquals(
            0L,
            RunStartupWatchdogPolicy.silenceElapsedMs(nowMs = 1_000L, lastEventMs = 5_000L),
        )
        assertEquals(
            111_000L,
            RunStartupWatchdogPolicy.waitMs(
                nowMs = 10_000L,
                lastEventMs = 1_000L,
                scanActive = true,
            ),
        )
        // Past the budget the next check still runs: the loop must observe the
        // stall instead of sleeping through it.
        assertEquals(
            1L,
            RunStartupWatchdogPolicy.waitMs(
                nowMs = 1_000_000L,
                lastEventMs = 1_000L,
                scanActive = true,
            ),
        )
    }

    @Test
    fun respectsOverriddenBudgets() {
        val previousScan = RunStartupWatchdogPolicy.scanSilenceTimeoutMs
        val previousQuiet = RunStartupWatchdogPolicy.quietPhaseSilenceTimeoutMs
        try {
            RunStartupWatchdogPolicy.scanSilenceTimeoutMs = 150L
            RunStartupWatchdogPolicy.quietPhaseSilenceTimeoutMs = 300L

            assertEquals(150L, RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive = true))
            assertEquals(300L, RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive = false))
            assertEquals(
                "The sni scan made no progress for 61s.",
                RunStartupWatchdogPolicy.stallMessage(
                    nowMs = 61_000L,
                    lastEventMs = 0L,
                    scanActive = true,
                    scan = "sni",
                ),
            )
        } finally {
            RunStartupWatchdogPolicy.scanSilenceTimeoutMs = previousScan
            RunStartupWatchdogPolicy.quietPhaseSilenceTimeoutMs = previousQuiet
        }
    }

    @Test
    fun clampsNonPositiveOverrides() {
        val previousScan = RunStartupWatchdogPolicy.scanSilenceTimeoutMs
        try {
            RunStartupWatchdogPolicy.scanSilenceTimeoutMs = 0L
            assertEquals(1L, RunStartupWatchdogPolicy.silenceTimeoutMs(scanActive = true))
            assertEquals(
                "The sni scan made no progress for 0s.",
                RunStartupWatchdogPolicy.stallMessage(
                    nowMs = 5L,
                    lastEventMs = 0L,
                    scanActive = true,
                    scan = "sni",
                ),
            )
        } finally {
            RunStartupWatchdogPolicy.scanSilenceTimeoutMs = previousScan
        }
    }
}
