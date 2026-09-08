package dev.zerodpi.android.service

import org.junit.Assert.assertEquals
import org.junit.Test

class AutoRestartPolicyTest {
    @Test
    fun doublesDelayEachAttemptUpToDefaultCap() {
        val expectedByAttempt = mapOf(
            1 to 1_000L,
            2 to 2_000L,
            3 to 4_000L,
            4 to 8_000L,
            5 to 16_000L,
            6 to 32_000L,
            7 to 60_000L,
            8 to 60_000L,
            20 to 60_000L,
        )
        expectedByAttempt.forEach { (attempt, expected) ->
            assertEquals(
                "attempt $attempt",
                expected,
                AutoRestartPolicy.delayMsForAttempt(attempt),
            )
        }
    }

    @Test
    fun clampsNonPositiveAttemptsToFirstAttempt() {
        assertEquals(1_000L, AutoRestartPolicy.delayMsForAttempt(0))
        assertEquals(1_000L, AutoRestartPolicy.delayMsForAttempt(-3))
    }

    @Test
    fun respectsOverriddenBaseAndCap() {
        val previousBase = AutoRestartPolicy.baseDelayMs
        val previousMax = AutoRestartPolicy.maxDelayMs
        try {
            AutoRestartPolicy.baseDelayMs = 50L
            AutoRestartPolicy.maxDelayMs = 2_000L

            val expectedByAttempt = mapOf(
                1 to 50L,
                2 to 100L,
                3 to 200L,
                4 to 400L,
                5 to 800L,
                6 to 1_600L,
                7 to 2_000L,
                8 to 2_000L,
            )
            expectedByAttempt.forEach { (attempt, expected) ->
                assertEquals(
                    "attempt $attempt",
                    expected,
                    AutoRestartPolicy.delayMsForAttempt(attempt),
                )
            }
        } finally {
            AutoRestartPolicy.baseDelayMs = previousBase
            AutoRestartPolicy.maxDelayMs = previousMax
        }
    }
}
