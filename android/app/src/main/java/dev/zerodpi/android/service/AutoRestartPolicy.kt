package dev.zerodpi.android.service

/**
 * Backoff schedule for supervised-session auto-restarts: each consecutive
 * unexpected run end doubles the wait before the next relaunch, starting at
 * [baseDelayMs] and never exceeding [maxDelayMs]. The attempt counter is
 * reset by [ZeroDpiService] once a relaunched run reaches Running.
 *
 * The delay knobs are mutable so instrumented tests can shrink the schedule;
 * production uses the default constants.
 */
internal object AutoRestartPolicy {
    const val DEFAULT_BASE_DELAY_MS = 1_000L
    const val DEFAULT_MAX_DELAY_MS = 60_000L

    @Volatile
    internal var baseDelayMs: Long = DEFAULT_BASE_DELAY_MS

    @Volatile
    internal var maxDelayMs: Long = DEFAULT_MAX_DELAY_MS

    fun delayMsForAttempt(attempt: Int): Long {
        val max = maxDelayMs.coerceAtLeast(1L)
        var delay = baseDelayMs.coerceIn(1L, max)
        val doublings = attempt.coerceAtLeast(1) - 1
        repeat(doublings) {
            if (delay >= max) {
                return max
            }
            delay = (delay * 2L).coerceAtMost(max)
        }
        return delay
    }
}
