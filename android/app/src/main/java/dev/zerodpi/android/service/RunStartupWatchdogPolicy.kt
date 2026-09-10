package dev.zerodpi.android.service

/**
 * Silence budgets for the app-side run-startup watchdog.
 *
 * Every run the service launches must leave its startup phase — reaching the
 * listener for relay modes, or exiting for scan and test modes. The native
 * process proves it is alive by emitting events: scan progress while a scan
 * runs, and log lines around it. A child that stays silent for the whole
 * budget of its current phase is wedged (Android froze it, a syscall blocks
 * it, or it died without reporting an exit) and the service recovers instead
 * of leaving the UI on "Starting" or "Scanning" forever.
 *
 * The budgets are generous by design. A scan reports one event per completed
 * probe and every probe is bounded by `SCAN_TIMEOUT_SECS`, so a silent
 * stretch this long cannot come from a healthy scan. The quiet phase after a
 * scan covers the interceptor, LOW_TTL discovery, and listener bring-up
 * before the first connection is accepted.
 *
 * The knobs are mutable so instrumented tests can shrink them; production
 * uses the default constants.
 */
internal object RunStartupWatchdogPolicy {
    const val DEFAULT_SCAN_SILENCE_TIMEOUT_MS = 120_000L
    const val DEFAULT_QUIET_PHASE_SILENCE_TIMEOUT_MS = 240_000L

    @Volatile
    internal var scanSilenceTimeoutMs: Long = DEFAULT_SCAN_SILENCE_TIMEOUT_MS

    @Volatile
    internal var quietPhaseSilenceTimeoutMs: Long = DEFAULT_QUIET_PHASE_SILENCE_TIMEOUT_MS

    /**
     * Silence budget for the current phase. A running scan keeps the tighter
     * budget because its events are guaranteed by the probe loop.
     */
    fun silenceTimeoutMs(scanActive: Boolean): Long =
        (if (scanActive) scanSilenceTimeoutMs else quietPhaseSilenceTimeoutMs).coerceAtLeast(1L)

    fun silenceElapsedMs(nowMs: Long, lastEventMs: Long): Long =
        (nowMs - lastEventMs).coerceAtLeast(0L)

    /** Delay until the next check, recomputed from the last observed event. */
    fun waitMs(nowMs: Long, lastEventMs: Long, scanActive: Boolean): Long {
        val timeoutMs = silenceTimeoutMs(scanActive)
        return (timeoutMs - silenceElapsedMs(nowMs, lastEventMs)).coerceIn(1L, timeoutMs)
    }

    /**
     * Non-null when the current phase has been silent for its whole budget.
     * The message names the phase so the log and the visible error explain why
     * the run was recovered.
     */
    fun stallMessage(
        nowMs: Long,
        lastEventMs: Long,
        scanActive: Boolean,
        scan: String?,
    ): String? {
        val elapsedMs = silenceElapsedMs(nowMs, lastEventMs)
        if (elapsedMs < silenceTimeoutMs(scanActive)) {
            return null
        }
        val phase = if (scanActive) {
            val name = scan?.takeIf { it.isNotBlank() } ?: "target"
            "The $name scan"
        } else {
            "The ZeroDPI startup"
        }
        return "$phase made no progress for ${elapsedMs / 1_000}s."
    }
}
